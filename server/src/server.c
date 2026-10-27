#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if.h>

#include "common.h"
#include "peer.h"
#include "acl.h"
#include "crypt.h"
#include "secure.h"
#include "device.h"
#include "status.h"
#include "audit.h"
#include "enroll.h"
#include "idp.h"
#include "dns.h"
#include "serverkey.h"
#include "flow.h"
#include "tcp.h"

#define MAX_EVENTS 8

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

/* 시그널 핸들러 안에서는 파일을 읽을 수 없다 (fopen / printf 는 핸들러에서 불러도
 * 안전한 함수가 아니다). 표시만 해 두고 메인 루프가 읽는다. */
static volatile sig_atomic_t reload_requested = 0;

static void on_reload(int sig)
{
	(void)sig;
	reload_requested = 1;
}

/* ACL 을 쓰는가. 시작할 때 규칙 파일을 받았는지로 정해지고 도는 중에는 바뀌지 않는다. */
static int acl_enabled;

/* 터널 대역의 prefix 와 MTU. 서버 자신의 tun 에 붙인 값과 같아야 하고 (-n, -m),
 * 클라이언트에게 그대로 내려간다. */
static int tun_prefix = 24;
static int tun_mtu = TUN_MTU;

/* ---- 로그 -------------------------------------------------------------------
 *
 * 밖에서 아무나 일으킬 수 있는 줄(위조, 모르는 세션, 짧은 패킷, ACL 거부)이 패킷마다
 * 찍히면, 초당 수만 개의 쓰레기 패킷이 서버보다 먼저 로그(디스크, journald)를 무너뜨린다.
 * 그런 줄은 종류마다 1초에 LOG_BURST 줄까지만 찍고, 넘친 수는 그 종류의 다음 줄 앞에 한
 * 줄로 알린다. 무엇을 몇 개 버렸는지는 상태 소켓의 카운터가 빠짐없이 센다.
 *
 * 통과한 패킷마다의 줄([udp->tun], [tun->udp], [udp->connector])은 -v 일 때만 찍는다.
 * 운영에서는 감사 로그의 access 사건이 "누가 어디에 닿았나"를 목적지마다 한 번 남긴다. */
#define LOG_BURST 20

enum log_kind { LOG_DROP, LOG_DENY, LOG_HS, LOG_KINDS };

static const char *const log_kind_name[LOG_KINDS] = { "drop", "deny", "handshake" };

static __thread struct {
	time_t at;		/* 이 초 (CLOCK_MONOTONIC) */
	int n;			/* 이 초에 찍은 줄 */
	unsigned long suppressed;
} log_state[LOG_KINDS];

static int verbose;

/* 이 종류의 줄을 지금 찍어도 되면 1. */
static int log_ok(enum log_kind k)
{
	time_t now = mono_now();

	if (log_state[k].at != now) {
		if (log_state[k].suppressed > 0) {
			printf("[log] %lu %s lines suppressed\n", log_state[k].suppressed, log_kind_name[k]);
		}
		log_state[k].at = now;
		log_state[k].n = 0;
		log_state[k].suppressed = 0;
	}
	if (log_state[k].n >= LOG_BURST) {
		log_state[k].suppressed++;
		return 0;
	}
	log_state[k].n++;
	return 1;
}

/* ---- 워커 ----------------------------------------------------------------------
 *
 * 서버는 패킷 수에서 막힌다 (README 의 "성능") — 패킷마다 시스템 콜, 열기, ACL, 쓰기를 한
 * 스레드가 한다. -w N 이면 워커 N 개가 저마다 UDP 소켓(SO_REUSEPORT)과 tun 큐(IFF_MULTI_QUEUE)를
 * 하나씩 갖고 같은 일을 나눠 한다. 커널이 UDP 는 출발지 주소로, tun 은 흐름으로 나눠 주므로 한
 * 클라이언트의 패킷은 늘 같은 워커로 온다.
 *
 * 잠금은 두 겹이다.
 *   table_lock   표(세션, 기기, ACL, 등록, IdP)를 바꾸는 일은 쓰기, 데이터 패킷은 읽기로 잡는다.
 *                핸드셰이크, keepalive, 로그인, 다시 읽기, 만료는 드물어 쓰기로 둔다. 쓰기를 먼저
 *                받게 해 데이터가 몰려도 핸드셰이크가 굶지 않는다.
 *   peer->lock   읽기 잠금 아래에서 데이터 패킷이 세션의 바뀌는 칸을 고치는 동안. 두 세션의 잠금을
 *                한꺼번에 쥐지 않는다 — 커넥터로 중계할 때 먼저 쥔 것을 놓고 다음 것을 잡는다.
 *                한꺼번에 쥐면 "클라이언트 → 커넥터"와 "커넥터 → 클라이언트"를 맡은 두 워커가
 *                서로를 기다린다.
 * 워커가 하나면 잡지 않는다 — 지금까지와 같은 단일 스레드다.
 *
 * 만료, 키 교체, 다시 읽기, 상태 소켓은 워커 0 (main) 만 맡는다. */
#define MAX_WORKERS 64

static int nworkers = 1;
static pthread_rwlock_t table_lock;

#define TABLE_RDLOCK()	do { if (nworkers > 1) pthread_rwlock_rdlock(&table_lock); } while (0)
#define TABLE_WRLOCK()	do { if (nworkers > 1) pthread_rwlock_wrlock(&table_lock); } while (0)
#define TABLE_UNLOCK()	do { if (nworkers > 1) pthread_rwlock_unlock(&table_lock); } while (0)

/* AUTH 를 받는 빠르기를 출발지 주소마다 제한한다 (토큰 버킷, 초당 auth_rate 개, 한꺼번에 세 배까지).
 * AUTH 는 ECDH 를 하고 표의 쓰기 잠금을 잡는다. nonce 가 출발지에 묶여 있어 AUTH 를 보내려면 실제
 * 주소가 있어야 하므로, 그 주소 하나가 서버의 CPU 와 모든 워커의 데이터 처리를 붙잡지 못하게 한다.
 * 칸은 주소의 해시로 고르고, 다른 주소가 같은 칸에 오면 덮는다 (잊는 쪽으로 틀린다). 0 이면 끈다. */
#define RATE_SLOTS	4096

typedef struct rate_slot {
	struct in6_addr addr;
	uint64_t at_us;
	uint64_t tokens_milli;
} rate_slot_t;

static rate_slot_t rate_slots[RATE_SLOTS];
static pthread_mutex_t rate_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t auth_rate = 20;
#define PEER_LOCK(p)	do { if (nworkers > 1) pthread_mutex_lock(&(p)->lock); } while (0)
#define PEER_UNLOCK(p)	do { if (nworkers > 1) pthread_mutex_unlock(&(p)->lock); } while (0)
#define STAT_INC(f)	__atomic_fetch_add(&stats.f, 1, __ATOMIC_RELAXED)

#define LOG_LIMITED(kind, ...) do { if (log_ok(kind)) printf(__VA_ARGS__); } while (0)
#define LOG_VERBOSE(...) do { if (verbose) printf(__VA_ARGS__); } while (0)

/* 세션 키의 수명, 초 (-L). 지나면 세션을 끝내고 클라이언트가 새 키로 다시 열게 한다. */
static time_t session_lifetime = SESSION_LIFETIME_SEC;

/* 기기 목록 파일. 등록이 끝나면 여기에 한 줄을 더하고 다시 읽는다. */
static const char *device_path;

static struct in_addr tun_subnet_of(struct in_addr ip)
{
	struct in_addr subnet;

	subnet.s_addr = tun_prefix == 0 ? 0 : ip.s_addr & htonl(0xFFFFFFFFu << (32 - tun_prefix));

	return subnet;
}

/* 이 기기에 내려 줄 터널 설정을 지금의 기기 목록과 ACL 에서 만든다. 저장해 두지 않고
 * 보낼 때마다 다시 만든다 — SIGHUP 으로 정책이 바뀌면 다음 keepalive 응답에 새 값이
 * 실리고, 무엇이 바뀌었는지 따로 추적할 것이 없다.
 *
 * 자리가 모자라 빠진 규칙의 수를 돌려준다. 그 대역은 이 기기에서 닿지 않는다. */
static int net_config_for(const device_t *dev, net_config_t *cfg)
{
	int dropped = 0;

	memset(cfg, 0, sizeof(*cfg));
	cfg->tun_ip = dev->tun_ip.s_addr;
	cfg->prefix_len = (uint8_t)tun_prefix;
	cfg->mtu = (uint16_t)tun_mtu;

	/* 커넥터에는 경로를 내려 주지 않는다. 그 대역은 커넥터 쪽에서 바로 붙어 있는
	 * 네트워크이고, 같은 대역을 터널로 보내라고 하면 자기 네트워크로 가는 길을 잃는다. */
	if (acl_enabled && dev->n_connector == 0) {
		cfg->n_routes = (uint8_t)acl_routes(dev->tun_ip, &dev->tags, tun_subnet_of(dev->tun_ip),
				tun_prefix, cfg->routes, NET_MAX_ROUTES, &dropped);
	}

	/* 내부 DNS 도 같다. 커넥터는 그 내부망 안에 있어 자기 DNS 를 이미 쓴다. */
	if (dev->n_connector == 0) {
		dns_fill(cfg);
	}

	return dropped;
}

/* ---- 커넥터 ------------------------------------------------------------------
 *
 * 서버 뒤의 네트워크로 가는 길은 지금까지 하나였다: 서버의 tun 에 쓰고 커널이 서버의 NIC
 * 로 내보낸다 (FORWARD_OUT). 그러려면 서버가 그 네트워크 안에 있어야 하고, 서버는 인터넷에
 * UDP 포트를 열어 둔 장비다. 보호하려는 네트워크 안에 바깥에서 들어오는 포트를 여는 셈이다.
 *
 * 커넥터는 그 네트워크 안에 두는 작은 클라이언트다. 다른 기기처럼 등록되고 서버로 "나가는"
 * 세션을 연다. 기기 목록에서 connector=10.101.0.0/16 으로 맡은 대역을 적으면, 서버는 그
 * 대역으로 가는 패킷을 tun 이 아니라 그 커넥터의 세션으로 보낸다. 서버는 인터넷에 두고,
 * 내부망에는 들어오는 포트가 하나도 없다.
 *
 *   클라이언트 --DATA--> 서버 (ACL, 포스처, 사용자) --DATA--> 커넥터 -> tun -> 내부망
 *   클라이언트 <--DATA-- 서버 (출발지 / 목적지 확인) <--DATA-- 커넥터 <- tun <- 답
 *
 * 판정은 지금처럼 서버가 한다. 커넥터로 보내기 전에 ACL 과 포스처와 사용자 조건을 모두
 * 지난다. 커넥터는 정책을 모르고, 받은 것을 내부망에 넣고 답을 돌려줄 뿐이다.
 *
 * 커넥터에서 오는 패킷은 다르게 본다. 그 출발지는 커넥터의 터널 주소가 아니라 내부망의
 * 자원이므로 출발지 검사를 "커넥터가 맡은 대역 안인가"로 바꾸고, 목적지는 붙어 있는
 * 클라이언트여야 한다. 내부망 쪽에서 연결을 시작하지 못하게 하는 것(답만 들이는 것)은
 * 커넥터 장비의 nftables 가 한다 — 서버는 연결 상태를 추적하지 않는다.
 *
 * 커넥터가 맡은 대역인데 커넥터가 붙어 있지 않으면 버린다. 서버의 tun 으로 대신 보내지
 * 않는다 — 같은 목적지가 커넥터의 상태에 따라 다른 길로 가면 정책을 읽을 수 없다. */

/* 클라이언트가 보낸 패킷(ACL 을 지났다)을 그 대역을 맡은 커넥터의 세션으로. 평문은
 * packet + PKT_HDR_LEN 에 n 바이트 있다. */
static void relay_to_connector(int32_t sock, const device_t *conn_dev, uint8_t *packet,
		size_t cap, int n)
{
	char ids[DEVICE_ID_STRLEN];
	peer_t *conn = peer_find_device(conn_dev->id);
	int len;

	net_ep_t to;
	socklen_t to_len;

	if (conn == NULL || conn->enroll) {
		LOG_LIMITED(LOG_DROP, "[drop] connector %s is not connected\n", device_id_str(conn_dev->id, ids));
		STAT_INC(connector_offline);
		return;
	}

	PEER_LOCK(conn);
	len = secure_seal(&conn->secure, MSG_TYPE_DATA, conn->session_idx, packet, cap, (size_t)n);
	if (len >= 0) {
		conn->tx_packets++;
		conn->tx_bytes += (uint64_t)n;
	}
	to = conn->outer;
	to_len = conn->outer_len;
	PEER_UNLOCK(conn);
	if (len < 0) {
		return;
	}

	if (net_send(sock, packet, len, &to, to_len) < 0) {
		perror("sendto connector");
	}
}

/* 커넥터가 보낸 패킷(내부망의 답)을 그 목적지의 클라이언트에게. 0 이면 보냈고 -1 이면
 * 버렸다. */
static int relay_from_connector(int32_t sock, peer_t *conn, const device_t *conn_dev,
		uint8_t *packet, size_t cap, int n)
{
	char sb[INET_ADDRSTRLEN], db[INET_ADDRSTRLEN];
	const uint8_t *ip = packet + PKT_HDR_LEN;
	struct in_addr src, dst;
	const device_t *to_dev;
	net_ep_t dst_addr;
	socklen_t dst_len;
	peer_t *to;
	int len;

	memcpy(&src, ip + IP_SRC_OFF, IP_ADDR_LEN);
	memcpy(&dst, ip + IP_DST_OFF, IP_ADDR_LEN);

	if (!device_connector_has(conn_dev, src)) {
		LOG_LIMITED(LOG_DROP, "[drop] connector sent %s -> %s, source outside its networks\n",
				ip_str(src, sb), ip_str(dst, db));
		STAT_INC(spoofed_src);
		return -1;
	}

	/* 내부망 쪽에서 먼저 거는 연결은 커넥터 장비의 nftables 가 막는다. -F 면 서버도 한 번 더 본다. */
	if (!flow_inbound_ok(ip, n)) {
		STAT_INC(flow_dropped);
		LOG_LIMITED(LOG_DENY, "[deny] connector sent %s -> %s, not a reply to a flow the client opened\n",
				ip_str(src, sb), ip_str(dst, db));
		return -1;
	}

	to = peer_lookup(dst);
	to_dev = to != NULL ? device_find(to->device_id) : NULL;
	if (to == NULL || to->enroll || to_dev == NULL || to_dev->n_connector != 0) {
		LOG_LIMITED(LOG_DROP, "[drop] connector sent %s -> %s, no client session there\n",
				ip_str(src, sb), ip_str(dst, db));
		STAT_INC(connector_dropped);
		return -1;
	}

	PEER_LOCK(conn);
	conn->rx_packets++;
	conn->rx_bytes += (uint64_t)n;
	PEER_UNLOCK(conn);

	PEER_LOCK(to);
	to->tx_packets++;
	to->tx_bytes += (uint64_t)n;
	len = secure_seal(&to->secure, MSG_TYPE_DATA, to->session_idx, packet, cap, (size_t)n);
	dst_addr = to->outer;
	dst_len = to->outer_len;
	PEER_UNLOCK(to);
	if (len < 0) {
		return -1;
	}
	if (net_send(sock, packet, len, &dst_addr, dst_len) < 0) {
		perror("sendto client");
	}

	return 0;
}

/* 핸드셰이크를 거절하고 이유를 알려 준다. 응답이 없는 것과 거절된 것을 클라이언트가
 * 구분해야 사용자에게 무엇을 고치라고 말할 수 있다.
 *
 * DENY: reason(1) | mac(32)
 *
 * dev 와 auth_mac 을 주면 그 기기의 키로 mac 을 만든다. 서명이 맞는 AUTH 를 받은 뒤의
 * 거절에만 줄 수 있다. 그 전에는 상대가 그 기기인지 모르고, 틀린 키로 온 상대에게는
 * 우리가 만든 mac 이 어차피 맞지 않는다. 그때는 0 으로 채워 보낸다 — 클라이언트는 mac 이
 * 맞는 거절만 서버의 답으로 믿고, 맞지 않는 것은 다른 답이 오지 않을 때에만 받아들인다. */
static void send_deny(int32_t sock, const net_ep_t *dst, socklen_t dstlen,
		uint8_t reason, const device_t *dev, const uint8_t *auth_mac)
{
	uint8_t res[DENY_HS_LEN];
	msg_header_t msg_header;
	int32_t off;

	memset(res, 0, sizeof(res));
	memset(&msg_header, 0, sizeof(msg_header));
	msg_header.version = PROTOCOL_VERSION;
	msg_header.type = MSG_TYPE_DENY;

	off = msg_encode(res, sizeof(res), &msg_header);
	res[off++] = reason;

	if (dev != NULL && auth_mac != NULL &&
			secure_deny_mac(dev->key, reason, auth_mac, res + off) < 0) {
		return;
	}

	if (reason <= DENY_POSTURE) {
		__atomic_fetch_add(&stats.deny[reason], 1, __ATOMIC_RELAXED);
	}

	if (net_send(sock, res, sizeof(res), dst, dstlen) < 0) {
		perror("sendto deny");
	}
}

/* 세션을 끝낸다고 알릴 때 peer_drop_if 에 넘기는 것. */
typedef struct disconnect_ctx {
	int32_t sock;
	uint8_t reason;		/* disconnect_reason_t */
	time_t now;		/* CLOCK_MONOTONIC 초 */
} disconnect_ctx_t;

/* 세션에 DISCONNECT 를 보낸다. 등록용 세션에도 보낸다 — 등록 중인 쪽도 답을 기다리지
 * 않게 된다. */
static void send_disconnect(peer_t *peer, void *arg)
{
	const disconnect_ctx_t *ctx = arg;
	uint8_t res[PKT_OVERHEAD + 1];
	int n;

	res[PKT_HDR_LEN] = ctx->reason;
	n = secure_seal(&peer->secure, MSG_TYPE_DISCONNECT, peer->session_idx, res, sizeof(res), 1);
	if (n < 0) {
		return;
	}
	if (net_send(ctx->sock, res, n, &peer->outer, peer->outer_len) < 0) {
		perror("sendto disconnect");
	}
}

/* 키를 바꿀 때가 된 세션 (proto.h 의 "세션 키의 수명"). 등록용 세션은 몇 초면 끝나고
 * 터널을 나르지 않으므로 보지 않는다. */
static int rekey_due(const peer_t *peer, void *arg)
{
	const disconnect_ctx_t *ctx = arg;

	return !peer->enroll &&
		(ctx->now - peer->established_at >= session_lifetime ||
		 peer->secure.tx_counter >= REKEY_AFTER_PACKETS ||
		 peer->secure.rx_max >= REKEY_AFTER_PACKETS);
}

/* 1초에 한 번. 키를 바꿀 때가 된 세션을 끝내고 클라이언트가 새 키로 다시 열게 한다. */
static void rekey_tick(int32_t sock)
{
	static time_t checked_at = -1;
	disconnect_ctx_t ctx = { .sock = sock, .reason = DISCONNECT_REKEY, .now = mono_now() };
	int n;

	if (ctx.now == checked_at) {
		return;
	}
	checked_at = ctx.now;

	n = peer_drop_if(rekey_due, send_disconnect, &ctx, "rekey");
	if (n > 0) {
		printf("[peer] %d session(s) reached the key lifetime, asked to re-handshake\n", n);
	}
}

/* ---- ACL 이 막은 패킷에 답하기 ---------------------------------------------------
 *
 * 막힌 패킷을 조용히 버리면 클라이언트의 프로그램은 타임아웃까지 기다린다 (TCP 의 SYN 은
 * 몇 번이고 다시 보내 수십 초). 방화벽의 REJECT 처럼 ICMP "관리자가 막음"(type 3 code 13,
 * RFC 1812)을 돌려주면 connect() 가 바로 실패하고 사용자는 "막혔다"를 곧바로 안다.
 *
 * 출발지는 막힌 목적지로 둔다. 서버는 자기 tun 주소를 모르고(설치 스크립트가 붙인다), 받는
 * 쪽 커널은 ICMP 안에 담긴 원래 헤더로 어느 연결의 오류인지를 찾을 뿐이다. ICMP 오류에는
 * 답하지 않는다 (RFC 1122 — 오류에 오류가 꼬리를 문다). 세션마다 1초에 ICMP_DENY_PER_SEC
 * 개까지만 보낸다. 받는 쪽은 인증된 세션 하나뿐이라 증폭은 없지만, 막힌 곳을 계속 두드리는
 * 프로그램 하나가 서버의 일을 두 배로 만들지 않게 한다. */
#define ICMP_DENY_PER_SEC 10
#define ICMP_QUOTE_LEN 8	/* 원래 패킷에서 IP 헤더 뒤로 담는 바이트 (RFC 792) */

static uint16_t inet_csum(const uint8_t *p, size_t len)
{
	uint32_t sum = 0;

	while (len > 1) {
		sum += (uint32_t)(p[0] << 8 | p[1]);
		p += 2;
		len -= 2;
	}
	if (len == 1) {
		sum += (uint32_t)(p[0] << 8);
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (uint16_t)~sum;
}

static void send_prohibited(int32_t sock, peer_t *peer, const uint8_t *orig, int len)
{
	uint8_t pkt[PKT_OVERHEAD + IP_MIN_HDR + 8 + 60 + ICMP_QUOTE_LEN];
	uint8_t *ip = pkt + PKT_HDR_LEN;
	uint8_t *icmp;
	int ihl = IP_IHL(orig);
	int quote;
	int total;
	uint16_t sum;
	time_t now = mono_now();
	int n;

	if (ihl < IP_MIN_HDR || ihl > 60 || len < ihl) {
		return;
	}
	/* ICMP 오류(echo 와 그 답이 아닌 것)에는 답하지 않는다. 조각난 패킷의 뒷조각도. */
	if (orig[IP_PROTO_OFF] == 1 && len > ihl && orig[ihl] != 0 && orig[ihl] != 8) {
		return;
	}
	if (((orig[6] & 0x1f) | orig[7]) != 0) {
		return;
	}

	if (peer->icmp_at != now) {
		peer->icmp_at = now;
		peer->icmp_n = 0;
	}
	if (peer->icmp_n >= ICMP_DENY_PER_SEC) {
		return;
	}
	peer->icmp_n++;

	quote = ihl + (len - ihl < ICMP_QUOTE_LEN ? len - ihl : ICMP_QUOTE_LEN);
	total = IP_MIN_HDR + 8 + quote;

	memset(ip, 0, (size_t)(IP_MIN_HDR + 8));
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total >> 8);
	ip[3] = (uint8_t)total;
	ip[8] = 64;			/* TTL */
	ip[IP_PROTO_OFF] = 1;		/* ICMP */
	memcpy(ip + IP_SRC_OFF, orig + IP_DST_OFF, IP_ADDR_LEN);
	memcpy(ip + IP_DST_OFF, orig + IP_SRC_OFF, IP_ADDR_LEN);
	sum = inet_csum(ip, IP_MIN_HDR);
	ip[10] = (uint8_t)(sum >> 8);
	ip[11] = (uint8_t)sum;

	icmp = ip + IP_MIN_HDR;
	icmp[0] = 3;			/* destination unreachable */
	icmp[1] = 13;			/* communication administratively prohibited */
	memcpy(icmp + 8, orig, (size_t)quote);
	sum = inet_csum(icmp, (size_t)(8 + quote));
	icmp[2] = (uint8_t)(sum >> 8);
	icmp[3] = (uint8_t)sum;

	n = secure_seal(&peer->secure, MSG_TYPE_DATA, peer->session_idx, pkt, sizeof(pkt), (size_t)total);
	if (n < 0) {
		return;
	}
	peer->tx_packets++;
	peer->tx_bytes += (uint64_t)total;
	if (net_send(sock, pkt, n, &peer->outer, peer->outer_len) < 0) {
		perror("sendto icmp");
	}
}

/* 열려 있는 세션을 거절한다. 세션 키로 감싸므로 서버만 만들 수 있다 — 세션 번호를
 * 엿본 제3자가 가짜 거절로 남의 접속을 끊을 수 없다. 보낸 뒤 세션을 내리는 것은
 * 부르는 쪽의 일이다. */
static void send_session_deny(int32_t sock, peer_t *peer, const net_ep_t *dst,
		socklen_t dstlen, uint8_t reason)
{
	uint8_t res[PKT_OVERHEAD + 1];
	int n;

	res[PKT_HDR_LEN] = reason;
	n = secure_seal(&peer->secure, MSG_TYPE_DENY, peer->session_idx, res, sizeof(res), 1);
	if (n < 0) {
		return;
	}

	if (reason <= DENY_POSTURE) {
		__atomic_fetch_add(&stats.deny[reason], 1, __ATOMIC_RELAXED);
	}

	if (net_send(sock, res, n, dst, dstlen) < 0) {
		perror("sendto deny");
	}
}

/* ---- 핸드셰이크의 nonce 와 기기 ID 감싸기 (proto.h, v9) ------------------------------- */

/* nonce 의 mac 키. 뜰 때 한 번 뽑고 어디에도 남기지 않는다 — 다시 시작하면 이전의 nonce 는 모두
 * 무효다. */
static uint8_t cookie_key[VPN_KEY_LEN];

/* 기기 목록이나 등록 대기 목록을 다시 읽은 시각. 다시 읽으면 기기마다 기억한 "마지막으로 쓴
 * nonce" 가 사라지므로, 그 전에 발급한 nonce 는 받지 않는다 (진행 중이던 핸드셰이크는 다시 한다).
 * 표 잠금 밖의 auth_precheck 도 읽으므로 __atomic 으로 읽고 쓴다. */
static uint64_t nonce_floor;

/* 기기 ID 를 푸는 키 쌍. 서버 키(-k)가 있으면 그것, 없으면 뜰 때 만든 일회용 키다. */
static crypt_ecdh_t *hs_key;
static uint8_t hs_pub[VPN_PUB_LEN];

static uint64_t mono_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int auth_rate_ok(const net_ep_t *src)
{
	const uint64_t burst = (uint64_t)auth_rate * 3 * 1000;
	uint64_t now = mono_us();
	uint32_t hash = 2166136261u;
	rate_slot_t *slot;
	size_t i;
	int ok;

	if (auth_rate == 0) {
		return 1;
	}
	for (i = 0; i < sizeof(src->sin6_addr); i++) {
		hash = (hash ^ ((const uint8_t *)&src->sin6_addr)[i]) * 16777619u;
	}
	slot = &rate_slots[hash % RATE_SLOTS];

	pthread_mutex_lock(&rate_lock);
	if (slot->at_us == 0 || memcmp(&slot->addr, &src->sin6_addr, sizeof(slot->addr)) != 0) {
		slot->addr = src->sin6_addr;
		slot->tokens_milli = burst;
	}
	else {
		slot->tokens_milli += (now - slot->at_us) * auth_rate / 1000;
		if (slot->tokens_milli > burst) {
			slot->tokens_milli = burst;
		}
	}
	slot->at_us = now;
	ok = slot->tokens_milli >= 1000;
	if (ok) {
		slot->tokens_milli -= 1000;
	}
	pthread_mutex_unlock(&rate_lock);
	return ok;
}

/* nonce = 발급 시각(8, 빅엔디언) | HMAC(cookie_key, 발급 시각 | 출발지 IP) 의 앞 8B */
static int nonce_make(uint64_t issued, const net_ep_t *src, uint8_t out[AUTH_NONCE_LEN])
{
	uint8_t msg[8 + sizeof(src->sin6_addr)];
	uint8_t mac[VPN_HASH_LEN];
	int i;

	for (i = 0; i < 8; i++) {
		out[i] = (uint8_t)(issued >> (56 - 8 * i));
	}
	memcpy(msg, out, 8);
	memcpy(msg + 8, &src->sin6_addr, sizeof(src->sin6_addr));
	if (crypt_hmac(cookie_key, sizeof(cookie_key), msg, sizeof(msg), mac) < 0) {
		return -1;
	}
	memcpy(out + 8, mac, AUTH_NONCE_LEN - 8);
	return 0;
}

/* 이 서버가 이 출발지에 내준, 아직 살아 있는 nonce 면 발급 시각, 아니면 0. */
static uint64_t nonce_check(const uint8_t n[AUTH_NONCE_LEN], const net_ep_t *src)
{
	uint8_t want[AUTH_NONCE_LEN];
	uint64_t issued = 0, now = mono_us();
	int i;

	for (i = 0; i < 8; i++) {
		issued = issued << 8 | n[i];
	}
	if (issued == 0 || issued <= __atomic_load_n(&nonce_floor, __ATOMIC_RELAXED) || issued > now ||
			now - issued > (uint64_t)NONCE_TTL_SEC * 1000000u ||
			nonce_make(issued, src, want) < 0 || !crypt_equal(want, n, AUTH_NONCE_LEN)) {
		return 0;
	}
	return issued;
}

static int handshake_init(void)
{
	if (crypt_random(cookie_key, sizeof(cookie_key)) < 0) {
		return -1;
	}
	if (serverkey() != NULL) {
		hs_key = serverkey();
		memcpy(hs_pub, serverkey_pub(), VPN_PUB_LEN);
		return 0;
	}
	hs_key = crypt_ecdh_new(hs_pub);
	return hs_key != NULL ? 0 : -1;
}

/* REQ_HANDSHAKE: zero(80)
 *
 * 여기서는 아무것도 믿지 않고 아무것도 남기지 않는다. 누가 왔는지도 묻지 않는다 — 기기 ID 는
 * AUTH 에 감싸여 온다. "이 nonce 로 서명해 봐라"와 ID 를 감쌀 공개키만 돌려준다. 키를 만들고
 * 합의하는 비싼 계산도, 기억할 상태도 없으므로 출발지를 위조한 REQ 를 쏟아부어 서버를 바쁘게
 * 하거나 표를 채울 수 없다. 답은 REQ 보다 크지 않다. */
/* 받지 않는 버전의 REQ 에: 헤더 | min | max (proto.h 의 VERSION). */
static void send_version(int32_t sock, const net_ep_t *src, socklen_t srclen)
{
	uint8_t res[VERSION_MSG_LEN];
	msg_header_t msg_header;
	int32_t off;

	memset(&msg_header, 0, sizeof(msg_header));
	msg_header.version = PROTOCOL_VERSION;
	msg_header.type = MSG_TYPE_VERSION;
	off = msg_encode(res, sizeof(res), &msg_header);
	res[off++] = PROTOCOL_VERSION_MIN;
	res[off++] = PROTOCOL_VERSION;
	if (net_send(sock, res, off, src, srclen) < 0) {
		perror("sendto version");
	}
}

static void handle_request(int32_t sock, const uint8_t *packet, int32_t n,
		const net_ep_t *src, socklen_t srclen)
{
	uint8_t res[sizeof(msg_header_t) + CHALLENGE_PAYLOAD_LEN];
	msg_header_t msg_header;
	int32_t off;

	(void)packet;
	if (n < (int32_t)(sizeof(msg_header_t) + REQ_HS_PAYLOAD_LEN)) {
		LOG_LIMITED(LOG_HS, "[HS] short request (%d bytes)\n", n);
		return;
	}

	memset(&msg_header, 0, sizeof(msg_header));
	msg_header.version = PROTOCOL_VERSION;
	msg_header.type = MSG_TYPE_CHALLENGE;

	off = msg_encode(res, sizeof(res), &msg_header);
	if (nonce_make(mono_us(), src, res + off) < 0) {
		return;
	}
	off += AUTH_NONCE_LEN;
	memcpy(res + off, hs_pub, VPN_PUB_LEN);
	off += VPN_PUB_LEN;

	if (net_send(sock, res, off, src, srclen) < 0) {
		perror("sendto challenge");
	}
}

/* 인증이 끝난 기기와 세션 키를 합의하고 RES_HANDSHAKE 를 만든다.
 *
 *   RES_HANDSHAKE: pub_s(64) | 암호화된 net_config | tag(16)
 *
 * 일회용 키 쌍을 새로 만들어 클라이언트의 것과 합의하고, 거기에 기기 키와 주고받은
 * 패킷의 해시를 섞어 세션 키를 뽑는다 (secure.h). tag 는 그 키로 만든다 — 클라이언트는
 * tag 가 맞는 것을 보고 상대가 이 기기의 키를 아는 서버임을 안다.
 *
 * res 에 보낼 패킷을 채우고 길이를 돌려준다. 실패하면 -1. */
static int open_session(peer_t *peer, const device_t *dev, const uint8_t *auth, uint8_t *res, size_t cap)
{
	uint8_t secret[VPN_SECRET_LEN];
	secure_keys_t keys;
	msg_header_t msg_header;
	net_config_t cfg;
	crypt_ecdh_t *ecdh;
	char ib[INET_ADDRSTRLEN];
	int dropped;
	int cfg_len;
	int len = -1;

	if (cap < RES_HS_MIN_LEN) {
		return -1;
	}

	/* 터널 설정은 수락과 한 통에 실어 보낸다. 따로 보내면 세션은 열렸는데 주소를 모르는
	 * 순간이 생기고, 그 한 통이 사라졌을 때를 처리해야 한다. 세션 키로 감싸므로 이 기기
	 * 말고는 읽을 수 없고, 도중에 경로를 끼워 넣을 수도 없다. */
	/* keepalive 마다 같은 말을 찍지 않게 세션을 열 때만 알린다. */
	dropped = net_config_for(dev, &cfg);
	if (dropped > 0) {
		printf("[HS] %s: %d allow rules not pushed as routes (at most %d per device)\n",
				ip_str(dev->tun_ip, ib), dropped, NET_MAX_ROUTES);
	}
	cfg_len = net_config_encode(res + RES_HS_HEAD_LEN, cap - RES_HS_MIN_LEN, &cfg);
	if (cfg_len < 0) {
		return -1;
	}

	memset(&msg_header, 0, sizeof(msg_header));
	msg_header.version = PROTOCOL_VERSION;
	msg_header.type = MSG_TYPE_RES_HANDSHAKE;
	msg_header.session_idx = peer->session_idx;
	msg_encode(res, cap, &msg_header);

	ecdh = crypt_ecdh_new(res + sizeof(msg_header_t));
	if (ecdh == NULL) {
		return -1;
	}

	/* 클라이언트의 공개키가 곡선 위의 점이 아니면 여기서 실패한다. */
	if (crypt_ecdh_derive(ecdh, auth + sizeof(msg_header_t) + AUTH_OFF_PUB, secret) < 0 ||
			secure_derive(dev->key, secret, auth, res, &keys) < 0) {
		goto out;
	}

	/* 서버는 S->C 키로 보내고 C->S 키로 받는다. */
	if (secure_session_open(&peer->secure, keys.s2c, keys.c2s) < 0) {
		goto out;
	}

	len = secure_res_seal(keys.res, res, cap, (size_t)cfg_len);

out:
	crypt_ecdh_free(ecdh);
	crypt_wipe(secret, sizeof(secret));
	crypt_wipe(&keys, sizeof(keys));

	return len;
}

/* AUTH: pub_c(64) | nonce(16) | sealed(device_id(16) | posture(8)) | tag(16) | mac(32)
 *
 * 검사 순서에 뜻이 있다. nonce 를 먼저 본다 — 이 서버가 그 출발지에 방금 내준 것이 아니면
 * ID 를 풀어 보는 계산(ECDH)도 하지 않는다. 키를 가졌다는 것(mac)을 확인하기 전에는 "포스처가 못
 * 미친다" 같은 구체적인 이유를 알려 주지 않는다. 인증되지 않은 상대에게 정책의
 * 내용을 흘리지 않기 위해서다. 키 합의도 그 뒤에 한다.
 *
 * 터널 IP 는 클라이언트가 대지 않는다. 기기 목록에 적힌 것을 서버가 준다. 전에는
 * 클라이언트가 적어 보낸 값이 목록과 같은지 대조했는데, 틀릴 수만 있고 고를 수는
 * 없는 값을 받는 셈이었다.
 *
 * nonce 와 감싼 ID 는 표 잠금 밖에서 미리 본다 (auth_precheck). */
typedef struct auth_pre {
	uint64_t issued;			/* nonce 의 발급 시각. 0 이면 이 서버가 내준 것이 아니다 */
	int opened;				/* 감싼 부분이 열렸나 */
	uint8_t plain[AUTH_SEALED_PLAIN_LEN];	/* 연 것: device_id | posture */
} auth_pre_t;

/* 표의 어떤 것도 보지 않는다 — cookie_key 와 hs_key 는 뜰 때 정해진다. ID 를 푸는 ECDH 는 비싸서,
 * 쓰기 잠금 안에서 하면 nonce 하나를 받아 둔 상대가 그 nonce 로 엉터리 AUTH 를 쏟아부어 그동안
 * 모든 워커의 데이터 패킷을 세울 수 있다. */
static void auth_precheck(const uint8_t *packet, int32_t n, const net_ep_t *src, auth_pre_t *pre)
{
	memset(pre, 0, sizeof(*pre));
	if (n < (int32_t)AUTH_PACKET_LEN) {
		return;
	}
	pre->issued = nonce_check(packet + sizeof(msg_header_t) + AUTH_OFF_NONCE, src);
	if (pre->issued != 0) {
		/* pub_c 가 곡선 위의 점이 아니어도 여기서 걸린다. */
		pre->opened = secure_auth_open(hs_key, hs_pub, packet, pre->plain) == 0;
	}
}

static void handle_auth(int32_t sock, const uint8_t *packet, int32_t n,
		const net_ep_t *src, socklen_t srclen, const auth_pre_t *pre)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];
	uint8_t res[RES_HS_MIN_LEN + NET_CONFIG_MAX_LEN];
	uint8_t mac[AUTH_MAC_LEN];
	uint8_t plain[AUTH_SEALED_PLAIN_LEN];	/* 감싼 부분을 푼 것: device_id | posture */
	uint8_t *id = plain;
	const uint8_t *body = packet + sizeof(msg_header_t);
	const uint8_t *auth_mac = body + AUTH_OFF_MAC;
	posture_report_t posture;
	uint64_t issued;
	struct in_addr tun_ip;
	device_t *dev;
	peer_t *peer;
	int fresh;
	int len;
	int enrolling = 0;

	if (n < (int32_t)AUTH_PACKET_LEN) {
		LOG_LIMITED(LOG_HS, "[HS] short auth (%d bytes)\n", n);
		return;
	}

	/* 기기를 모르는 채 거절하는 두 경우는 감사 로그에 기기 칸을 0 으로 적는다. */
	/* 미리 본 뒤 이 잠금을 잡기까지 기기 목록을 다시 읽었으면, 그 전에 발급한 nonce 는 이제 받지 않는다. */
	issued = pre->issued > nonce_floor ? pre->issued : 0;
	if (issued == 0) {
		LOG_LIMITED(LOG_HS, "[HS] auth with a stale or foreign nonce\n");
		memset(id, 0, DEVICE_ID_LEN);
		audit_auth_denied(id, src, DENY_BAD_AUTH);
		send_deny(sock, src, srclen, DENY_BAD_AUTH, NULL, NULL);
		return;
	}
	if (!pre->opened) {
		LOG_LIMITED(LOG_HS, "[HS] auth whose device id does not open\n");
		memset(id, 0, DEVICE_ID_LEN);
		audit_auth_denied(id, src, DENY_BAD_AUTH);
		send_deny(sock, src, srclen, DENY_BAD_AUTH, NULL, NULL);
		return;
	}
	memcpy(plain, pre->plain, sizeof(plain));

	dev = device_find(id);
	if (dev == NULL) {
		dev = enroll_find(id);
		enrolling = dev != NULL;
	}
	if (dev == NULL) {
		LOG_LIMITED(LOG_HS, "[HS] unknown device %s\n", device_id_str(id, ids));
		audit_auth_denied(id, src, DENY_UNKNOWN_DEVICE);
		send_deny(sock, src, srclen, DENY_UNKNOWN_DEVICE, NULL, NULL);
		return;
	}
	device_id_str(dev->id, ids);

	/* 같은 nonce 는 한 번만: 이 기기가 마지막으로 쓴 것보다 늦게 발급된 것만 받는다. */
	fresh = issued > dev->nonce_used;

	/* 틀린 AUTH 는 nonce 를 건드리지 않는다. 받기만 하면 버리던 때에는 아무 값이나
	 * 채운 AUTH 한 통으로 진짜 기기의 핸드셰이크를 깨뜨릴 수 있었다. 그 기기가 보냈다고
	 * 확인되지 않은 패킷은 그 기기의 상태를 바꾸지 못한다.
	 *
	 * mac 은 헤더부터 덮는다. 일회용 공개키도 그 안이라, 사이에 낀 쪽이 자기 공개키로
	 * 바꿔 끼우면 여기서 걸린다. */
	if (!fresh ||
			crypt_hmac(dev->key, AUTH_KEY_LEN, packet, AUTH_SIGNED_LEN, mac) < 0 ||
			!crypt_equal(mac, auth_mac, AUTH_MAC_LEN)) {
		LOG_LIMITED(LOG_HS, "[HS] bad auth from device %s\n", ids);
		audit_auth_denied(dev->id, src, DENY_BAD_AUTH);
		send_deny(sock, src, srclen, DENY_BAD_AUTH, NULL, NULL);
		return;
	}

	/* 여기부터는 그 기기가 맞다. nonce 는 한 번만 쓴다 — 서명이 맞은 AUTH 를 받은
	 * 순간, 뒤의 검사에서 거절되더라도 쓴 것으로 친다. 남겨 두면 엿들은 AUTH 를 그대로
	 * 다시 보내 세션을 또 열 수 있다. */
	dev->nonce_used = issued;

	tun_ip = dev->tun_ip;

	/* 누구인지는 확인됐다. 이제 그 기기가 지금 믿을 만한 상태인지 본다. 포스처는
	 * mac 의 서명 범위 안이라 전달 도중에 고쳐지지 않았다. */
	/* 코드에 묶인 터널 주소를 그 사이에 다른 기기가 쓰게 됐으면 이 코드로는 등록할 수
	 * 없다. 여기서 멈추지 않으면 아래에서 그 주소의 세션을 내리게 되어, 쓸 수 없는 코드
	 * 하나가 멀쩡한 기기의 연결을 끊는다. */
	if (enrolling && device_find_ip(dev->tun_ip) != NULL) {
		printf("[enroll] code %s: its tunnel ip is already assigned to a device\n", ids);
		send_deny(sock, src, srclen, DENY_UNKNOWN_DEVICE, dev, auth_mac);
		return;
	}

	/* 등록하러 온 기기는 여기서 걸러내지 않는다. 정책은 그 기기가 등록을 마치고 자기
	 * 키로 터널을 열 때 건다. 등록까지 막으면 "방화벽을 켜고 다시 오라"는 말을 등록
	 * 실패로 듣게 되고, 등록용 세션으로는 어차피 어디에도 닿을 수 없다. */
	posture_decode(plain + DEVICE_ID_LEN, sizeof(posture), &posture);
	if (!enrolling && !device_posture_ok(dev, &posture)) {
		printf("[HS] device %s posture rejected (build=%u firewall=%u antivirus=%u disk=%u)\n",
				ids, posture.os_build, posture.firewall, posture.antivirus, posture.disk);
		audit_auth_denied(dev->id, src, DENY_POSTURE);
		send_deny(sock, src, srclen, DENY_POSTURE, dev, auth_mac);
		return;
	}

	/* 새로 인증하면 새 세션이다. 번호도, 키도, counter 도 새로 시작한다. 예전 세션에서
	 * 엿들은 패킷은 번호가 달라 찾지 못하고, 찾더라도 키가 달라 열리지 않는다. */
	peer = peer_lookup(tun_ip);
	if (peer != NULL) {
		peer_drop(peer, "replaced");
	}

	/* 이 기기가 다른 주소로 열어 둔 세션도 내린다. 관리자가 기기의 터널 주소를 바꾸면
	 * 예전 주소의 세션이 남는데, 그 주소는 이제 이 기기의 것이 아니다. 만료(60초)를
	 * 기다리는 동안 그 주소를 새로 받은 다른 기기와 겹친다. */
	while ((peer = peer_find_device(dev->id)) != NULL) {
		peer_drop(peer, "replaced");
	}

	peer = peer_register(tun_ip, dev->id, src, srclen);
	if (peer == NULL) {
		printf("[HS] register failed for %s\n", ip_str(tun_ip, ib));
		return;
	}

	peer->posture = posture;

	len = open_session(peer, dev, packet, res, sizeof(res));
	if (len < 0) {
		printf("[HS] key agreement failed for device %s\n", ids);
		peer_drop(peer, "error");
		return;
	}

	if (enrolling) {
		/* 등록용 세션이다. 기기의 세션으로 세지 않고, 감사 로그에도 세션으로 남기지
		 * 않는다. 받게 될 터널 주소의 자리를 미리 쓰지만 그 주소로는 아무것도 오가지
		 * 않는다. */
		peer->enroll = 1;
		printf("[enroll] code %s accepted, waiting for the device (%s)\n", ids, ip_str(tun_ip, ib));
	}
	else {
		STAT_INC(handshake_ok);
		audit_session_open(peer);

		printf("[HS] device %s authenticated as %s (build=%u firewall=%u antivirus=%u disk=%u)\n",
				ids, ip_str(tun_ip, ib), posture.os_build, posture.firewall, posture.antivirus, posture.disk);
	}

	if (net_send(sock, res, len, &peer->outer, peer->outer_len) < 0){
		perror("sendto handshake");
	}
}

/* KEEPALIVE (S -> C): 암호화된 net_config. 클라이언트는 이것으로 서버가 살아 있고 세션이
 * 그대로임을 안다. tag 가 붙으므로 서버인 척하는 쪽이 대신 보내 줄 수 없다.
 *
 * 응답마다 지금의 터널 설정을 통째로 싣는다. 관리자가 ACL 을 고쳐 그 기기가 갈 수 있는
 * 대역이 바뀌면, 클라이언트는 다음 keepalive(10초 이내)에서 새 경로를 받는다. 포스처가
 * 정책에 대 보이는 주기와 같다. */
static void send_keepalive(int32_t sock, peer_t *peer, const device_t *dev)
{
	uint8_t packet[PKT_OVERHEAD + NET_CONFIG_MAX_LEN];
	net_config_t cfg;
	int n;

	net_config_for(dev, &cfg);
	n = net_config_encode(packet + PKT_HDR_LEN, sizeof(packet) - PKT_OVERHEAD, &cfg);
	if (n < 0) {
		return;
	}

	n = secure_seal(&peer->secure, MSG_TYPE_KEEPALIVE, peer->session_idx, packet, sizeof(packet), (size_t)n);
	if (n < 0) {
		return;
	}

	if (net_send(sock, packet, n, &peer->outer, peer->outer_len) < 0) {
		perror("sendto");
	}
}

/* KEEPALIVE (C -> S). 세션 키로 푼 뒤의 내용은 posture(8) 이다.
 *
 * 핸드셰이크에서 한 번 통과했다고 세션이 끝날 때까지 믿지 않는다. 클라이언트는
 * keepalive 마다 지금의 포스처를 다시 싣고, 서버는 받을 때마다 정책에 다시 대 본다.
 *
 * 여기까지 온 패킷은 tag 가 맞았으므로 그 기기가 이 세션에 보낸 것이다. 위조된 것과
 * 다시 보낸 것은 이미 걸러졌고, 그런 패킷으로는 세션이 끊기지 않는다. 포스처가 정책에
 * 못 미치면 DENY 로 알리고 세션을 내린다 — 기기 스스로 "지금 방화벽이 꺼져 있다"고
 * 말한 것이다. */
static void handle_keepalive(int32_t sock, peer_t *peer, const uint8_t *body, int32_t n,
		uint64_t counter, const net_ep_t *src, socklen_t srclen)
{
	char ids[DEVICE_ID_STRLEN];
	posture_report_t posture;
	device_t *dev;

	if (n < (int32_t)sizeof(posture)) {
		LOG_LIMITED(LOG_DROP, "[drop] keepalive without posture (%d bytes)\n", n);
		STAT_INC(keepalive_dropped);
		return;
	}

	device_id_str(peer->device_id, ids);

	/* 세션이 열린 뒤 기기가 목록에서 지워졌다. */
	dev = device_find(peer->device_id);
	if (dev == NULL) {
		printf("[ka] device %s is no longer registered\n", ids);
		send_session_deny(sock, peer, src, srclen, DENY_UNKNOWN_DEVICE);
		peer_drop(peer, "device_removed");
		return;
	}

	/* 포스처 보고는 순서대로만 받는다. 데이터 패킷은 순서가 바뀌어 와도 받지만
	 * (secure.c 의 창), 보고는 "지금의 상태"라 늦게 온 예전 것이 최신 것을 덮으면 안
	 * 된다. 방화벽이 켜져 있던 때의 보고를 길목에서 붙잡아 두었다가, 끈 뒤에 풀어
	 * 놓는 것을 막는다. */
	if (peer->ka_seen && counter <= peer->ka_counter) {
		LOG_LIMITED(LOG_DROP, "[drop] keepalive out of order (counter %llu) idx=%08x\n",
				(unsigned long long)counter, peer->session_idx);
		STAT_INC(keepalive_dropped);
		return;
	}
	peer->ka_counter = counter;
	peer->ka_seen = 1;

	posture_decode(body, sizeof(posture), &posture);
	if (!device_posture_ok(dev, &posture)) {
		printf("[ka] device %s posture rejected (build=%u firewall=%u antivirus=%u disk=%u)\n",
				ids, posture.os_build, posture.firewall, posture.antivirus, posture.disk);
		send_session_deny(sock, peer, src, srclen, DENY_POSTURE);
		peer_drop(peer, "posture");
		return;
	}

	/* 기기 정책은 통과했다. 보고된 값은 세션에 남겨 둔다 — 기기 정책보다 높은 수준을
	 * 요구하는 ACL 규칙이 있으면 다음 패킷부터 이 값으로 판정한다. */
	peer->posture = posture;

	/* 토큰이 끝난 사용자를 세션에서 뗀다. ACL 은 패킷마다 만료를 따로 보므로 권한은 이미
	 * 그 순간에 끝났다. 여기서는 기록하고 상태에서 지운다. 세션은 그대로다 — 기기는 여전히
	 * 등록된 기기이고, 사용자가 새 토큰을 받으면 클라이언트가 다시 보낸다. */
	if (peer->logged_in && peer->user.expires <= (int64_t)time(NULL)) {
		printf("[login] device %s: user %s logged out (token expired)\n", ids, peer->user.name);
		audit_logout(peer, "expired");
		peer->logged_in = 0;
		memset(&peer->user, 0, sizeof(peer->user));
	}

	peer_touch(peer, src, srclen);
	send_keepalive(sock, peer, dev);
}

/* ENROLL (C -> S): device_id(16) | 기기 공개키(64). 등록 코드로 연 세션에서만 온다.
 *
 * 여기까지 온 것은 코드를 아는 쪽이다. 기기가 스스로 만든 ID 와 키를 받아 기기 목록에
 * 올린다. 터널 주소, 포스처 조건, 이름은 관리자가 코드를 만들 때 정해 둔 것을 쓴다 —
 * 기기가 정할 수 있는 것은 자기 신원뿐이다.
 *
 * 코드는 한 번 쓰면 끝이다. 다만 답이 사라져 같은 요청이 다시 오는 것은 받아 준다. 같은
 * ID 로 다시 오면 같은 답을 하고, 다른 ID 로 오면 거절한다. */
static void handle_enroll(int32_t sock, peer_t *peer, const uint8_t *body, int32_t n,
		const net_ep_t *src, socklen_t srclen)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];
	char label[64];
	uint8_t res[PKT_OVERHEAD + ENROLL_REPLY_LEN];
	uint8_t status;
	struct in_addr tun_ip;
	device_t *pending;
	int done;

	if (n < (int32_t)ENROLL_PAYLOAD_LEN) {
		LOG_LIMITED(LOG_DROP, "[enroll] short request (%d bytes)\n", n);
		return;
	}

	if (peer->enrolled) {
		status = memcmp(peer->enrolled_id, body, DEVICE_ID_LEN) == 0 ? ENROLL_OK : ENROLL_GONE;
	}
	else {
		pending = enroll_find(peer->device_id);

		if (pending == NULL) {
			status = ENROLL_GONE;
		}
		else if (device_find(body) != NULL || device_find_ip(pending->tun_ip) != NULL) {
			status = ENROLL_CONFLICT;
		}
		else {
			tun_ip = pending->tun_ip;
			snprintf(label, sizeof(label), "%s", enroll_label(pending));

			/* 파일에 적은 뒤 그 파일을 다시 읽어서 올린다. 표에 직접 끼워 넣으면 파일과
			 * 표가 다른 길로 만들어져, 다음에 다시 읽었을 때 달라질 수 있다. 읽고 나서
			 * 그 기기가 정말 있는지까지 본다. */
			done = enroll_complete(pending, body, body + DEVICE_ID_LEN, device_path);
			if (done == ENROLL_COMPLETE_CONFLICT) {
				printf("[enroll] device %s: its id or tunnel ip was added to %s meanwhile\n",
						device_id_str(body, ids), device_path);
				status = ENROLL_CONFLICT;
			}
			else if (done < 0 || (__atomic_store_n(&nonce_floor, mono_us(), __ATOMIC_RELAXED), device_load(device_path)) < 0 ||
					device_find(body) == NULL) {
				printf("[enroll] could not add device %s to %s\n",
						device_id_str(body, ids), device_path);
				status = ENROLL_FAILED;
			}
			else {
				peer->enrolled = 1;
				memcpy(peer->enrolled_id, body, DEVICE_ID_LEN);
				status = ENROLL_OK;

				printf("[enroll] device %s enrolled as %s\n",
						device_id_str(body, ids), ip_str(tun_ip, ib));
				printf("device: reloaded, %d devices\n", device_count());
				audit_enrolled(body, tun_ip, src, label);
			}
		}
	}

	/* 답에 서버 공개키를 싣는다. 기기는 그것과 자기 비밀키로 기기 키를 뽑는다 (proto.h). 등록 세션은
	 * 코드를 아는 서버만 열 수 있으므로 기기는 이 공개키를 따로 확인하지 않아도 된다. */
	res[PKT_HDR_LEN] = status;
	memcpy(res + PKT_HDR_LEN + 1, serverkey_pub(), VPN_PUB_LEN);
	n = secure_seal(&peer->secure, MSG_TYPE_ENROLL, peer->session_idx, res, sizeof(res), ENROLL_REPLY_LEN);
	if (n < 0) {
		return;
	}

	peer_touch(peer, src, srclen);
	if (net_send(sock, res, n, src, srclen) < 0) {
		perror("sendto enroll");
	}
}

/* LOGIN (C -> S): 사용자의 토큰. 기기의 세션에서만 온다.
 *
 * 토큰이 맞으면 그 사용자를 세션에 붙인다. 이미 다른 사용자가 붙어 있었으면 바꾼다 —
 * 같은 기기에서 다른 사람이 로그인한 것이다. 틀린 토큰은 있던 사용자를 떼지 않는다.
 * 새 토큰을 받다가 실패했다고 아직 유효한 로그인까지 잃을 이유는 없다.
 *
 * 답에는 결과와 토큰의 만료 시각과 서버가 읽은 사용자 이름을 싣는다. 클라이언트는
 * 그것을 보고 언제 새 토큰이 필요한지, IdP 의 어느 클레임이 이름으로 쓰였는지 안다. */
static void handle_login(int32_t sock, peer_t *peer, const uint8_t *body, int32_t n,
		const net_ep_t *src, socklen_t srclen)
{
	uint8_t res[PKT_OVERHEAD + LOGIN_RES_HEAD_LEN + USER_NAME_MAX];
	char ids[DEVICE_ID_STRLEN];
	user_identity_t who;
	uint64_t expires = 0;
	size_t name_len = 0;
	int status, same, i;

	device_id_str(peer->device_id, ids);
	/* 토큰 [ " " DPoP 증명 ] (proto.h). JWT 에는 공백이 없다. */
	{
		const char *sp = memchr(body, ' ', (size_t)n);
		size_t tl = sp != NULL ? (size_t)(sp - (const char *)body) : (size_t)n;

		status = idp_verify((const char *)body, tl, sp != NULL ? sp + 1 : NULL,
				sp != NULL ? (size_t)n - tl - 1 : 0, (int64_t)time(NULL), &who);
	}

	if (status == LOGIN_OK) {
		/* 답이 사라져 같은 토큰이 다시 온 것이면 다시 기록하지 않는다. */
		same = peer->logged_in && strcmp(peer->user.name, who.name) == 0 &&
			peer->user.expires == who.expires;
		peer->user = who;
		peer->logged_in = 1;
		if (!same) {
			STAT_INC(login_ok);
			printf("[login] device %s: user %s (%u groups) until %lld\n",
					ids, who.name, who.n_groups, (long long)who.expires);
			audit_login(peer, status);
		}
		expires = (uint64_t)who.expires;
		name_len = strlen(who.name);
	}
	else {
		STAT_INC(login_failed);
		printf("[login] device %s: token rejected (%s)\n", ids, idp_status_name(status));
		audit_login(peer, status);
	}

	res[PKT_HDR_LEN] = (uint8_t)status;
	for (i = 0; i < 8; i++) {
		res[PKT_HDR_LEN + 1 + i] = (uint8_t)(expires >> (56 - 8 * i));
	}
	memcpy(res + PKT_HDR_LEN + LOGIN_RES_HEAD_LEN, who.name, name_len);

	n = secure_seal(&peer->secure, MSG_TYPE_LOGIN, peer->session_idx, res, sizeof(res),
			LOGIN_RES_HEAD_LEN + name_len);
	if (n < 0) {
		return;
	}

	peer_touch(peer, src, srclen);
	if (net_send(sock, res, n, src, srclen) < 0) {
		perror("sendto login");
	}
}

/* vpn_server verify-token <idp-file> < token
 * 받으면 "ok user=... groups=... expires_in=...s" 와 0, 아니면 "rejected: <사유>" 와 1. 기기에 묶인
 * 토큰이면 토큰 뒤에 공백(또는 줄바꿈)과 DPoP 증명을 이어 준다. */
static int verify_token(const char *idp_file)
{
	static char token[LOGIN_TOKEN_MAX + 2];
	user_identity_t who;
	size_t n;
	int status, g;

	if (idp_load(idp_file) < 0) {
		return 2;
	}

	n = fread(token, 1, sizeof(token) - 1, stdin);
	while (n > 0 && (token[n - 1] == '\n' || token[n - 1] == '\r' || token[n - 1] == ' ')) {
		n--;
	}

	{
		char *sp = memchr(token, ' ', n);
		char *nl = memchr(token, '\n', n);
		size_t tl;

		if (sp == NULL || (nl != NULL && nl < sp)) {
			sp = nl;
		}
		tl = sp != NULL ? (size_t)(sp - token) : n;
		while (tl > 0 && token[tl - 1] == '\r') {
			tl--;
		}
		status = idp_verify(token, tl, sp != NULL ? sp + 1 : NULL, sp != NULL ? n - (size_t)(sp + 1 - token) : 0,
				(int64_t)time(NULL), &who);
	}
	if (status != LOGIN_OK) {
		printf("rejected: %s\n", idp_status_name(status));
		return 1;
	}

	printf("ok user=%s groups=", who.name);
	for (g = 0; g < who.n_groups; g++) {
		printf("%s%s", g == 0 ? "" : ",", who.groups[g]);
	}
	printf(" expires_in=%llds\n", (long long)(who.expires - (int64_t)time(NULL)));

	return 0;
}

/* 데이터 패킷 (MSG_TYPE_DATA). 표의 읽기 잠금 아래에서 돈다 — 세션과 기기와 규칙은 그동안 바뀌지
 * 않는다. 세션의 바뀌는 칸은 peer->lock 으로 고친다 (위의 "워커"). */
static void udp_data(int32_t sock, int tun_fd, uint8_t *packet, size_t cap, int n,
		const msg_header_t *h, const net_ep_t *src, socklen_t srclen)
{
	char ib[INET_ADDRSTRLEN], ob[NET_EP_STRLEN];
	const device_t *conn_dev;
	struct in_addr inner, inner_dst;
	peer_t *peer;
	uint8_t *ip;
	int verdict;

	peer = peer_find_idx(h->session_idx);
	if (peer == NULL) {
		LOG_LIMITED(LOG_DROP, "[drop] unknown session_idx[%08x]\n", h->session_idx);
		STAT_INC(unknown_session);
		return;
	}

	/* 세션 번호는 와이어에 그대로 보인다. 그 번호를 댔다고 그 기기인 것은
	 * 아니다. 세션 키로 열리는 패킷만 그 기기가 보낸 것이고, 열리지 않는
	 * 패킷은 세션의 어떤 상태도 바꾸지 못한 채 여기서 버려진다. */
	PEER_LOCK(peer);
	n = secure_open(&peer->secure, packet, (size_t)n, NULL);
	PEER_UNLOCK(peer);
	if (n == SECURE_REPLAY) {
		LOG_LIMITED(LOG_DROP, "[drop] counter already seen idx=%08x\n", peer->session_idx);
		STAT_INC(replayed);
		return;
	}
	if (n < 0) {
		LOG_LIMITED(LOG_DROP, "[drop] tag does not match idx=%08x\n", peer->session_idx);
		STAT_INC(bad_tag);
		return;
	}

	/* 등록용 세션은 등록 말고는 아무것도 하지 못한다. 코드만 가진 쪽이
	 * 그 세션으로 터널에 패킷을 넣을 수 있으면, 등록 코드가 곧 접속
	 * 권한이 된다. */
	if (peer->enroll) {
		LOG_LIMITED(LOG_DROP, "[drop] type %u on an enrollment session idx=%08x\n",
				h->type, peer->session_idx);
		return;
	}

	ip = packet + PKT_HDR_LEN;
	if (n < IP_MIN_HDR || IP_VERSION(ip) != 4){
		return;
	}

	/* 커넥터가 보낸 내부망의 답. 출발지는 커넥터의 터널 주소가 아니다. */
	conn_dev = device_find(peer->device_id);
	if (conn_dev != NULL && conn_dev->n_connector != 0) {
		if (relay_from_connector(sock, peer, conn_dev, packet, cap, n) == 0) {
			PEER_LOCK(peer);
			peer_touch(peer, src, srclen);
			PEER_UNLOCK(peer);
		}
		return;
	}

	memcpy(&inner, ip + IP_SRC_OFF, IP_ADDR_LEN);

	if (inner.s_addr != peer->inner.s_addr) {
		LOG_LIMITED(LOG_DROP, "[drop] spoofed src %s for idx %08x\n", ip_str(inner, ib), peer->session_idx);
		STAT_INC(spoofed_src);
		return;
	}

	/* 규칙 파일 없이 뜬 서버는 터널 대역 안까지만 통과시킨다. 전에는 "ACL 이
	 * 없으면 전부 허용"이었는데, 그때는 터널 대역 밖으로 가는 길 자체가
	 * 없어서 결과가 같았다. 이제 서버가 뒤쪽 네트워크로 전달할 수 있으므로,
	 * 규칙을 적지 않았다는 이유로 그 네트워크 전체가 열려서는 안 된다.
	 * 터널 밖으로 내보낼 곳은 규칙으로 적어서 연다. */
	memcpy(&inner_dst, ip + IP_DST_OFF, IP_ADDR_LEN);
	if (acl_enabled) {
		verdict = acl_check(ip, n, &peer->posture, peer->logged_in ? &peer->user : NULL,
				conn_dev != NULL ? &conn_dev->tags : NULL);
	}
	else {
		verdict = tun_subnet_of(inner_dst).s_addr == tun_subnet_of(peer->inner).s_addr
			? ACL_ALLOW : ACL_DENY;
	}

	if (verdict != ACL_ALLOW) {
		STAT_INC(acl_denied);
		if (verdict == ACL_DENY_POSTURE) {
			STAT_INC(acl_denied_posture);
		}
		if (verdict == ACL_DENY_USER) {
			STAT_INC(acl_denied_user);
		}
		if (log_ok(LOG_DENY)) {
			printf("[deny] %s -> %s proto=%d (%d bytes)",
					ip_str(inner, ib), ip_str(inner_dst, ob),
					ip[IP_PROTO_OFF], n);
			if (!acl_enabled) {
				printf(" outside the tunnel subnet (no acl file)");
			}
			if (verdict == ACL_DENY_POSTURE) {
				printf(" posture below the rule (build=%u firewall=%u antivirus=%u disk=%u)",
						peer->posture.os_build, peer->posture.firewall,
						peer->posture.antivirus, peer->posture.disk);
			}
			if (verdict == ACL_DENY_USER) {
				printf(" rule is for other users (logged in: %s)",
						peer->logged_in ? peer->user.name : "nobody");
			}
			printf("\n");
		}
		PEER_LOCK(peer);
		peer->acl_denied++;
		audit_access(peer, ip, n, 0, !acl_enabled ? "no_acl_file" :
				verdict == ACL_DENY_POSTURE ? "posture" :
				verdict == ACL_DENY_USER ? "user" : "acl");
		send_prohibited(sock, peer, ip, n);
		PEER_UNLOCK(peer);
		return;
	}

	PEER_LOCK(peer);
	audit_access(peer, ip, n, 1, NULL);
	peer_touch(peer, src, srclen);
	peer->rx_packets++;
	peer->rx_bytes += (uint64_t)n;
	PEER_UNLOCK(peer);

	/* 이 흐름의 답은 돌아올 때 들인다 (flow.h, -F). */
	flow_outbound(ip, n);

	conn_dev = device_connector_for(inner_dst);
	if (conn_dev != NULL) {
		LOG_VERBOSE("[udp->connector] %d bytes %s -> %s\n", n, ip_str(inner, ib),
				ip_str(inner_dst, ob));
		relay_to_connector(sock, conn_dev, packet, cap, n);
		return;
	}

	LOG_VERBOSE("[udp->tun] %d bytes from %s (inner src %s), icmp type=%d\n",
			n, endpoint_str(src, ob, sizeof(ob)),
			ip_str(inner, ib), ip[IP_IHL(ip)]);

	if (write(tun_fd, ip, n) < 0) {
		perror("write tun");
	}
}

/* 데이터가 아닌 것 (핸드셰이크, keepalive, 로그인, 등록, 종료 통지). 표의 쓰기 잠금 아래에서
 * 돈다 — 다른 워커의 데이터 패킷이 그동안 멈추므로 세션의 잠금은 필요 없다. */
static void udp_control(int32_t sock, uint8_t *packet, int n, const msg_header_t *h,
		const net_ep_t *src, socklen_t srclen)
{
	char ib[INET_ADDRSTRLEN];
	uint64_t counter;
	peer_t *peer;
	uint8_t *ip;

	peer = peer_find_idx(h->session_idx);
	if (peer == NULL) {
		LOG_LIMITED(LOG_DROP, "[drop] unknown session_idx[%08x]\n", h->session_idx);
		STAT_INC(unknown_session);
		return;
	}

	n = secure_open(&peer->secure, packet, (size_t)n, &counter);
	if (n == SECURE_REPLAY) {
		LOG_LIMITED(LOG_DROP, "[drop] counter already seen idx=%08x\n", peer->session_idx);
		STAT_INC(replayed);
		return;
	}
	if (n < 0) {
		LOG_LIMITED(LOG_DROP, "[drop] tag does not match idx=%08x\n", peer->session_idx);
		STAT_INC(bad_tag);
		return;
	}

	ip = packet + PKT_HDR_LEN;

	/* 등록용 세션은 등록 말고는 아무것도 하지 못한다. */
	if (peer->enroll) {
		if (h->type == MSG_TYPE_ENROLL) {
			handle_enroll(sock, peer, ip, n, src, srclen);
		}
		else {
			LOG_LIMITED(LOG_DROP, "[drop] type %u on an enrollment session idx=%08x\n",
					h->type, peer->session_idx);
		}
		return;
	}

	switch (h->type) {
		case MSG_TYPE_KEEPALIVE:
			handle_keepalive(sock, peer, ip, n, counter, src, srclen);
			return;
		case MSG_TYPE_LOGIN:
			handle_login(sock, peer, ip, n, src, srclen);
			return;
		case MSG_TYPE_DISCONNECT:
			printf("[peer] %s closed its session idx=%08x\n",
					ip_str(peer->inner, ib), peer->session_idx);
			peer_drop(peer, "closed");
			return;
		default:
			LOG_LIMITED(LOG_DROP, "[drop] unknown type %u\n", h->type);
			return;
	}
}

/* 받은 UDP 패킷 하나. packet 에 n 바이트, cap 은 packet 의 크기다. 헤더의 종류를 보고 데이터면 표의
 * 읽기 잠금, 아니면 쓰기 잠금으로 넘긴다. 종류는 tag 가 덮는 칸이라, 바꿔 보내면 열리지 않는다.
 *
 * 인증 전에 누구나 보낼 수 있는 것은 쓰기 잠금을 잡기 전에 거른다 — 쓰기 잠금 동안 모든 워커의 데이터가
 * 멈추기 때문이다. REQ 는 표를 보지 않으므로 잠금 없이 답하고, AUTH 는 주소마다 빠르기를 제한한 뒤
 * 비싼 앞부분을 잠금 밖에서 하고, 없는 세션 번호로 온 것은 읽기 잠금 안에서 버린다. */
static void udp_in(int32_t sock, int tun_fd, uint8_t *packet, size_t cap, int n,
		const net_ep_t *src, socklen_t srclen)
{
	msg_header_t h;

	if (msg_decode(packet, (size_t)n, &h) < 0) {
		LOG_LIMITED(LOG_DROP, "[drop] bad header (%d bytes)\n", n);
		return;
	}
	if (h.version < PROTOCOL_VERSION_MIN || h.version > PROTOCOL_VERSION) {
		/* 접속을 청하는 쪽에만 답한다. 그 밖의 종류는 버전마다 모양이 다르니 읽지 않는다. */
		if (h.type == MSG_TYPE_REQ_HANDSHAKE && auth_rate_ok(src)) {
			send_version(sock, src, srclen);
		}
		LOG_LIMITED(LOG_DROP, "[drop] protocol v%u from a client (this server takes v%u..v%u)\n",
				h.version, PROTOCOL_VERSION_MIN, PROTOCOL_VERSION);
		STAT_INC(version_mismatch);
		return;
	}

	if (h.type == MSG_TYPE_DATA) {
		TABLE_RDLOCK();
		udp_data(sock, tun_fd, packet, cap, n, &h, src, srclen);
		TABLE_UNLOCK();
	}
	else if (h.type == MSG_TYPE_REQ_HANDSHAKE) {
		handle_request(sock, packet, n, src, srclen);
	}
	else if (h.type == MSG_TYPE_AUTH) {
		auth_pre_t pre;

		if (!auth_rate_ok(src)) {
			LOG_LIMITED(LOG_HS, "[HS] too many AUTH from one address, dropped\n");
			STAT_INC(auth_rate_limited);
			return;
		}
		auth_precheck(packet, n, src, &pre);
		TABLE_WRLOCK();
		handle_auth(sock, packet, n, src, srclen, &pre);
		TABLE_UNLOCK();
	}
	else {
		int known;

		TABLE_RDLOCK();
		known = peer_find_idx(h.session_idx) != NULL;
		TABLE_UNLOCK();
		if (!known) {
			LOG_LIMITED(LOG_DROP, "[drop] unknown session_idx[%08x]\n", h.session_idx);
			STAT_INC(unknown_session);
			return;
		}
		TABLE_WRLOCK();
		udp_control(sock, packet, n, &h, src, srclen);
		TABLE_UNLOCK();
	}
}

/* tun 에서 읽은 패킷 하나. packet + PKT_HDR_LEN 에 n 바이트, cap 은 packet 의 크기다. */
static void tun_in(int32_t sock, uint8_t *packet, size_t cap, int n)
{
	char ib[INET_ADDRSTRLEN], ob[NET_EP_STRLEN];
	net_ep_t to;
	socklen_t to_len;
	struct in_addr inner, from;
	peer_t *peer;
	uint8_t *ip;

	ip = packet + PKT_HDR_LEN;
	if (n < IP_MIN_HDR || IP_VERSION(ip) != 4) {
		LOG_LIMITED(LOG_DROP, "[skip] non-IPv4 (ver=%d, %d bytes)\n",
				IP_VERSION(ip), n);
		return;
	}

	memcpy(&inner, ip + IP_DST_OFF, IP_ADDR_LEN);

	TABLE_RDLOCK();
	peer = peer_lookup(inner);
	if (peer == NULL || peer->enroll) {
		TABLE_UNLOCK();
		LOG_LIMITED(LOG_DROP, "[drop] no peer for %s\n", ip_str(inner, ib));
		return;
	}

	/* 서버 쪽에서 먼저 클라이언트로 거는 연결은 들이지 않는다 (-F). 터널 대역 안에서 오는 것은 다른
	 * 클라이언트가 보내 그쪽의 ACL 을 이미 지났거나, 서버 자신의 터널 주소다. */
	memcpy(&from, ip + IP_SRC_OFF, IP_ADDR_LEN);
	if (flow_enabled() && tun_subnet_of(from).s_addr != tun_subnet_of(inner).s_addr &&
			!flow_inbound_ok(ip, n)) {
		TABLE_UNLOCK();
		STAT_INC(flow_dropped);
		LOG_LIMITED(LOG_DENY, "[deny] %s: not a reply to a flow the client opened (stateful, -F)\n", ip_str(inner, ib));
		return;
	}

	PEER_LOCK(peer);
	LOG_VERBOSE("[tun->udp] %d bytes to %s (%s), icmp type=%d\n",
			n, ip_str(inner, ib),
			endpoint_str(&peer->outer, ob, sizeof(ob)),
			ip[IP_IHL(ip)]);

	peer->tx_packets++;
	peer->tx_bytes += (uint64_t)n;

	n = secure_seal(&peer->secure, MSG_TYPE_DATA, peer->session_idx,
			packet, cap, (size_t)n);
	to = peer->outer;
	to_len = peer->outer_len;
	PEER_UNLOCK(peer);
	TABLE_UNLOCK();

	if (n < 0) {
		LOG_LIMITED(LOG_DROP, "[drop] seal failed for %s\n", ip_str(inner, ib));
		return;
	}

	if (net_send(sock, packet, (size_t)n, &to, to_len) < 0) {
		perror("sendto");
	}
}

/* 워커 하나의 소켓과 tun 큐. 워커 0 은 main 의 루프다. */
typedef struct worker {
	int32_t sock;
	int tun_fd;
	pthread_t thread;
} worker_t;

static worker_t workers[MAX_WORKERS];

/* 같은 이름의 tun 장치에 큐를 하나 더 연다 (IFF_MULTI_QUEUE). 커널이 흐름마다 큐를 나눠 준다.
 * 처음 부를 때 name 이 비어 있으면 이름을 받는다. */
static int tun_open_queue(char *name)
{
	struct ifreq ifr;
	int fd;

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	if (*name) {
		/* ifr 는 위에서 0 으로 채웠다. 끝의 NUL 자리 하나를 남기고 옮긴다. */
		memcpy(ifr.ifr_name, name, strnlen(name, IFNAMSIZ - 1));
	}
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		close(fd);
		return -1;
	}
	strcpy(name, ifr.ifr_name);
	return fd;
}

/* TCP 로 온 패킷 (tcp.h). 워커 0 의 소켓과 tun 큐로 UDP 와 같은 길을 지난다. */
static void tcp_packet(uint8_t *packet, size_t cap, int n, const net_ep_t *from, socklen_t fromlen)
{
	udp_in(workers[0].sock, workers[0].tun_fd, packet, cap, n, from, fromlen);
}

/* 워커 1..N-1. 데이터와 핸드셰이크를 나눠 받을 뿐 만료, 다시 읽기, 상태 소켓은 하지 않는다. */
static void *worker_main(void *arg)
{
	worker_t *w = arg;
	struct epoll_event ev, events[MAX_EVENTS];
	net_ep_t src;
	socklen_t srclen;
	uint8_t packet[BUF_SIZE];
	int epfd, nev, i, n;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		perror("epoll_create1 (worker)");
		return NULL;
	}
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = w->sock;
	epoll_ctl(epfd, EPOLL_CTL_ADD, w->sock, &ev);
	ev.data.fd = w->tun_fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, w->tun_fd, &ev);

	while (running) {
		nev = epoll_wait(epfd, events, MAX_EVENTS, 1000);
		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == w->sock) {
				srclen = sizeof(src);
				n = net_recv(w->sock, packet, sizeof(packet), &src, &srclen);
				if (n >= 0) {
					udp_in(w->sock, w->tun_fd, packet, sizeof(packet), n, &src, srclen);
				}
			}
			else {
				n = read(w->tun_fd, packet + PKT_HDR_LEN, sizeof(packet) - PKT_OVERHEAD);
				if (n >= 0) {
					tun_in(w->sock, packet, sizeof(packet), n);
				}
			}
		}
	}

	close(epfd);
	return NULL;
}

int main(int argc, char *argv[])
{
	char ifname[IFNAMSIZ];
	int tun_fd, sock, n, port;
	int tcp_port = 0, tcp_fd = -1;
	time_t tick_at = -1;
	int epfd = -1, nev, i;
	int opt;
	int status_fd = -1;
	const char *status_path = NULL;
	const char *enroll_path = NULL;
	const char *idp_path = NULL;
	const char *dns_path = NULL;
	const char *key_path = NULL;
	int nd;
	struct epoll_event ev, events[MAX_EVENTS];
	struct sockaddr_in6 local_addr;
	net_ep_t src;
	socklen_t srclen;
	uint8_t packet[BUF_SIZE];
	char *end;
	int ret = 1;
	int fd = 0;

	/* 서버를 띄우지 않고 암호 도구만 확인한다. Windows 클라이언트의
	 * `vpn_client selftest` 와 같은 벡터를 쓴다. */
	if (argc == 2 && strcmp(argv[1], "selftest") == 0) {
		return crypt_selftest();
	}

	/* 서버를 띄우지 않고 토큰 하나를 IdP 설정에 대 본다. IdP 를 새로 붙일 때 "이 IdP 가
	 * 주는 토큰을 서버가 받는가"(aud 매퍼, 그룹 클레임, 서명 알고리즘)를 먼저 확인한다. */
	if (argc == 3 && strcmp(argv[1], "verify-token") == 0) {
		return verify_token(argv[2]);
	}

	/* 서버의 고정 키 쌍을 만든다 (serverkey.h). 처음 한 번. 있는 파일은 덮지 않는다. */
	if (argc == 3 && strcmp(argv[1], "genkey") == 0) {
		return serverkey_generate(argv[2]) == 0 ? 0 : 1;
	}

	while ((opt = getopt(argc, argv, "s:n:m:a:e:u:d:k:L:w:t:r:Fv")) != -1) {
		if (opt == 's') {
			status_path = optarg;
		}
		else if (opt == 'e') {
			enroll_path = optarg;
		}
		else if (opt == 'u') {
			idp_path = optarg;
		}
		else if (opt == 'd') {
			dns_path = optarg;
		}
		else if (opt == 'k') {
			key_path = optarg;
		}
		else if (opt == 'a') {
			if (audit_open(optarg) < 0) {
				fprintf(stderr, "cannot open the audit log : %s\n", optarg);
				return 1;
			}
		}
		else if (opt == 'n') {
			tun_prefix = (int)strtol(optarg, &end, 10);
			if (*end != '\0' || tun_prefix < 8 || tun_prefix > 30) {
				fprintf(stderr, "invalid tunnel prefix length (8..30) : %s\n", optarg);
				return 1;
			}
		}
		else if (opt == 'm') {
			tun_mtu = (int)strtol(optarg, &end, 10);
			if (*end != '\0' || tun_mtu < 576 || tun_mtu > (int)(BUF_SIZE - PKT_OVERHEAD)) {
				fprintf(stderr, "invalid tunnel mtu (576..%d) : %s\n", (int)(BUF_SIZE - PKT_OVERHEAD), optarg);
				return 1;
			}
		}
		else if (opt == 'v') {
			verbose = 1;
		}
		else if (opt == 'F') {
			flow_enable();
		}
		else if (opt == 't') {
			long v = strtol(optarg, &end, 10);
			if (*end != '\0' || v <= 0 || v > 65535) {
				fprintf(stderr, "invalid tcp port : %s\n", optarg);
				return 1;
			}
			tcp_port = (int)v;
		}
		else if (opt == 'w') {
			long v = strtol(optarg, &end, 10);
			if (*end != '\0' || v < 1 || v > MAX_WORKERS) {
				fprintf(stderr, "invalid number of workers (1..%d) : %s\n", MAX_WORKERS, optarg);
				return 1;
			}
			nworkers = (int)v;
		}
		else if (opt == 'r') {
			long v = strtol(optarg, &end, 10);
			if (*end != '\0' || v < 0 || v > 100000) {
				fprintf(stderr, "invalid AUTH rate per address per second (0 = no limit, ..100000) : %s\n", optarg);
				return 1;
			}
			auth_rate = (uint32_t)v;
		}
		else if (opt == 'L') {
			/* 짧게 두면 키를 자주 바꾸는 만큼 왕복 두 번의 끊김이 잦아진다. 시험에서는
			 * 몇 초로 줄여 바뀌는 것을 본다. */
			long v = strtol(optarg, &end, 10);
			if (*end != '\0' || v < 2 || v > 7 * 86400) {
				fprintf(stderr, "invalid session lifetime in seconds (2..%d) : %s\n", 7 * 86400, optarg);
				return 1;
			}
			session_lifetime = (time_t)v;
		}
		else {
			argc = 0;
			break;
		}
	}

	/* 옵션을 걷어내고 나머지 인자가 다시 argv[1] 부터 오게 한다. */
	if (argc != 0) {
		argv[optind - 1] = argv[0];
		argv += optind - 1;
		argc -= optind - 1;
	}

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: %s [-s status-socket] [-a audit-log] [-e enroll-file] [-u idp-file] [-d dns-file] [-k server-key] [-n tunnel-prefix-len] [-m tunnel-mtu] [-L session-lifetime-sec] [-w workers] [-r auth-per-sec] [-F] [-t tcp-port] [-v] <port> <device-file> [acl-file]\n", argv[0]);
		fprintf(stderr, "       -L: re-key every session after this many seconds (default %d)\n", SESSION_LIFETIME_SEC);
		fprintf(stderr, "       -w: worker threads, each with its own UDP socket and tun queue (default 1)\n");
		fprintf(stderr, "       -F: stateful: toward a client, pass only replies to flows the client opened\n");
		fprintf(stderr, "       -t: also take sessions over TCP on this port (e.g. 443) for networks that block UDP\n");
		fprintf(stderr, "       -v: a log line for every packet that passes (drops and denials are\n");
		fprintf(stderr, "           always logged, at most %d lines a second of each kind)\n", LOG_BURST);
		fprintf(stderr, "       -e: pending enrollments; with it the server adds devices to <device-file> itself\n");
		fprintf(stderr, "       -u: accept user logins (JWT) from the identity provider this file describes\n");
		fprintf(stderr, "       -d: internal DNS pushed to clients ('server <ip>' and 'domain <name>' lines)\n");
		fprintf(stderr, "       -k: the server key; needed for p256: devices and for enrollment (-e)\n");
		fprintf(stderr, "       %s genkey <server-key>   make the server key once\n", argv[0]);
		fprintf(stderr, "       -n, -m: what the tun device is configured with (default /24, mtu %d);\n", TUN_MTU);
		fprintf(stderr, "               they are pushed to every client\n");
		fprintf(stderr, "       %s selftest\n", argv[0]);
		return 1;
	}
	port = strtol(argv[1], &end, 10);
	if (*end != '\0' || port <= 0 || port > 65535) {
		fprintf(stderr, "invalid port : %s\n", argv[1]);
		return 1;
	}

	peer_init();
	acl_init();
	device_init();

	/* 서버 키는 기기 목록보다 먼저 읽는다. 공개키 기기(p256:)의 키를 그것으로 뽑는다. 등록 코드로
	 * 올라오는 기기는 모두 공개키 기기이므로 -e 에는 -k 가 있어야 한다. */
	if (key_path != NULL) {
		if (serverkey_load(key_path) < 0) {
			return 1;
		}
		printf("server key: %s\n", key_path);
	}
	else if (enroll_path != NULL) {
		fprintf(stderr, "enrollment (-e) needs the server key (-k); make one with: %s genkey <file>\n", argv[0]);
		return 1;
	}

	if (handshake_init() < 0) {
		fprintf(stderr, "cannot set up the handshake keys\n");
		return 1;
	}

	/* 기기 목록은 ACL 과 달리 생략할 수 없다. 없으면 누구도 받아 줄 수 없고,
	 * "목록이 없으면 모두 허용"으로 두면 설정 실수가 곧 무인증 서버가 된다. */
	nd = device_load(argv[2]);
	if (nd < 0) {
		fprintf(stderr, "device_load failed: %s\n", argv[2]);
		return 1;
	}
	printf("device: %d devices loaded from %s\n", nd, argv[2]);
	device_dump();
	device_path = argv[2];

	/* 등록은 파일을 줬을 때만 받는다. 주지 않은 서버는 기기 목록을 읽기만 하고, 바깥에서
	 * 온 요청으로 그 파일이 바뀌는 일이 없다. */
	enroll_init();
	if (enroll_path != NULL) {
		int ne = enroll_load(enroll_path);
		if (ne < 0) {
			fprintf(stderr, "enroll_load failed: %s\n", enroll_path);
			return 1;
		}
		printf("enroll: %d pending from %s\n", ne, enroll_path);
	}

	if (argc == 4) {
		int nr = acl_load(argv[3]);
		if (nr < 0) {
			fprintf(stderr, "acl_load failed: %s\n", argv[3]);
			return 1;
		}
		printf("acl: %d rules loaded from %s\n", nr, argv[3]);
		acl_dump();
		acl_enabled = 1;
	} else {
		printf("acl: no rule file, only the tunnel subnet is reachable\n");
	}

	/* 사용자 로그인도 파일을 줬을 때만 받는다. 주지 않으면 user= / group= 이 걸린 규칙은
	 * 누구에게도 맞지 않는다 (기본 거부 쪽으로 틀린다). */
	if (idp_path != NULL) {
		int nk = idp_load(idp_path);
		if (nk < 0) {
			fprintf(stderr, "idp_load failed: %s\n", idp_path);
			return 1;
		}
		printf("idp: %d signing keys loaded from %s\n", nk, idp_path);
		idp_dump();
	}

	if (dns_path != NULL) {
		int nn = dns_load(dns_path);
		if (nn < 0) {
			fprintf(stderr, "dns_load failed: %s\n", dns_path);
			return 1;
		}
		printf("dns: %d domains from %s\n", nn, dns_path);
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGHUP, on_reload);

	/* 쓰기를 먼저 받는다. 읽기(데이터)를 먼저 받으면 패킷이 끊이지 않는 동안 핸드셰이크가 굶는다. */
	if (nworkers > 1) {
		pthread_rwlockattr_t attr;

		pthread_rwlockattr_init(&attr);
		pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
		pthread_rwlock_init(&table_lock, &attr);
		pthread_rwlockattr_destroy(&attr);
	}

	memset(&local_addr, 0, sizeof(local_addr));
	/* IPv4 와 IPv6 를 한 소켓으로 (IPV6_V6ONLY 0). IPv4 클라이언트는 v4-mapped 주소로 온다 (tcp.h). */
	local_addr.sin6_family = AF_INET6;
	local_addr.sin6_addr   = in6addr_any;
	local_addr.sin6_port   = htons((uint16_t)port);

	ifname[0] = '\0';
	for (i = 0; i < nworkers; i++) {
		int one = 1;

		workers[i].sock = -1;
		workers[i].tun_fd = nworkers == 1 ? tun_alloc(ifname) : tun_open_queue(ifname);
		if (workers[i].tun_fd < 0) {
			fprintf(stderr, "tun_alloc failed%s\n", nworkers > 1 ? " (multi-queue)" : "");
			return 1;
		}
		workers[i].sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (workers[i].sock < 0) {
			perror("socket");
			return 1;
		}
		{
			int off = 0;

			setsockopt(workers[i].sock, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
		}
		/* 같은 포트에 소켓 여럿. 커널이 출발지 주소의 해시로 나눠 주므로 한 클라이언트는 한 워커로 온다. */
		if (nworkers > 1 && setsockopt(workers[i].sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
			perror("SO_REUSEPORT");
			return 1;
		}
		if (bind(workers[i].sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
			perror("bind");
			return 1;
		}
		/* 답을 요청이 온 주소에서 보내려고 (tcp.h). */
		if (net_udp_init(workers[i].sock) < 0) {
			perror("IP_PKTINFO");
			return 1;
		}
	}
	tun_fd = workers[0].tun_fd;
	sock = workers[0].sock;

	printf("tun device: %s (fd=%d)\n", ifname, tun_fd);
	printf("listening on UDP 0.0.0.0:%d%s\n", port, nworkers > 1 ? "" : "");
	if (nworkers > 1) {
		printf("workers: %d\n", nworkers);
	}

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		perror("epoll_create1"); goto out;
	}

	ev.events  = EPOLLIN;
	ev.data.fd = tun_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
		perror("epoll_ctl: tun_fd"); goto out;
	}

	ev.events  = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		perror("epoll_ctl: sock"); goto out;
	}

	if (status_path != NULL) {
		status_fd = status_listen(status_path);
		if (status_fd < 0) {
			goto out;
		}

		ev.events  = EPOLLIN;
		ev.data.fd = status_fd;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, status_fd, &ev) < 0) {
			perror("epoll_ctl: status_fd"); goto out;
		}
		printf("status socket: %s\n", status_path);
	}

	if (tcp_port != 0) {
		tcp_fd = tcp_listen((uint16_t)tcp_port);
		if (tcp_fd < 0) {
			goto out;
		}
		ev.events  = EPOLLIN;
		ev.data.fd = tcp_fd;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, tcp_fd, &ev) < 0) {
			perror("epoll_ctl: tcp_fd"); goto out;
		}
		printf("listening on TCP 0.0.0.0:%d\n", tcp_port);
	}

	printf("epoll ready (epfd=%d, tun_fd=%d, sock=%d)\n", epfd, tun_fd, sock);

	for (i = 1; i < nworkers; i++) {
		if (pthread_create(&workers[i].thread, NULL, worker_main, &workers[i]) != 0) {
			fprintf(stderr, "cannot start worker %d\n", i);
			running = 0;
			nworkers = i;	/* 이미 띄운 것만 기다린다 */
			break;
		}
	}

	while (running) {
		nev = epoll_wait(epfd, events, MAX_EVENTS, 1000);
		if (nev < 0) {
			if (errno == EINTR){
				continue;
			}
			perror("epoll_wait");
			break;
		}

		/* 만료와 키 교체는 1초에 한 번 표를 훑는다. 워커가 여럿이면 표를 쓰기로 잡으므로 패킷마다
		 * 잡지 않게 초가 바뀌었을 때만 들어간다. */
		if (mono_now() != tick_at) {
			tick_at = mono_now();
			TABLE_WRLOCK();
			peer_check_expired();
			rekey_tick(sock);
			TABLE_UNLOCK();
			tcp_tick(epfd);
		}
		status_tick(epfd);

		/* kill -HUP 으로 기기 목록과 ACL 을 다시 읽는다. 서버를 내렸다 올리면 모든
		 * 세션이 끊기지만, 이렇게 하면 정책을 바꾸거나 기기 하나를 지우는 동안
		 * 나머지는 그대로 붙어 있다. 열려 있는 세션은 건드리지 않는다 — 다음
		 * keepalive 가 새 목록에 대 보고 걸러진다. epoll_wait 의 타임아웃이 1초라
		 * 시그널을 받고 늦어도 1초 안에 여기에 온다. */
		if (reload_requested) {
			reload_requested = 0;
			TABLE_WRLOCK();

			/* 감사 로그를 돌리는 쪽이 파일 이름을 바꿔 두었으면 새 파일에 이어 쓴다. */
			audit_reopen();

			/* ACL 은 패킷마다 대 보므로 다음 패킷부터 바로 새 규칙이다. 시작할 때
			 * 규칙 파일을 주지 않은 서버는 다시 읽어도 ACL 이 켜지지 않는다. 파일이
			 * 생겼다고 도중에 켜면, 파일이 사라졌을 때 끄는 것도 받아 줘야 하고 그건
			 * 설정 실수 하나로 전부 열리는 길이다. */
			if (acl_enabled) {
				int nr = acl_load(argv[3]);
				if (nr < 0) {
					printf("acl: reload failed, keeping the previous rules\n");
					audit_reload("acl", 0, 0);
				}
				else {
					printf("acl: reloaded, %d rules\n", nr);
					audit_reload("acl", 1, nr);
					acl_dump();
				}
			}

			/* IdP 가 키를 바꾸면 새 JWKS 를 받아 두고 SIGHUP 을 보낸다. 이미 로그인한
			 * 사용자는 그 토큰이 끝날 때까지 그대로다. */
			if (idp_path != NULL) {
				int nk = idp_load(idp_path);
				if (nk < 0) {
					printf("idp: reload failed, keeping the previous keys\n");
					audit_reload("idp", 0, 0);
				}
				else {
					printf("idp: reloaded, %d signing keys\n", nk);
					audit_reload("idp", 1, nk);
				}
			}

			/* 붙어 있는 기기는 다음 keepalive 응답에서 새 DNS 를 받는다. */
			if (dns_path != NULL) {
				int nn = dns_load(dns_path);
				if (nn < 0) {
					printf("dns: reload failed, keeping the previous servers\n");
					audit_reload("dns", 0, 0);
				}
				else {
					printf("dns: reloaded, %d domains\n", nn);
					audit_reload("dns", 1, nn);
				}
			}

			/* 기기 목록보다 먼저 찍는다. 관리 도구는 "device:" 줄을 보고 다시 읽기가
			 * 끝났다고 판단한다. */
			__atomic_store_n(&nonce_floor, mono_us(), __ATOMIC_RELAXED);
			if (enroll_path != NULL) {
				int ne = enroll_load(enroll_path);
				if (ne < 0) {
					printf("enroll: reload failed, keeping the previous list\n");
				}
				else {
					printf("enroll: reloaded, %d pending\n", ne);
				}
			}

			nd = device_load(argv[2]);
			if (nd < 0) {
				printf("device: reload failed, keeping the previous list\n");
				audit_reload("devices", 0, 0);
			}
			else {
				printf("device: reloaded, %d devices\n", nd);
				audit_reload("devices", 1, nd);
				device_dump();
			}
			TABLE_UNLOCK();
		}

		for (i = 0; i < nev; i++) {
			fd = events[i].data.fd;

			/* 상태를 이어 쓰는 접속. 상대가 닫은 것(EPOLLHUP)도 거기서 처리해 닫는다 —
			 * 아래로 내려가면 닫히지 않은 채 매번 다시 깨운다. */
			if (status_writable(epfd, fd)) {
				continue;
			}
			/* TCP 연결. 닫힌 것(EPOLLHUP)도 거기서 처리한다. */
			if (fd == tcp_fd) {
				tcp_accept(epfd, tcp_fd);
				continue;
			}
			if (tcp_event(epfd, fd, events[i].events, tcp_packet)) {
				continue;
			}

			if (events[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "[err] fd=%d events=0x%x\n",
						fd, events[i].events);
				continue;
			}

			if (fd == status_fd) {
				TABLE_WRLOCK();
				status_serve(epfd, status_fd, acl_enabled);
				TABLE_UNLOCK();
			}
			else if (fd == sock) {
				srclen = sizeof(src);
				n = net_recv(sock, packet, sizeof(packet), &src, &srclen);
				if (n < 0) {
					perror("recvfrom"); goto out;
				}
				udp_in(sock, tun_fd, packet, sizeof(packet), n, &src, srclen);
			}
			else if (fd == tun_fd) {
				/* 앞에는 헤더가, 뒤에는 tag 가 붙을 자리를 남기고 읽는다. 암호화는
				 * 읽은 자리에서 하므로 패킷을 옮기지 않는다. */
				n = read(tun_fd, packet + PKT_HDR_LEN, sizeof(packet) - PKT_OVERHEAD);
				if (n < 0) { perror("read tun"); goto out; }
				tun_in(sock, packet, sizeof(packet), n);
			}
		}
	}
	ret = 0;

	/* 다른 워커는 running 을 보고 1초 안에 끝난다. 그 뒤로는 스레드가 하나다. */
	for (i = 1; i < nworkers; i++) {
		pthread_join(workers[i].thread, NULL);
	}

	/* 끝난다고 알린다. 다시 시작하는 중이면 클라이언트는 30초를 기다리지 않고 바로 다시
	 * 붙는다. 세션도 감사 로그에 "shutdown" 으로 닫힌다. */
	{
		disconnect_ctx_t ctx = { .sock = sock, .reason = DISCONNECT_SERVER_SHUTDOWN };

		peer_drop_if(NULL, send_disconnect, &ctx, "shutdown");
	}

out:
	if (epfd >= 0) {
		close(epfd);
	}
	if (status_fd >= 0) {
		close(status_fd);
		unlink(status_path);
	}
	if (tcp_fd >= 0) {
		close(tcp_fd);
	}
	for (i = 0; i < nworkers; i++) {
		if (workers[i].sock >= 0) {
			close(workers[i].sock);
		}
		if (workers[i].tun_fd >= 0) {
			close(workers[i].tun_fd);
		}
	}
	audit_close();
	return ret;
}

