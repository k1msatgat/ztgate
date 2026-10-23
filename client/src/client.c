#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"
#include "identity.h"
#include "netcfg.h"
#include "posture.h"
#include "session.h"
#include "connector.h"

/* Linux 클라이언트 (프로토콜 버전 5).
 *
 *   vpn_client [-k 신원파일] enroll <server-ip> <port> <등록 코드>
 *   vpn_client [-k 신원파일] [-i tun 이름] [-t 토큰 파일] [-v] run <server-ip> <port>
 *   vpn_client posture
 *   vpn_client selftest
 *
 * 동작은 Windows 클라이언트(windows/core/tunnel.c 의 tunnel_run)와 같다. 같은 프로토콜
 * 코드(client/src/session.c, lib/common/secure.c)를 부하 생성기와 함께 쓴다. */

#define MAX_EVENTS 8

#define LOOP_TICK_MSEC		1000
#define POSTURE_POLL_MSEC	2000
#define SERVER_TIMEOUT_MSEC	(SERVER_TIMEOUT_SEC * 1000)

#define TUN_IFNAME_DEFAULT	"ztgate0"

#define EXIT_DENIED	2	/* 서버가 거절했다 — 스크립트가 "닿지 못함"과 구분할 수 있게 */

/* 답이 없는 LOGIN 을 다시 보내는 간격. keepalive 보다 짧게 잡아 로그인이 늦지 않게 한다. */
#define LOGIN_RETRY_MSEC	3000

typedef struct client {
	vpn_session_t session;
	identity_t ident;
	netcfg_t net;
	posture_report_t posture;	/* 마지막으로 보고한 값 */
	uint64_t last_rx_ms;
	uint64_t last_ka_ms;
	uint64_t last_posture_ms;
	uint32_t bcast;			/* 터널 대역의 브로드캐스트 주소 */
	int denied;			/* 서버가 세션을 거절했다. 터널은 두고 패킷만 막는다 */
	int readdress;			/* 서버가 다른 터널 주소를 주었다. 다시 핸드셰이크한다 */
	int server_closed;		/* 서버가 DISCONNECT 로 세션을 끝냈다. 다시 핸드셰이크한다 */

	/* 사용자 로그인 (-t). 토큰 파일이 바뀌거나 세션을 새로 열 때마다 보낸다. */
	const char *token_path;
	struct stat token_seen;		/* 마지막으로 읽은 파일 (바뀌었는지 보려고) */
	int login_due;			/* 보내야 하는데 아직 답을 받지 못했다 */
	uint64_t last_login_ms;
	int64_t user_expires;		/* 서버가 받아 준 토큰의 exp. 0 이면 로그인하지 않은 상태 */
	int verbose;
	const char *lan_if;		/* 커넥터로 돌 때 내부망 쪽 장치 (connector.h) */
} client_t;

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

static uint64_t get_current_time_ms(void){
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((uint64_t)ts.tv_sec * 1000) + ((uint64_t)(ts.tv_nsec / 1000000));
}

static const char *state_name(uint8_t state)
{
	return state == POSTURE_STATE_ON ? "on" : state == POSTURE_STATE_OFF ? "off" : "unknown";
}

static uint32_t subnet_broadcast(uint32_t addr, uint8_t prefix_len)
{
	uint32_t mask = htonl(0xFFFFFFFFu << (32 - prefix_len));

	return (addr & mask) | ~mask;
}

/* 서버는 inner dst 로 피어를 1:1 로 찾아(peer_lookup) 그 피어에게만 보내므로 멀티캐스트나
 * 브로드캐스트는 전달할 상대가 없다. 넣어 봐야 서버가 버리고, keepalive 판단만 흐린다. */
static int deliverable_dst(const client_t *c, const uint8_t *ip)
{
	uint32_t dst;

	/* 224.0.0.0/4 멀티캐스트와 240.0.0.0/4 (255.255.255.255 포함) */
	if (ip[IP_DST_OFF] >= 224) {
		return 0;
	}

	memcpy(&dst, ip + IP_DST_OFF, IP_ADDR_LEN);

	return dst != c->bcast;
}

/* 포스처를 다시 읽어 마지막으로 보고한 값과 달라졌는지 본다. 달라졌으면 갱신하고 1 을
 * 돌려줘 다음 keepalive 주기를 기다리지 않고 바로 보고하게 한다.
 *
 * 10초 주기만으로는 방화벽을 끈 뒤 최대 10초 동안 서버가 모른다. 읽는 것은 nft 를 한 번
 * 부르는 정도라 2초마다 읽고, 보내는 것은 값이 바뀌었을 때만 앞당긴다. */
static int posture_changed(client_t *c, uint64_t now)
{
	posture_report_t report;

	if (now - c->last_posture_ms < POSTURE_POLL_MSEC) {
		return 0;
	}
	c->last_posture_ms = now;

	posture_collect(&report);
	if (memcmp(&report, &c->posture, sizeof(report)) == 0) {
		return 0;
	}

	printf("[posture] changed: kernel=%u firewall=%s antivirus=%s\n", report.os_build,
			state_name(report.firewall), state_name(report.antivirus));
	c->posture = report;

	return 1;
}

/* 서버가 수락에 실어 준 설정을 tun 에 맞춘다. */
static int apply_session_config(client_t *c)
{
	if (!netcfg_usable(&c->session.cfg)) {
		fprintf(stderr, "[cfg] the server sent a tunnel configuration this client cannot use\n");
		return -1;
	}
	if (netcfg_apply(&c->net, &c->session.cfg) < 0) {
		return -1;
	}
	c->bcast = subnet_broadcast(c->net.applied.tun_ip, c->net.applied.prefix_len);

	return 0;
}

static int handshake(client_t *c)
{
	c->last_posture_ms = get_current_time_ms();
	posture_collect(&c->posture);
	printf("[HS] posture: kernel=%u firewall=%s antivirus=%s\n", c->posture.os_build,
			state_name(c->posture.firewall), state_name(c->posture.antivirus));

	return session_handshake(&c->session, c->ident.id, c->ident.key, &c->posture);
}

/* 서버의 keepalive 응답에는 지금의 터널 설정이 통째로 실려 온다. 경로나 MTU 만 바뀌었으면
 * 그 자리에서 맞추고, 주소가 바뀌었으면 다시 핸드셰이크한다 (새 주소로 세션을 다시 연다). */
static void netcfg_refresh(client_t *c, const uint8_t *body, int len)
{
	net_config_t cfg;

	if (net_config_decode(body, (size_t)len, &cfg) < 0 || !netcfg_usable(&cfg)) {
		printf("[cfg] unusable tunnel configuration in keepalive, kept the current one\n");
		return;
	}

	if (net_config_equal(&cfg, &c->net.applied)) {
		return;
	}

	if (cfg.tun_ip != c->net.applied.tun_ip || cfg.prefix_len != c->net.applied.prefix_len) {
		if (!c->readdress) {
			printf("[cfg] the server assigned a different tunnel address\n");
		}
		c->readdress = 1;
		return;
	}

	netcfg_apply(&c->net, &cfg);
}

/* ---- 사용자 로그인 ------------------------------------------------------------
 *
 * 클라이언트는 IdP 와 직접 이야기하지 않는다. 로그인(브라우저, 기기 코드)은 별도의 도구가
 * 하고 받은 토큰을 파일에 적는다 (client/ztgate_login). 클라이언트는 그 파일을 지켜보다가
 * 바뀌면 읽어서 세션 안으로 보낸다. 토큰을 새로 받는 것(refresh)도 그 도구의 일이라,
 * 터널을 도는 이 프로세스에는 HTTPS 도 IdP 별 차이도 들어오지 않는다. */

/* 토큰 파일을 읽는다. 앞뒤 공백과 줄바꿈은 뗀다. 길이, 실패하면 -1.
 *
 * 토큰은 가진 사람이 곧 그 사용자인 증표라 신원 파일처럼 다른 사람이 읽을 수 있는 파일은
 * 쓰지 않는다. 주인은 따지지 않는다 — 로그인은 보통 일반 계정으로 하고 터널은 root 로
 * 돌린다. */
static int token_read(const char *path, uint8_t *out, size_t cap)
{
	struct stat st;
	ssize_t n;
	size_t s = 0, e;
	int fd;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || (st.st_mode & 077) != 0) {
		fprintf(stderr, "[login] %s: must be a regular file with mode 600\n", path);
		close(fd);
		return -1;
	}

	n = read(fd, out, cap);
	close(fd);
	if (n <= 0) {
		return -1;
	}

	e = (size_t)n;
	while (s < e && (out[s] == ' ' || out[s] == '\n' || out[s] == '\r' || out[s] == '\t')) s++;
	while (e > s && (out[e - 1] == ' ' || out[e - 1] == '\n' || out[e - 1] == '\r' || out[e - 1] == '\t')) e--;
	if (e == s || (size_t)n == cap) {
		fprintf(stderr, "[login] %s: empty, or longer than %d bytes\n", path, (int)LOGIN_TOKEN_MAX);
		return -1;
	}
	memmove(out, out + s, e - s);

	return (int)(e - s);
}

/* 1초 틱마다 부른다. 파일이 바뀌었으면 보낼 것으로 표시하고, 보낼 것이 있으면 보낸다.
 * 답이 오면(login_response) 표시를 지운다. 답이 사라져도 LOGIN_RETRY_MSEC 뒤에 다시 간다. */
static void login_tick(client_t *c, uint64_t now)
{
	uint8_t packet[BUF_SIZE];
	struct stat st;
	int n;

	if (c->token_path == NULL || c->denied) {
		return;
	}

	if (stat(c->token_path, &st) == 0 &&
			(st.st_mtim.tv_sec != c->token_seen.st_mtim.tv_sec ||
			 st.st_mtim.tv_nsec != c->token_seen.st_mtim.tv_nsec ||
			 st.st_ino != c->token_seen.st_ino || st.st_size != c->token_seen.st_size)) {
		c->token_seen = st;
		c->login_due = 1;
		c->last_login_ms = 0;
	}

	/* 서버가 받아 준 토큰이 끝났다. 서버도 같은 순간에 사용자를 뗀다. */
	if (c->user_expires != 0 && (int64_t)time(NULL) >= c->user_expires) {
		printf("[login] token expired — waiting for a new one in %s\n", c->token_path);
		c->user_expires = 0;
	}

	if (!c->login_due || now - c->last_login_ms < LOGIN_RETRY_MSEC) {
		return;
	}
	c->last_login_ms = now;

	n = token_read(c->token_path, packet + PKT_HDR_LEN, LOGIN_TOKEN_MAX + 1);
	if (n < 0) {
		/* 파일이 아직 없거나 쓰는 중이다. 바뀌면 다시 본다. */
		c->login_due = 0;
		return;
	}
	if (session_send(&c->session, MSG_TYPE_LOGIN, packet, sizeof(packet), (size_t)n) < 0) {
		fprintf(stderr, "[login] send failed\n");
	}
	crypt_wipe(packet, sizeof(packet));
}

/* LOGIN (S -> C): status(1) | expires(8) | 사용자 이름 */
static void login_response(client_t *c, const uint8_t *body, int n)
{
	char name[LOGIN_USER_MAX + 1];
	uint64_t expires = 0;
	int i, nl;

	if (n < LOGIN_RES_HEAD_LEN) {
		return;
	}
	for (i = 0; i < 8; i++) {
		expires = (expires << 8) | body[1 + i];
	}
	nl = n - LOGIN_RES_HEAD_LEN;
	if (nl > LOGIN_USER_MAX) {
		nl = LOGIN_USER_MAX;
	}
	memcpy(name, body + LOGIN_RES_HEAD_LEN, (size_t)nl);
	name[nl] = '\0';

	c->login_due = 0;
	/* 거절돼도 서버는 그 전에 로그인한 사용자를 그대로 둔다. 그 만료 시각도 그대로 둔다. */
	if (body[0] != LOGIN_OK) {
		printf("[login] rejected: %s\n", session_login_name(body[0]));
		return;
	}

	if ((int64_t)expires != c->user_expires) {
		printf("[login] logged in as %s (token valid for %llds)\n", name,
				(long long)((int64_t)expires - (int64_t)time(NULL)));
	}
	c->user_expires = (int64_t)expires;
}

/* TUN -> UDP */
static int pump_tun(client_t *c, int32_t tun_fd, uint8_t *packet, size_t cap)
{
	uint8_t *ip = packet + PKT_HDR_LEN;
	int n;

	/* 앞에는 헤더가, 뒤에는 tag 가 붙을 자리를 남기고 읽는다. 암호화는 읽은 자리에서
	 * 하므로 패킷을 옮기지 않는다. */
	n = (int)read(tun_fd, ip, cap - PKT_OVERHEAD);
	if (n < 0) {
		perror("read tun");
		return -1;
	}

	if (n < IP_MIN_HDR || IP_VERSION(ip) != 4 || !deliverable_dst(c, ip)) {
		return 0;
	}

	/* 거절된 동안에는 서버에 세션이 없다. 보내 봐야 서버가 모르는 세션으로 버린다. */
	if (c->denied) {
		return 0;
	}

	if (c->verbose) {
		printf("[tun->udp] %d bytes, proto=%d\n", n, ip[IP_PROTO_OFF]);
	}

	if (session_send(&c->session, MSG_TYPE_DATA, packet, cap, (size_t)n) < 0) {
		fprintf(stderr, "[drop] seal / send failed\n");
	}

	return 0;
}

/* UDP -> TUN */
static int pump_udp(client_t *c, int32_t tun_fd, uint8_t *packet, size_t cap)
{
	msg_header_t msg_header;
	uint64_t counter;
	uint8_t *ip = packet + PKT_HDR_LEN;
	ssize_t wire;
	int n;

	wire = recv(c->session.sock, packet, cap, 0);
	if (wire < 0) {
		/* 서버 포트가 닫혀 있다는 ICMP. 서버가 재시작하는 중일 수 있다. */
		if (errno == ECONNREFUSED || errno == EAGAIN || errno == EINTR) {
			return 0;
		}
		perror("recv");
		return -1;
	}

	if (msg_decode(packet, (size_t)wire, &msg_header) < 0 ||
			msg_header.version != PROTOCOL_VERSION) {
		return 0;
	}

	if (msg_header.session_idx != c->session.idx) {
		if (c->verbose) {
			printf("[drop] wrong session [%08x][%08x]\n", msg_header.session_idx, c->session.idx);
		}
		return 0;
	}

	/* 출발지와 세션 번호는 위조할 수 있다. 정말 서버가 이 세션에 보낸 것인지는 tag 가
	 * 말해 준다. 그 전에는 내용을 믿지 않고 "서버가 살아 있다"는 표시(last_rx_ms)도 하지
	 * 않는다 — 순서가 반대면 위조 패킷이 죽은 서버를 살아 있는 것처럼 보이게 한다. */
	n = secure_open(&c->session.secure, packet, (size_t)wire, &counter);
	if (n < 0) {
		printf("[drop] %s\n", n == SECURE_REPLAY ? "counter already seen" : "tag does not match");
		return 0;
	}

	c->last_rx_ms = get_current_time_ms();

	switch (msg_header.type) {
		case MSG_TYPE_KEEPALIVE:
			if (c->verbose) {
				printf("[keepalive] recv\n");
			}
			netcfg_refresh(c, ip, n);
			return 0;
		case MSG_TYPE_DENY:
			/* 세션 중의 거절. 방금 보낸 keepalive 의 포스처가 정책에 못 미쳤거나 서버
			 * 쪽 정책이 바뀌었다. tun 은 닫지 않는다 — 닫으면 방화벽을 다시 켰을 때
			 * 스스로 돌아올 수 없다. */
			if (n < 1) {
				return 0;
			}
			printf("[deny] %s\n", session_deny_name(ip[0]));
			c->denied = 1;
			return 0;
		case MSG_TYPE_LOGIN:
			login_response(c, ip, n);
			return 0;
		case MSG_TYPE_DISCONNECT:
			/* 서버가 끝난다. 다시 시작하는 중일 수 있으니 30초를 기다리지 않고 다음 틱에
			 * 다시 핸드셰이크한다. 거절과 달리 포스처를 바꿀 일이 없다. */
			printf("[HS] server closed the session (%s), reconnecting\n",
					n >= 1 && ip[0] == DISCONNECT_SERVER_SHUTDOWN ? "shutting down" : "closed");
			c->server_closed = 1;
			return 0;
		case MSG_TYPE_DATA:
			break;
		default:
			printf("[drop] unknown type %u\n", msg_header.type);
			return 0;
	}

	if (n < IP_MIN_HDR || IP_VERSION(ip) != 4) {
		printf("[drop] udp: not IPv4 (%d bytes)\n", n);
		return 0;
	}

	if (c->verbose) {
		printf("[udp->tun] %d bytes, proto=%d\n", n, ip[IP_PROTO_OFF]);
	}

	if (write(tun_fd, ip, (size_t)n) < 0) {
		perror("write tun");
	}

	return 0;
}

static int open_socket(const struct sockaddr_in *server)
{
	int32_t sock;

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	/* connect 해 두면 서버가 아닌 곳에서 온 UDP 는 커널이 걸러 준다. */
	if (connect(sock, (const struct sockaddr *)server, sizeof(*server)) < 0) {
		perror("connect");
		close(sock);
		return -1;
	}

	return sock;
}

static int run(client_t *c, const struct sockaddr_in *server, const char *ifname)
{
	char sb[INET_ADDRSTRLEN];
	uint8_t packet[BUF_SIZE];
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];
	int32_t tun_fd = -1, epfd = -1, fd;
	int nev, i, changed, hs;
	uint64_t now;
	int ret = 1;

	c->session.sock = open_socket(server);
	if (c->session.sock < 0) {
		return 1;
	}

	printf("tunneling to %s:%u\n", ip_str(server->sin_addr, sb), ntohs(server->sin_port));

	/* 서버가 받아 준 뒤에 tun 을 만든다. 순서를 반대로 하면 거절당하는 경우에도 장치와
	 * 터널 대역 경로가 잠깐 생겼다 사라진다. 접근이 허락되기 전에는 터널이 없는 편이 맞다. */
	hs = handshake(c);
	if (hs != HS_OK) {
		ret = hs == HS_DENIED ? EXIT_DENIED : 1;
		goto out;
	}

	strncpy(c->net.ifname, ifname, IFNAMSIZ - 1);
	c->net.server = server->sin_addr;
	tun_fd = tun_alloc(c->net.ifname);
	if (tun_fd < 0) {
		fprintf(stderr, "tun_alloc failed\n");
		goto out;
	}
	printf("[%s] tun device ready\n", c->net.ifname);

	if (apply_session_config(c) < 0) {
		goto out;
	}

	/* 커넥터: 서버가 보내 준 내부망 행 패킷을 lan 으로 내보낼 준비. 터널 대역은 서버가 준
	 * 주소에서 안다. */
	if (c->lan_if != NULL) {
		struct in_addr net;
		uint8_t p = c->net.applied.prefix_len;

		net.s_addr = c->net.applied.tun_ip & htonl(0xFFFFFFFFu << (32 - p));
		if (connector_up(c->net.ifname, c->lan_if, net, p) < 0) {
			goto out;
		}
	}

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		perror("epoll_create1");
		goto out;
	}

	ev.events = EPOLLIN;
	ev.data.fd = tun_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0){
		perror("epoll_ctl: tun_fd");
		goto out;
	}

	ev.events = EPOLLIN;
	ev.data.fd = c->session.sock;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->session.sock, &ev) < 0){
		perror("epoll_ctl: sock");
		goto out;
	}

	c->last_rx_ms = get_current_time_ms();
	c->last_ka_ms = c->last_rx_ms;
	printf("[%s] connected\n", c->net.ifname);
	c->login_due = c->token_path != NULL;

	while (running){
		nev = epoll_wait(epfd, events, MAX_EVENTS, LOOP_TICK_MSEC);
		if (nev < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("epoll_wait");
			goto out;
		}

		now = get_current_time_ms();
		changed = posture_changed(c, now);

		/* 다시 핸드셰이크하는 경우는 셋이다.
		 *  - 서버가 30초 동안 조용하다 (재시작했거나 세션이 만료됐다).
		 *  - 서버가 다른 터널 주소를 주었다.
		 *  - 거절된 상태에서 포스처가 바뀌었다. 사용자가 방화벽을 다시 켰을 수 있으니 30초를
		 *    기다리지 않고 바로 다시 물어본다.
		 * 거절된 상태에서도 첫 번째 조건이 그대로 걸려, 포스처가 그대로여도 30초마다 다시
		 * 물어본다. 서버 쪽 정책이 풀렸을 수 있다. */
		if (now - c->last_rx_ms > SERVER_TIMEOUT_MSEC || c->readdress || c->server_closed ||
				(c->denied && changed)) {
			if (c->denied) {
				printf("[HS] retry after deny\n");
			}
			else if (c->server_closed) {
				printf("[HS] re-handshake after the server closed the session\n");
			}
			else if (c->readdress) {
				printf("[HS] re-handshake for the new tunnel address\n");
			}
			else {
				printf("[HS] no rx from server for %ds, re-handshake\n", SERVER_TIMEOUT_SEC);
			}

			/* 실패해도 여기서 다시 묻지 않는다. 그대로 두면 매 틱마다 핸드셰이크한다. */
			c->readdress = 0;
			c->server_closed = 0;
			switch (handshake(c)) {
				case HS_OK:
					if (apply_session_config(c) < 0) {
						goto out;
					}
					c->denied = 0;
					printf("[%s] connected\n", c->net.ifname);
					/* 새 세션에는 사용자가 없다. 지금 가진 토큰을 다시 보낸다. */
					c->login_due = c->token_path != NULL;
					c->last_login_ms = 0;
					c->user_expires = 0;
					break;
				case HS_DENIED:
					c->denied = 1;
					break;
				default:
					if (!running) {
						break;
					}
					fprintf(stderr, "[HS] failed re-handshake[%s][%u], retry in %ds\n",
							ip_str(server->sin_addr, sb), ntohs(server->sin_port),
							SERVER_TIMEOUT_SEC);
					break;
			}
			now = get_current_time_ms();
			c->last_rx_ms = now;
			c->last_ka_ms = now;
		}

		/* keepalive 는 NAT 매핑 유지, 생존 확인(서버는 반드시 되돌려준다), 포스처 재보고를
		 * 맡는다. 포스처는 트래픽이 흐르는 중에도 보고돼야 하므로 유휴 여부와 관계없이 10초
		 * 마다 보낸다. 거절된 상태에서는 서버에 세션이 없어 보내지 않는다. */
		else if (!c->denied && (changed || now - c->last_ka_ms > KEEPALIVE_INTERVAL_MSEC)) {
			if (session_send_keepalive(&c->session, &c->posture) < 0) {
				fprintf(stderr, "[keepalive] send failed\n");
			}
			else if (c->verbose || changed) {
				printf("[keepalive] sent\n");
			}
			c->last_ka_ms = now;
		}

		login_tick(c, now);

		for (i = 0; i < nev; i++){
			fd = events[i].data.fd;

			if (events[i].events & (EPOLLERR | EPOLLHUP)) {
				/* connect 한 UDP 소켓은 ICMP port unreachable 을 EPOLLERR 로도 알린다.
				 * 읽어서 오류를 비워야 다음 epoll_wait 가 또 깨우지 않는다. */
				if (fd != c->session.sock) {
					fprintf(stderr, "[err] fd=%d events=0x%x\n", fd, events[i].events);
					continue;
				}
			}

			if (fd == tun_fd) {
				if (pump_tun(c, tun_fd, packet, sizeof(packet)) < 0) {
					goto out;
				}
			}
			else if (fd == c->session.sock) {
				if (pump_udp(c, tun_fd, packet, sizeof(packet)) < 0) {
					goto out;
				}
			}
		}
	}
	ret = 0;

	/* 끝난다고 알린다. 서버는 이 세션을 만료(60초)까지 붙잡아 두지 않는다. */
	if (session_send_disconnect(&c->session, DISCONNECT_CLIENT_EXIT) == 0 && c->session.idx != 0) {
		printf("[HS] session closed\n");
	}

out:
	connector_down();
	session_close(&c->session);
	if (epfd >= 0) {
		close(epfd);
	}
	if (tun_fd >= 0) {
		close(tun_fd);
	}
	close(c->session.sock);
	crypt_wipe(packet, sizeof(packet));

	return ret;
}

/* 새 ID 와 키를 만들어 등록 코드로 서버에 올리고, 서버가 받아 준 뒤에 저장한다. */
static int enroll(client_t *c, const struct sockaddr_in *server, const char *code,
		const char *path, int force)
{
	identity_t existing;
	int r;
	int ret = 1;

	/* 이미 등록된 신원을 덮으면 서버에 등록된 예전 키는 더 이상 맞지 않는다. */
	if (!force && identity_load(path, &existing) != IDENTITY_NOT_ENROLLED) {
		fprintf(stderr, "%s already exists. Use -f to replace this device's identity.\n", path);
		crypt_wipe(&existing, sizeof(existing));
		return 1;
	}

	if (identity_generate(&c->ident) != IDENTITY_OK) {
		fprintf(stderr, "cannot generate a device identity\n");
		return 1;
	}

	c->session.sock = open_socket(server);
	if (c->session.sock < 0) {
		return 1;
	}

	posture_collect(&c->posture);
	r = session_enroll(&c->session, code, c->ident.id, c->ident.key, &c->posture);
	switch (r) {
		case ENROLL_OK:
			if (identity_save(path, &c->ident) != IDENTITY_OK) {
				/* 서버에는 올라갔는데 키를 잃었다. 관리자가 목록에서 지우고 새 코드를
				 * 만들어야 한다. */
				fprintf(stderr, "enrolled, but could not save %s — ask for a new code\n", path);
				break;
			}
			printf("enrolled. identity saved to %s\n", path);
			ret = 0;
			break;
		case ENROLL_GONE:
		case SESSION_ENROLL_REJECTED:
			fprintf(stderr, "the server does not know this code (mistyped, expired or already used)\n");
			break;
		case ENROLL_CONFLICT:
			fprintf(stderr, "the server already has this device id or tunnel address\n");
			break;
		case SESSION_ENROLL_BAD_CODE:
			fprintf(stderr, "not an enrollment code: %s\n", code);
			break;
		case SESSION_ENROLL_NO_RESPONSE:
			fprintf(stderr, "no response from the server\n");
			break;
		default:
			fprintf(stderr, "enrollment failed (%d)\n", r);
			break;
	}

	close(c->session.sock);
	crypt_wipe(&c->ident, sizeof(c->ident));

	return ret;
}

static void print_posture(void)
{
	posture_report_t p;

	posture_collect(&p);
	printf("kernel    %u.%u.%u (%u)\n", p.os_build >> 16, (p.os_build >> 8) & 0xFF,
			p.os_build & 0xFF, p.os_build);
	printf("firewall  %s\n", state_name(p.firewall));
	printf("antivirus unknown (not collected on Linux)\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-k identity-file] enroll <server-ip> <port> <enrollment-code> [-f]\n"
		"       %s [-k identity-file] [-i ifname] [-t token-file] [-v] run <server-ip> <port>\n"
		"       %s [-k identity-file] [-i ifname] [-v] connector <server-ip> <port> <lan-ifname>\n"
		"       %s posture\n"
		"       %s selftest\n"
		"  -k  device identity file (default %s)\n"
		"  -i  tun device name (default %s)\n"
		"  -t  log in as the user whose token (JWT) is in this file; sent again when it changes\n"
		"  -f  replace an existing identity when enrolling\n"
		"  -v  log every packet\n"
		"  connector: forward what the server relays to this device onto <lan-ifname> (NAT,\n"
		"             replies only back); the device must be listed with connector=<net>\n",
		prog, prog, prog, prog, prog, IDENTITY_FILE_DEFAULT, TUN_IFNAME_DEFAULT);
}

static int parse_server(const char *ip, const char *port, struct sockaddr_in *out)
{
	char *end;
	long p;

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;

	p = strtol(port, &end, 10);
	if (*end != '\0' || p <= 0 || p > 65535) {
		fprintf(stderr, "invalid port : %s\n", port);
		return -1;
	}
	out->sin_port = htons((uint16_t)p);

	if (inet_pton(AF_INET, ip, &out->sin_addr) != 1) {
		fprintf(stderr, "invalid server ip : %s\n", ip);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const char *ident_path = IDENTITY_FILE_DEFAULT;
	const char *ifname = TUN_IFNAME_DEFAULT;
	struct sigaction sa;
	struct sockaddr_in server;
	client_t client;
	const char *cmd;
	int force = 0;
	int opt;
	int ret = 1;

	/* 로그를 파일로 돌려도 줄 단위로 바로 보이게 한다 (test/linux_e2e.sh 가 읽는다). */
	setvbuf(stdout, NULL, _IOLBF, 0);
	memset(&client, 0, sizeof(client));

	while ((opt = getopt(argc, argv, "+k:i:t:vf")) != -1) {
		switch (opt) {
			case 'k': ident_path = optarg; break;
			case 'i': ifname = optarg; break;
			case 't': client.token_path = optarg; break;
			case 'v': client.verbose = 1; break;
			case 'f': force = 1; break;
			default: usage(argv[0]); return 1;
		}
	}
	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}

	cmd = argv[optind];
	/* 명령 뒤에 온 -f / -v 도 받는다. */
	for (opt = optind + 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "-f") == 0) {
			force = 1;
		}
		else if (strcmp(argv[opt], "-v") == 0) {
			client.verbose = 1;
		}
	}

	/* SA_RESTART 를 주지 않는다. 핸드셰이크 중의 poll 이 신호로 깨어나야 Ctrl-C 가 바로 듣는다. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (strcmp(cmd, "selftest") == 0) {
		return crypt_selftest() == 0 ? 0 : 1;
	}
	if (strcmp(cmd, "posture") == 0) {
		print_posture();
		return 0;
	}

	if (strcmp(cmd, "enroll") == 0 && argc - optind >= 4) {
		if (parse_server(argv[optind + 1], argv[optind + 2], &server) < 0) {
			return 1;
		}
		return enroll(&client, &server, argv[optind + 3], ident_path, force);
	}

	/* connector 는 run 에 내부망 쪽 장치 하나가 더해진 것이다. */
	if (strcmp(cmd, "connector") == 0 && argc - optind >= 4) {
		if (!connector_ifname_ok(argv[optind + 3])) {
			fprintf(stderr, "invalid interface name : %s\n", argv[optind + 3]);
			return 1;
		}
		client.lan_if = argv[optind + 3];
		cmd = "run";
	}

	if (strcmp(cmd, "run") == 0 && argc - optind >= 3) {
		if (parse_server(argv[optind + 1], argv[optind + 2], &server) < 0) {
			return 1;
		}
		switch (identity_load(ident_path, &client.ident)) {
			case IDENTITY_OK:
				break;
			case IDENTITY_NOT_ENROLLED:
				fprintf(stderr, "%s not found — enroll this device first\n", ident_path);
				return 1;
			default:
				return 1;
		}
		ret = run(&client, &server, ifname);
		crypt_wipe(&client.ident, sizeof(client.ident));
		return ret;
	}

	usage(argv[0]);
	return 1;
}
