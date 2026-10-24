/* 서버 데이터 경로의 부하 생성기.
 *
 * 등록된 기기인 척 인증 핸드셰이크를 마친 뒤, 터널 안에 ICMP echo request 를 실은
 * DATA 패킷을 정해진 시간 동안 보낸다. 서버는 그 패킷을 tun 에 쓰고, 커널이 답한
 * echo reply 를 다시 tun 에서 읽어 DATA 로 돌려준다. 돌아온 개수를 세면 서버의 두
 * 경로(udp->tun, tun->udp)를 모두 지난 왕복 처리량이 된다.
 *
 *   loadgen [-s 페이로드] [-t 초] [-r pps] [-d 목적지] <server> <port> <id> <key>
 *
 * 실제 클라이언트가 아니라 TUN 을 만들지 않는다. UDP 소켓 하나로 와이어 포맷만
 * 흉내 내므로 root 가 필요 없고, 클라이언트 쪽 tun / 커널 비용이 측정에 섞이지 않는다.
 * 핸드셰이크와 패킷 암호(AES-256-GCM)는 Linux 클라이언트와 같은 client/src/session.c 를
 * 쓴다 — 같은 코드라 와이어가 어긋날 일이 없고, 암호화 비용도 실제와 같다. 터널 주소는
 * 서버가 RES_HANDSHAKE 로 내려 준 것을 쓴다.
 *
 * 송신과 수신은 스레드를 나눈다. 한 스레드가 번갈아 하면 보내는 동안 받지 못한
 * 응답이 소켓 버퍼에서 넘쳐 "서버가 잃어버린 것"처럼 보인다. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "session.h"

#define ICMP_HDR_LEN	8
#define ICMP_ECHO_REPLY	0
#define ICMP_ECHO_REQ	8
#define STAMP_LEN	8		/* 페이로드 앞 8B 에 보낸 시각(ns)을 싣는다 */
#define MIN_PAYLOAD	STAMP_LEN
#define MAX_PAYLOAD	(TUN_MTU - IP_MIN_HDR - ICMP_HDR_LEN)	/* 서버의 -m 기본값 기준 */

/* 지연 히스토그램. 10ms 까지는 1us 단위, 그 위로는 10s 까지 1ms 단위로 센다.
 * 수신 스레드 하나만 쓰고 측정이 끝난 뒤에 읽으므로 잠금이 필요 없다. */
#define FINE_US		10000
#define COARSE_MS	10000
#define HIST_LEN	(FINE_US + COARSE_MS)

typedef struct opts {
	struct sockaddr_in server;
	uint8_t dev_id[DEVICE_ID_LEN];
	uint8_t key[AUTH_KEY_LEN];
	struct in_addr dst;
	int payload;
	int seconds;
	uint64_t rate;			/* 0 이면 가능한 한 빨리 */
} opts_t;

/* 송신 / 수신 스레드와 1초마다 찍는 메인 스레드가 함께 본다. 값 하나씩만 읽고
 * 쓰므로 relaxed 로 충분하다 — 서로 다른 카운터 사이의 순서는 필요 없다. */
static _Atomic uint64_t tx_pkts, tx_errs, rx_pkts, rx_bytes, rx_other;
static atomic_int tx_stop, rx_stop;

static uint64_t hist[HIST_LEN];
static struct in_addr tun_ip;		/* 서버가 정해 준 이 기기의 터널 주소 */
static uint16_t icmp_id;

/* 송신 스레드는 tx 쪽(tx, tx_counter)만, 수신 스레드는 rx 쪽(rx, rx_max, rx_seen)만
 * 만진다. 두 방향의 키와 EVP 문맥이 따로라 잠금 없이 나눠 쓸 수 있다. */
static vpn_session_t sess;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int parse_hex(const char *s, uint8_t *out, size_t len)
{
	size_t i;
	unsigned int v;

	if (strlen(s) != len * 2) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		if (sscanf(s + i * 2, "%2x", &v) != 1) {
			return -1;
		}
		out[i] = (uint8_t)v;
	}
	return 0;
}

static uint16_t checksum(const uint8_t *p, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2) {
		sum += (uint32_t)(p[i] << 8 | p[i + 1]);
	}
	if (len & 1) {
		sum += (uint32_t)(p[len - 1] << 8);
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)~sum;
}

/* ---- 송신 ----------------------------------------------------------------- */

/* 평문 IP 패킷(IPv4 | ICMP echo | stamp | 채움)을 한 번만 만든다. 패킷마다 바뀌는
 * 것은 ICMP seq, 보낸 시각, ICMP 체크섬뿐이다. IP 헤더는 그대로 두므로 IP 체크섬은
 * 다시 계산하지 않는다. 헤더와 counter 는 secure_seal 이 붙인다. */
static size_t build_template(uint8_t *ip, const opts_t *o)
{
	uint8_t *icmp = ip + IP_MIN_HDR;
	uint16_t total = (uint16_t)(IP_MIN_HDR + ICMP_HDR_LEN + o->payload);
	uint16_t sum;
	int i;

	memset(ip, 0, IP_MIN_HDR);
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total >> 8);
	ip[3] = (uint8_t)total;
	ip[8] = 64;			/* TTL */
	ip[IP_PROTO_OFF] = 1;		/* ICMP */
	/* 서버는 inner src 가 세션의 터널 IP 와 다르면 위조로 보고 버린다. */
	memcpy(ip + IP_SRC_OFF, &tun_ip, IP_ADDR_LEN);
	memcpy(ip + IP_DST_OFF, &o->dst, IP_ADDR_LEN);
	sum = checksum(ip, IP_MIN_HDR);
	ip[10] = (uint8_t)(sum >> 8);
	ip[11] = (uint8_t)sum;

	memset(icmp, 0, ICMP_HDR_LEN);
	icmp[0] = ICMP_ECHO_REQ;
	icmp[4] = (uint8_t)(icmp_id >> 8);
	icmp[5] = (uint8_t)icmp_id;
	for (i = STAMP_LEN; i < o->payload; i++) {
		icmp[ICMP_HDR_LEN + i] = (uint8_t)i;
	}

	return total;
}

static void stamp(uint8_t *ip, const opts_t *o, uint64_t seq)
{
	uint8_t *icmp = ip + IP_MIN_HDR;
	uint64_t t = now_ns();
	uint16_t sum;

	icmp[2] = icmp[3] = 0;
	icmp[6] = (uint8_t)(seq >> 8);
	icmp[7] = (uint8_t)seq;
	/* 시각은 우리만 읽으므로 호스트 바이트 순서 그대로 둔다. 커널은 echo 의
	 * 페이로드를 그대로 돌려준다. */
	memcpy(icmp + ICMP_HDR_LEN, &t, STAMP_LEN);
	sum = checksum(icmp, (size_t)ICMP_HDR_LEN + (size_t)o->payload);
	icmp[2] = (uint8_t)(sum >> 8);
	icmp[3] = (uint8_t)sum;
}

typedef struct worker {
	int sock;
	const opts_t *o;
} worker_t;

static void *tx_main(void *arg)
{
	const worker_t *w = arg;
	const opts_t *o = w->o;
	uint8_t plain[TUN_MTU];
	uint8_t buf[BUF_SIZE];
	size_t len = build_template(plain, o);
	uint64_t seq = 0, start = now_ns(), due;
	struct timespec nap = { 0, 20000 };

	while (!atomic_load_explicit(&tx_stop, memory_order_relaxed)) {
		/* -r 가 있으면 "지금까지 보냈어야 할 개수"를 따라간다. 패킷마다 자지 않고
		 * 뒤처진 만큼 몰아서 보낸 뒤 잠깐 쉰다 — nanosleep 의 해상도로는 패킷 하나
		 * 간격(수 us)을 맞출 수 없다. */
		if (o->rate != 0) {
			due = (now_ns() - start) * o->rate / 1000000000ull;
			if (seq >= due) {
				nanosleep(&nap, NULL);
				continue;
			}
		}

		/* 암호화가 제자리에서 일어나므로 평문을 매번 다시 놓는다. */
		stamp(plain, o, seq);
		memcpy(buf + PKT_HDR_LEN, plain, len);
		if (session_send(&sess, MSG_TYPE_DATA, buf, sizeof(buf), len) < 0) {
			/* ENOBUFS / ECONNREFUSED 등. 보내지 못한 것은 손실로 세지 않는다. */
			atomic_fetch_add_explicit(&tx_errs, 1, memory_order_relaxed);
			continue;
		}
		seq++;
		atomic_fetch_add_explicit(&tx_pkts, 1, memory_order_relaxed);
	}

	return NULL;
}

/* ---- 수신 ----------------------------------------------------------------- */

static void record_latency(uint64_t ns)
{
	uint64_t us = ns / 1000;

	if (us < FINE_US) {
		hist[us]++;
	} else if (us / 1000 < COARSE_MS) {
		hist[FINE_US + us / 1000]++;
	} else {
		hist[HIST_LEN - 1]++;
	}
}

static uint64_t percentile_us(double p)
{
	uint64_t total = 0, want, seen = 0;
	size_t i;

	for (i = 0; i < HIST_LEN; i++) {
		total += hist[i];
	}
	if (total == 0) {
		return 0;
	}
	want = (uint64_t)((double)total * p);
	for (i = 0; i < HIST_LEN; i++) {
		seen += hist[i];
		if (seen > want) {
			return i < FINE_US ? i : (i - FINE_US) * 1000;
		}
	}
	return 0;
}

static void *rx_main(void *arg)
{
	const worker_t *w = arg;
	uint8_t buf[BUF_SIZE];
	const uint8_t *ip, *icmp;
	msg_header_t h;
	uint64_t sent_at, counter;
	ssize_t n;
	int len;

	while (!atomic_load_explicit(&rx_stop, memory_order_relaxed)) {
		n = recv(w->sock, buf, sizeof(buf), 0);
		if (n < 0) {
			continue;		/* SO_RCVTIMEO — 멈추라는 신호를 보러 간다 */
		}
		if (msg_decode(buf, (size_t)n, &h) < 0 || h.type != MSG_TYPE_DATA ||
				h.session_idx != sess.idx) {
			atomic_fetch_add_explicit(&rx_other, 1, memory_order_relaxed);
			continue;
		}
		len = secure_open(&sess.secure, buf, (size_t)n, &counter);
		if (len < IP_MIN_HDR + ICMP_HDR_LEN + STAMP_LEN) {
			atomic_fetch_add_explicit(&rx_other, 1, memory_order_relaxed);
			continue;
		}

		ip = buf + PKT_HDR_LEN;
		icmp = ip + IP_IHL(ip);
		if (ip[IP_PROTO_OFF] != 1 || icmp + ICMP_HDR_LEN + STAMP_LEN > ip + len ||
				icmp[0] != ICMP_ECHO_REPLY ||
				(uint16_t)(icmp[4] << 8 | icmp[5]) != icmp_id) {
			atomic_fetch_add_explicit(&rx_other, 1, memory_order_relaxed);
			continue;
		}

		memcpy(&sent_at, icmp + ICMP_HDR_LEN, STAMP_LEN);
		record_latency(now_ns() - sent_at);
		atomic_fetch_add_explicit(&rx_pkts, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&rx_bytes, (uint64_t)len, memory_order_relaxed);
	}

	return NULL;
}

/* ---- main ----------------------------------------------------------------- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-s payload] [-t seconds] [-r pps] [-d dst-ip]\n"
		"          <server-ip> <port> <device-id-hex> <key-hex>\n"
		"  -s  ICMP payload bytes, %d..%d (default 56)\n"
		"  -t  seconds to send (default 10)\n"
		"  -r  packets per second, 0 = as fast as possible (default 0)\n"
		"  -d  inner destination (default 10.0.0.1, the server's tunnel address)\n"
		"The tunnel address is the one the server hands out in RES_HANDSHAKE.\n",
		prog, MIN_PAYLOAD, MAX_PAYLOAD);
}

int main(int argc, char *argv[])
{
	opts_t o = { .payload = 56, .seconds = 10, .rate = 0 };
	posture_report_t post = {
		.os_build = 0,
		.firewall = POSTURE_STATE_ON,
		.antivirus = POSTURE_STATE_ON,
	};
	struct timeval tv = { 0, 200000 };
	int bufsize = 4 << 20;
	pthread_t tx, rx;
	worker_t w;
	uint64_t t0, t1, prev_tx = 0, prev_rx = 0, cur_tx, cur_rx;
	uint64_t sent, got, bytes;
	double secs, loss;
	int opt, sock, s;
	struct timespec drain = { 1, 0 };

	inet_pton(AF_INET, "10.0.0.1", &o.dst);

	while ((opt = getopt(argc, argv, "s:t:r:d:")) != -1) {
		switch (opt) {
			case 's': o.payload = atoi(optarg); break;
			case 't': o.seconds = atoi(optarg); break;
			case 'r': o.rate = strtoull(optarg, NULL, 10); break;
			case 'd':
				if (inet_pton(AF_INET, optarg, &o.dst) != 1) {
					usage(argv[0]); return 1;
				}
				break;
			default: usage(argv[0]); return 1;
		}
	}
	if (argc - optind != 4 || o.payload < MIN_PAYLOAD || o.payload > MAX_PAYLOAD ||
			o.seconds <= 0) {
		usage(argv[0]);
		return 1;
	}

	o.server.sin_family = AF_INET;
	o.server.sin_port = htons((uint16_t)atoi(argv[optind + 1]));
	if (inet_pton(AF_INET, argv[optind], &o.server.sin_addr) != 1 ||
			parse_hex(argv[optind + 2], o.dev_id, DEVICE_ID_LEN) < 0 ||
			parse_hex(argv[optind + 3], o.key, AUTH_KEY_LEN) < 0) {
		usage(argv[0]);
		return 1;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}
	/* connect 해 두면 send / recv 만으로 되고, 서버가 아닌 곳에서 온 패킷은 커널이
	 * 걸러 준다. 버퍼는 net.core.[rw]mem_max 까지만 커진다. */
	if (connect(sock, (struct sockaddr *)&o.server, sizeof(o.server)) < 0) {
		perror("connect");
		return 1;
	}
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

	icmp_id = (uint16_t)getpid();

	/* 측정용 기기라 포스처는 늘 통과하는 값을 싣는다. */
	sess.sock = sock;
	if (session_handshake(&sess, o.dev_id, o.key, NULL, &post) != HS_OK) {
		return 1;
	}
	tun_ip.s_addr = sess.cfg.tun_ip;
	if (o.rate) {
		printf("session idx %08x, tunnel %s, payload %d B, %d s, target %" PRIu64 " pps\n",
				sess.idx, inet_ntoa(tun_ip), o.payload, o.seconds, o.rate);
	} else {
		printf("session idx %08x, tunnel %s, payload %d B, %d s, as fast as possible\n",
				sess.idx, inet_ntoa(tun_ip), o.payload, o.seconds);
	}

	w.sock = sock;
	w.o = &o;
	if ((s = pthread_create(&rx, NULL, rx_main, &w)) != 0 ||
			(s = pthread_create(&tx, NULL, tx_main, &w)) != 0) {
		fprintf(stderr, "pthread_create: %s\n", strerror(s));
		return 1;
	}

	t0 = now_ns();
	for (s = 0; s < o.seconds; s++) {
		sleep(1);
		cur_tx = atomic_load_explicit(&tx_pkts, memory_order_relaxed);
		cur_rx = atomic_load_explicit(&rx_pkts, memory_order_relaxed);
		printf("%3ds  tx %9" PRIu64 " pps  rx %9" PRIu64 " pps\n",
				s + 1, cur_tx - prev_tx, cur_rx - prev_rx);
		fflush(stdout);
		prev_tx = cur_tx;
		prev_rx = cur_rx;
	}
	atomic_store(&tx_stop, 1);
	pthread_join(tx, NULL);
	t1 = now_ns();

	/* 아직 오고 있는 응답을 받을 시간을 준다. 그 뒤에도 안 온 것이 손실이다. */
	nanosleep(&drain, NULL);
	atomic_store(&rx_stop, 1);
	pthread_join(rx, NULL);

	sent = atomic_load(&tx_pkts);
	got = atomic_load(&rx_pkts);
	bytes = atomic_load(&rx_bytes);
	secs = (double)(t1 - t0) / 1e9;
	loss = sent ? 100.0 * (double)(sent - (got < sent ? got : sent)) / (double)sent : 0.0;

	/* 마지막 줄은 스크립트가 읽는다. 형식을 바꾸면 tools/loadgen/bench.sh 도 고친다. */
	printf("RESULT payload=%d sent=%" PRIu64 " recv=%" PRIu64 " send_err=%" PRIu64
			" other=%" PRIu64 " tx_pps=%.0f rx_pps=%.0f rx_mbps=%.1f loss=%.2f"
			" p50_us=%" PRIu64 " p99_us=%" PRIu64 " p999_us=%" PRIu64 "\n",
			o.payload, sent, got, atomic_load(&tx_errs), atomic_load(&rx_other),
			(double)sent / secs, (double)got / secs, (double)bytes * 8 / secs / 1e6, loss,
			percentile_us(0.50), percentile_us(0.99), percentile_us(0.999));

	session_close(&sess);
	close(sock);
	return 0;
}
