#define _GNU_SOURCE	/* accept4 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "common.h"
#include "peer.h"
#include "acl.h"
#include "device.h"
#include "status.h"
#include "flow.h"

server_stats_t stats;

static time_t started_at;

/* 세션 하나가 400바이트 남짓이라 세션이 수천 개면 MB 단위가 된다. 버퍼는 필요한 만큼
 * 늘리되 STATUS_MAX 를 넘으면 잘린 JSON 을 보내지 않고 아무것도 보내지 않는다. */
#define STATUS_MAX (16u << 20)

static char *out;
static size_t outlen, outcap;
static int overflow;

static void put(const char *fmt, ...)
{
	va_list ap;
	size_t want;
	char *grown;
	int n;

	if (overflow) {
		return;
	}

	for (;;) {
		va_start(ap, fmt);
		n = vsnprintf(out + outlen, outcap - outlen, fmt, ap);
		va_end(ap);

		if (n < 0) {
			overflow = 1;
			return;
		}
		if ((size_t)n < outcap - outlen) {
			outlen += (size_t)n;
			return;
		}

		want = outcap * 2;
		while (want - outlen <= (size_t)n) {
			want *= 2;
		}
		if (want > STATUS_MAX || (grown = realloc(out, want)) == NULL) {
			overflow = 1;
			return;
		}
		out = grown;
		outcap = want;
	}
}

/* ---- 쓰는 중인 접속 -----------------------------------------------------------
 *
 * 받는 쪽 소켓 버퍼(보통 수백 KB)보다 크면 한 번에 다 쓰지 못한다. 터널을 나르는 루프라
 * 기다릴 수 없으므로 남은 것을 들고 있다가 쓸 수 있게 되면(EPOLLOUT) 이어 쓴다. 다 읽지
 * 않고 붙어만 있는 쪽이 자리를 차지하지 않게 WRITER_TTL_SEC 가 지나면 끊는다. */
#define WRITERS 4
#define WRITER_TTL_SEC 5

typedef struct writer {
	int fd;			/* -1 이면 빈 자리 */
	char *buf;
	size_t len, off;
	time_t at;		/* CLOCK_MONOTONIC 초 */
} writer_t;

static writer_t writers[WRITERS] = {
	{ .fd = -1 }, { .fd = -1 }, { .fd = -1 }, { .fd = -1 },
};

static void writer_close(int epfd, writer_t *w)
{
	epoll_ctl(epfd, EPOLL_CTL_DEL, w->fd, NULL);
	close(w->fd);
	free(w->buf);
	w->fd = -1;
	w->buf = NULL;
}

/* 남은 것을 쓸 수 있는 만큼 쓴다. 다 썼거나 상대가 닫았으면 접속을 닫는다. */
static void writer_flush(int epfd, writer_t *w)
{
	ssize_t n;

	while (w->off < w->len) {
		n = send(w->fd, w->buf + w->off, w->len - w->off, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		w->off += (size_t)n;
	}

	writer_close(epfd, w);
}

static const char *state_str(uint8_t v)
{
	switch (v) {
	case POSTURE_STATE_ON:	return "on";
	case POSTURE_STATE_OFF:	return "off";
	default:		return "unknown";
	}
}

/* 문자열로 나가는 값은 전부 여기서 만든 것이다 (16진수, 점 찍은 주소, 고정된 단어).
 * 밖에서 들어온 글자가 그대로 실리지 않으므로 JSON 이스케이프가 필요 없다. */
static void build(int acl_enabled)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN], ob[INET_ADDRSTRLEN];
	time_t now = mono_now();
	const peer_t *p;
	const device_t *dev;
	int i, g, first = 1;

	outlen = 0;
	overflow = 0;

	if (out == NULL) {
		out = malloc(65536);
		if (out == NULL) {
			overflow = 1;
			return;
		}
		outcap = 65536;
	}

	put("{\"uptime_sec\":%ld,\"devices\":%d,", (long)(now - started_at), device_count());
	put("\"acl\":{\"enabled\":%s,\"rules\":%d},", acl_enabled ? "true" : "false", acl_count());

	put("\"counters\":{\"handshake_ok\":%llu,", (unsigned long long)stats.handshake_ok);
	put("\"deny_unknown_device\":%llu,", (unsigned long long)stats.deny[DENY_UNKNOWN_DEVICE]);
	put("\"deny_bad_auth\":%llu,", (unsigned long long)stats.deny[DENY_BAD_AUTH]);
	put("\"deny_tun_ip\":%llu,", (unsigned long long)stats.deny[DENY_TUN_IP]);
	put("\"deny_posture\":%llu,", (unsigned long long)stats.deny[DENY_POSTURE]);
	put("\"keepalive_dropped\":%llu,", (unsigned long long)stats.keepalive_dropped);
	put("\"bad_tag\":%llu,", (unsigned long long)stats.bad_tag);
	put("\"replayed\":%llu,", (unsigned long long)stats.replayed);
	put("\"unknown_session\":%llu,", (unsigned long long)stats.unknown_session);
	put("\"spoofed_src\":%llu,", (unsigned long long)stats.spoofed_src);
	put("\"acl_denied\":%llu,", (unsigned long long)stats.acl_denied);
	put("\"acl_denied_posture\":%llu,", (unsigned long long)stats.acl_denied_posture);
	put("\"acl_denied_user\":%llu,", (unsigned long long)stats.acl_denied_user);
	put("\"login_ok\":%llu,", (unsigned long long)stats.login_ok);
	put("\"login_failed\":%llu,", (unsigned long long)stats.login_failed);
	put("\"connector_offline\":%llu,", (unsigned long long)stats.connector_offline);
	put("\"connector_dropped\":%llu,", (unsigned long long)stats.connector_dropped);
	put("\"flow_dropped\":%llu},", (unsigned long long)stats.flow_dropped);
	put("\"flows\":{\"enabled\":%s,\"open\":%d},", flow_enabled() ? "true" : "false", flow_count());

	put("\"sessions\":[");
	for (i = 0; i < MAX_PEERS; i++) {
		p = peer_at(i);
		/* 등록용 세션은 기기의 세션이 아니다. 목록에 섞이면 없는 기기가 붙어 있는 것처럼 보인다. */
		if (p == NULL || p->enroll) {
			continue;
		}

		put("%s{\"tunnel_ip\":\"%s\",\"device_id\":\"%s\",", first ? "" : ",",
				ip_str(p->inner, ib), device_id_str(p->device_id, ids));
		put("\"endpoint\":\"%s:%d\",\"session_idx\":\"%08x\",",
				ip_str(p->outer.sin_addr, ob), ntohs(p->outer.sin_port), p->session_idx);
		put("\"age_sec\":%ld,\"idle_sec\":%ld,",
				(long)(now - p->established_at), (long)(now - p->last_seen));
		put("\"posture\":{\"os_build\":%u,\"firewall\":\"%s\",\"antivirus\":\"%s\"},",
				p->posture.os_build, state_str(p->posture.firewall),
				state_str(p->posture.antivirus));
		put("\"rx_packets\":%llu,\"rx_bytes\":%llu,",
				(unsigned long long)p->rx_packets, (unsigned long long)p->rx_bytes);
		put("\"tx_packets\":%llu,\"tx_bytes\":%llu,",
				(unsigned long long)p->tx_packets, (unsigned long long)p->tx_bytes);
		put("\"acl_denied\":%llu,", (unsigned long long)p->acl_denied);
		/* 커넥터면 맡은 대역. 일반 기기는 빈 목록이다. */
		put("\"connector\":[");
		dev = device_find(p->device_id);
		for (g = 0; dev != NULL && g < dev->n_connector; g++) {
			struct in_addr a = { .s_addr = dev->connector[g].addr };
			put("%s\"%s/%u\"", g == 0 ? "" : ",", ip_str(a, ib), dev->connector[g].prefix_len);
		}
		put("],");
		/* 태그는 policy.c 가 정한 글자(a-z 0-9 _ -)뿐이라 그대로 적어도 된다. */
		put("\"tags\":[");
		for (g = 0; dev != NULL && g < dev->tags.n; g++) {
			put("%s\"%s\"", g == 0 ? "" : ",", dev->tags.name[g]);
		}
		put("],");
		/* 이름과 그룹은 policy.c 가 정한 글자만 들어 있어 따옴표 없이 그대로 적어도 된다. */
		if (p->logged_in) {
			put("\"user\":{\"name\":\"%s\",\"expires\":%lld,\"groups\":[", p->user.name,
					(long long)p->user.expires);
			for (g = 0; g < p->user.n_groups; g++) {
				put("%s\"%s\"", g == 0 ? "" : ",", p->user.groups[g]);
			}
			put("]}}");
		}
		else {
			put("\"user\":null}");
		}
		first = 0;
	}
	put("]}\n");
}

int status_listen(const char *path)
{
	struct sockaddr_un addr;
	mode_t old;
	int fd;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "status: socket path too long\n");
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("status socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	/* 지난 실행이 남긴 소켓 파일이 있으면 bind 가 실패한다. */
	unlink(path);

	/* 소켓 파일은 bind 하는 순간 생긴다. 만든 뒤에 chmod 하면 그 사이에 열려 있는
	 * 틈이 생기므로, 처음부터 600 으로 만들어지게 umask 를 좁혀 둔다. */
	old = umask(0177);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("status bind");
		umask(old);
		close(fd);
		return -1;
	}
	umask(old);

	if (listen(fd, 8) < 0) {
		perror("status listen");
		close(fd);
		unlink(path);
		return -1;
	}

	started_at = mono_now();

	return fd;
}

void status_serve(int epfd, int lfd, int acl_enabled)
{
	struct epoll_event ev;
	writer_t *w = NULL;
	int fd;
	int i;

	fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		return;
	}

	for (i = 0; i < WRITERS; i++) {
		if (writers[i].fd < 0) {
			w = &writers[i];
			break;
		}
	}

	if (w == NULL) {
		fprintf(stderr, "status: too many readers\n");
		close(fd);
		return;
	}

	build(acl_enabled);
	if (overflow) {
		fprintf(stderr, "status: status too large\n");
		close(fd);
		return;
	}

	/* 만든 버퍼를 이 접속에 넘긴다. 다음 접속은 새 버퍼에 만든다. */
	w->fd = fd;
	w->buf = out;
	w->len = outlen;
	w->off = 0;
	w->at = mono_now();
	out = NULL;
	outlen = outcap = 0;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLOUT;
	ev.data.fd = fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		perror("epoll_ctl: status writer");
		close(fd);
		free(w->buf);
		w->fd = -1;
		w->buf = NULL;
		return;
	}

	/* 대개 여기서 한 번에 다 나가고 닫힌다. 상대가 먼저 닫았을 때 SIGPIPE 로 서버가
	 * 죽지 않게 MSG_NOSIGNAL (writer_flush). */
	writer_flush(epfd, w);
}

int status_writable(int epfd, int fd)
{
	int i;

	for (i = 0; i < WRITERS; i++) {
		if (writers[i].fd >= 0 && writers[i].fd == fd) {
			writer_flush(epfd, &writers[i]);
			return 1;
		}
	}

	return 0;
}

void status_tick(int epfd)
{
	time_t now = mono_now();
	int i;

	for (i = 0; i < WRITERS; i++) {
		if (writers[i].fd >= 0 && now - writers[i].at > WRITER_TTL_SEC) {
			fprintf(stderr, "status: reader did not finish in %ds, closing\n", WRITER_TTL_SEC);
			writer_close(epfd, &writers[i]);
		}
	}
}
