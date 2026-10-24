#define _GNU_SOURCE	/* accept4 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "common.h"
#include "proto.h"
#include "tcp.h"

#define FRAME_HDR	2
#define FD_MAP		65536	/* 이보다 큰 fd 의 연결은 받지 않는다 */

typedef struct conn {
	pthread_mutex_t lock;	/* fd, gen, wbuf 를 지킨다 (쓰기는 어느 워커든 한다) */
	int fd;			/* -1 이면 빈 자리 */
	uint32_t gen;		/* 자리를 다시 쓸 때마다 는다. 닫힌 연결로 보내던 것이 새 연결로 가지 않게 */
	struct sockaddr_in peer;
	uint8_t rbuf[FRAME_HDR + BUF_SIZE];
	size_t rlen;
	uint8_t *wbuf;		/* 못 보낸 것. 쌓일 때만 잡는다 */
	size_t wlen;
	time_t seen;		/* 마지막으로 받은 때 (CLOCK_MONOTONIC) */
} conn_t;

static conn_t conns[TCP_CONN_MAX];
static int16_t fd_conn[FD_MAP];
static int ready;
static int ep = -1;	/* 연결을 건 epoll (워커 0). 쓰기가 막히면 다른 워커가 EPOLLOUT 을 건다 */
static int nconn;

static void init(void)
{
	int i;

	if (ready) {
		return;
	}
	for (i = 0; i < TCP_CONN_MAX; i++) {
		pthread_mutex_init(&conns[i].lock, NULL);
		conns[i].fd = -1;
	}
	for (i = 0; i < FD_MAP; i++) {
		fd_conn[i] = -1;
	}
	ready = 1;
}

int tcp_listen(uint16_t port)
{
	struct sockaddr_in a;
	int one = 1;
	int fd;

	init();
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("tcp socket");
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 128) < 0) {
		perror("tcp bind / listen");
		close(fd);
		return -1;
	}
	return fd;
}

/* 이 연결을 가리키는 "주소". tcp.h 의 표시 방식. */
static void pseudo(int idx, struct sockaddr_in *out)
{
	*out = conns[idx].peer;
	out->sin_family = AF_UNSPEC;
	out->sin_port = htons((uint16_t)idx);
	memset(out->sin_zero, 0, sizeof(out->sin_zero));
	memcpy(out->sin_zero, &conns[idx].gen, sizeof(conns[idx].gen));
}

/* 워커 0 에서만 부른다 (받기, 쉬는 연결 정리). */
static void conn_close(int epfd, int idx)
{
	conn_t *c = &conns[idx];

	pthread_mutex_lock(&c->lock);
	if (c->fd >= 0) {
		epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
		fd_conn[c->fd] = -1;
		close(c->fd);
		c->fd = -1;
		c->gen++;
		free(c->wbuf);
		c->wbuf = NULL;
		c->wlen = 0;
		c->rlen = 0;
		nconn--;
	}
	pthread_mutex_unlock(&c->lock);
}

void tcp_accept(int epfd, int lfd)
{
	struct sockaddr_in from;
	socklen_t len;
	struct epoll_event ev;
	int one = 1;
	int fd, i;

	ep = epfd;
	for (;;) {
		len = sizeof(from);
		fd = accept4(lfd, (struct sockaddr *)&from, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			return;
		}
		for (i = 0; i < TCP_CONN_MAX && conns[i].fd >= 0; i++) {
		}
		if (i == TCP_CONN_MAX || fd >= FD_MAP) {
			close(fd);
			continue;
		}
		/* 작은 패킷(keepalive, 핸드셰이크)을 모아 두지 않는다. */
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

		pthread_mutex_lock(&conns[i].lock);
		conns[i].fd = fd;
		conns[i].peer = from;
		conns[i].rlen = 0;
		conns[i].seen = mono_now();
		pthread_mutex_unlock(&conns[i].lock);
		fd_conn[fd] = (int16_t)i;
		nconn++;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = fd;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
			conn_close(epfd, i);
		}
	}
}

/* 못 보낸 것을 보낸다. 잠근 채로 부른다. 다 보내면 EPOLLOUT 을 내린다. */
static void flush_locked(conn_t *c)
{
	struct epoll_event ev;
	ssize_t n;

	while (c->wlen > 0) {
		n = send(c->fd, c->wbuf, c->wlen, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n <= 0) {
			return;
		}
		memmove(c->wbuf, c->wbuf + n, c->wlen - (size_t)n);
		c->wlen -= (size_t)n;
	}
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = c->fd;
	epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev);
}

int tcp_event(int epfd, int fd, uint32_t events, tcp_packet_fn on_packet)
{
	uint8_t packet[BUF_SIZE];
	struct sockaddr_in from;
	conn_t *c;
	ssize_t n;
	size_t len;
	int idx;

	if (!ready || fd < 0 || fd >= FD_MAP || fd_conn[fd] < 0) {
		return 0;
	}
	idx = fd_conn[fd];
	c = &conns[idx];

	if (events & EPOLLOUT) {
		pthread_mutex_lock(&c->lock);
		flush_locked(c);
		pthread_mutex_unlock(&c->lock);
	}
	if (!(events & (EPOLLIN | EPOLLHUP | EPOLLERR))) {
		return 1;
	}

	for (;;) {
		n = read(fd, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen);
		if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
			conn_close(epfd, idx);
			return 1;
		}
		if (n < 0) {
			return 1;
		}
		c->rlen += (size_t)n;
		c->seen = mono_now();

		/* 다 들어온 틀마다 하나씩 넘긴다. 남은 조각은 다음 읽기에 이어 붙인다. */
		while (c->rlen >= FRAME_HDR) {
			len = (size_t)(c->rbuf[0] << 8 | c->rbuf[1]);
			if (len == 0 || len > BUF_SIZE) {
				conn_close(epfd, idx);	/* 틀이 깨졌다. 다시 맞출 방법이 없다 */
				return 1;
			}
			if (c->rlen < FRAME_HDR + len) {
				break;
			}
			memcpy(packet, c->rbuf + FRAME_HDR, len);
			memmove(c->rbuf, c->rbuf + FRAME_HDR + len, c->rlen - FRAME_HDR - len);
			c->rlen -= FRAME_HDR + len;

			pseudo(idx, &from);
			on_packet(packet, sizeof(packet), (int)len, &from, sizeof(from));
			if (c->fd < 0) {
				return 1;	/* 처리하다 닫혔다 */
			}
		}
	}
}

void tcp_tick(int epfd)
{
	time_t now = mono_now();
	int i;

	if (!ready) {
		return;
	}
	for (i = 0; i < TCP_CONN_MAX; i++) {
		if (conns[i].fd >= 0 && now - conns[i].seen > TCP_IDLE_SEC) {
			conn_close(epfd, i);
		}
	}
}

int net_udp_init(int sock)
{
	int one = 1;

	return setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
}

ssize_t net_recv(int sock, void *buf, size_t cap, struct sockaddr_in *src, socklen_t *srclen)
{
	union {
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct cmsghdr align;
	} ctl;
	struct iovec iov = { buf, cap };
	struct msghdr msg;
	struct cmsghdr *cm;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = src;
	msg.msg_namelen = *srclen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);

	n = recvmsg(sock, &msg, 0);
	if (n < 0) {
		return n;
	}
	*srclen = msg.msg_namelen;
	memset(src->sin_zero, 0, sizeof(src->sin_zero));
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo pi;

			memcpy(&pi, CMSG_DATA(cm), sizeof(pi));
			memcpy(src->sin_zero, &pi.ipi_addr, sizeof(pi.ipi_addr));
		}
	}
	return n;
}

/* 도착 주소가 적힌 UDP 주소면 그 주소에서 보낸다. */
static int udp_send(int sock, const void *buf, size_t len, const struct sockaddr_in *to)
{
	union {
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct cmsghdr align;
	} ctl;
	struct sockaddr_in dst = *to;
	struct iovec iov = { (void *)buf, len };
	struct in_pktinfo pi;
	struct msghdr msg;
	struct cmsghdr *cm;

	memset(dst.sin_zero, 0, sizeof(dst.sin_zero));
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(&pi, 0, sizeof(pi));
	memcpy(&pi.ipi_spec_dst, to->sin_zero, sizeof(pi.ipi_spec_dst));
	if (pi.ipi_spec_dst.s_addr != 0) {
		memset(&ctl, 0, sizeof(ctl));
		msg.msg_control = ctl.buf;
		msg.msg_controllen = sizeof(ctl.buf);
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(pi));
		memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
	}
	return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

int net_send(int sock, const void *buf, size_t len, const struct sockaddr_in *to, socklen_t tolen)
{
	uint8_t hdr[FRAME_HDR];
	struct iovec iov[2];
	struct msghdr msg;
	struct epoll_event ev;
	uint32_t gen;
	conn_t *c;
	ssize_t n;
	size_t done, need;
	int idx;

	if (to->sin_family != AF_UNSPEC) {
		(void)tolen;
		return udp_send(sock, buf, len, to);
	}

	idx = ntohs(to->sin_port);
	memcpy(&gen, to->sin_zero, sizeof(gen));
	if (!ready || idx >= TCP_CONN_MAX || len == 0 || len > BUF_SIZE) {
		return -1;
	}
	c = &conns[idx];
	hdr[0] = (uint8_t)(len >> 8);
	hdr[1] = (uint8_t)len;

	pthread_mutex_lock(&c->lock);
	if (c->fd < 0 || c->gen != gen) {
		pthread_mutex_unlock(&c->lock);
		return -1;	/* 그 연결은 닫혔다. 클라이언트가 다시 붙으면 새 연결로 간다 */
	}

	done = 0;
	if (c->wlen == 0) {
		memset(&msg, 0, sizeof(msg));
		iov[0].iov_base = hdr;
		iov[0].iov_len = FRAME_HDR;
		iov[1].iov_base = (void *)buf;
		iov[1].iov_len = len;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		n = sendmsg(c->fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
		done = n > 0 ? (size_t)n : 0;
	}

	if (done < FRAME_HDR + len) {
		need = FRAME_HDR + len - done;
		if (c->wbuf == NULL) {
			c->wbuf = malloc(TCP_WBUF);
		}
		/* 틀의 일부만 나간 것은 끝까지 보내야 한다 (뒤의 틀이 어긋난다). 아직 하나도 안 나갔는데
		 * 자리가 없으면 이 패킷은 버린다. */
		if (c->wbuf == NULL || (done == 0 && c->wlen + need > TCP_WBUF)) {
			pthread_mutex_unlock(&c->lock);
			return -1;
		}
		if (c->wlen + need > TCP_WBUF) {
			pthread_mutex_unlock(&c->lock);
			return -1;	/* 부분만 나간 틀을 담을 자리도 없다 — 읽기 쪽이 틀이 깨진 것을 보고 닫는다 */
		}
		if (done < FRAME_HDR) {
			memcpy(c->wbuf + c->wlen, hdr + done, FRAME_HDR - done);
			c->wlen += FRAME_HDR - done;
			memcpy(c->wbuf + c->wlen, buf, len);
			c->wlen += len;
		}
		else {
			memcpy(c->wbuf + c->wlen, (const uint8_t *)buf + (done - FRAME_HDR), need);
			c->wlen += need;
		}
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLOUT;
		ev.data.fd = c->fd;
		epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev);
	}
	pthread_mutex_unlock(&c->lock);
	return 0;
}

const char *endpoint_str(const struct sockaddr_in *ep_addr, char *dst, size_t cap)
{
	char ib[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ep_addr->sin_addr, ib, sizeof(ib));
	if (ep_addr->sin_family == AF_UNSPEC) {
		snprintf(dst, cap, "%s (tcp)", ib);
	}
	else {
		snprintf(dst, cap, "%s:%d", ib, ntohs(ep_addr->sin_port));
	}
	return dst;
}

int tcp_conn_count(void)
{
	return nconn;
}
