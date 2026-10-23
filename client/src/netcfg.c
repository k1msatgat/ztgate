#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "netcfg.h"

/* 주소, MTU, 경로는 ioctl 로 넣는다 (ifconfig / route 가 쓰던 방식).
 *
 * 요즘 도구(ip)는 rtnetlink 를 쓰고 그쪽이 IPv6, 여러 주소, 경로 속성까지 다룬다. 여기서
 * 넣는 것은 IPv4 주소 하나와 게이트웨이 없는 경로 몇 개라 ioctl 로 충분하고, 메시지를
 * 직접 짜는 netlink 보다 읽기 쉽다. IPv6 를 터널에 싣게 되면 netlink 로 바꿔야 한다. */

static uint32_t prefix_mask(uint8_t prefix_len)
{
	return prefix_len == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix_len));
}

static void sin_set(struct sockaddr *sa, uint32_t addr)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	memcpy(sa, &sin, sizeof(sin));
}

static const char *ip4(uint32_t addr, char *dst)
{
	struct in_addr a = { .s_addr = addr };

	return inet_ntop(AF_INET, &a, dst, INET_ADDRSTRLEN);
}

int netcfg_usable(const net_config_t *c)
{
	return c->tun_ip != 0 && c->prefix_len >= NETCFG_PREFIX_MIN &&
		c->prefix_len <= NETCFG_PREFIX_MAX &&
		c->mtu >= NETCFG_MTU_MIN && c->mtu <= BUF_SIZE - PKT_OVERHEAD;
}

/* 이 대역을 터널로 돌려도 되는가.
 *
 *   /0                모든 트래픽을 터널로 보내라는 뜻이다. 서버가 그런 값을 줄 일은
 *                     없지만(acl.c 의 acl_routes), 준다고 따르지는 않는다.
 *   서버 주소를 덮는 대역  서버로 가는 UDP 가 터널로 들어간다. 터널 패킷을 싣고 가야
 *                     할 길이 터널 자신이 되어, 넣는 순간 연결이 끊긴다. */
static int route_usable(const netcfg_t *n, const net_route_t *r)
{
	if (r->prefix_len == 0) {
		return 0;
	}

	return (n->server.s_addr & prefix_mask(r->prefix_len)) != r->addr;
}

static int route_in(const net_config_t *c, const net_route_t *r)
{
	int i;

	for (i = 0; i < c->n_routes; i++) {
		if (c->routes[i].addr == r->addr && c->routes[i].prefix_len == r->prefix_len) {
			return 1;
		}
	}

	return 0;
}

/* 게이트웨이 없이 장치만 정한 경로다. 터널은 점대점이라 다음 홉이 따로 없고, tun 에
 * 넣으면 서버가 받는다. */
static void route_ctl(int sock, netcfg_t *n, const net_route_t *r, unsigned long req)
{
	char ib[INET_ADDRSTRLEN];
	struct rtentry rt;
	int add = req == SIOCADDRT;

	if (!route_usable(n, r)) {
		if (add) {
			printf("[cfg] route %s/%u ignored (%s)\n", ip4(r->addr, ib), r->prefix_len,
					r->prefix_len == 0 ? "default route" : "it covers the server address");
		}
		return;
	}

	memset(&rt, 0, sizeof(rt));
	sin_set(&rt.rt_dst, r->addr);
	sin_set(&rt.rt_genmask, prefix_mask(r->prefix_len));
	rt.rt_flags = RTF_UP;
	rt.rt_dev = n->ifname;

	if (ioctl(sock, req, &rt) < 0 && !(add && errno == EEXIST)) {
		fprintf(stderr, "[cfg] route %c %s/%u failed: %s\n", add ? '+' : '-',
				ip4(r->addr, ib), r->prefix_len, strerror(errno));
		return;
	}

	printf("[cfg] route %c %s/%u\n", add ? '+' : '-', ip4(r->addr, ib), r->prefix_len);
}

/* ---- 내부 DNS ------------------------------------------------------------------
 *
 * systemd-resolved 의 인터페이스별 설정으로 건다. domain 앞의 ~ 는 "이 이름은 이 인터페이스의
 * DNS 로 묻되, 짧은 이름 뒤에 붙여 보지는 않는다"는 뜻이다 — 분할 DNS (proto.h). tun 장치가
 * 없어지면 resolved 가 그 설정을 스스로 버리므로 끝날 때 따로 지우지 않는다.
 *
 * resolved 를 쓰지 않는 장비(/etc/resolv.conf 를 직접 쓰는 곳)에서는 걸지 않는다. 모든 이름을
 * 회사 DNS 로 보내는 것(resolv.conf 를 바꾸는 것)은 분할 DNS 가 아니다. */
static const char *const RESOLVECTL[] = { "/usr/bin/resolvectl", "/bin/resolvectl" };

static int run_resolvectl(char *const argv[])
{
	const char *path = NULL;
	int status;
	pid_t pid;
	size_t i;

	for (i = 0; i < sizeof(RESOLVECTL) / sizeof(RESOLVECTL[0]); i++) {
		if (access(RESOLVECTL[i], X_OK) == 0) {
			path = RESOLVECTL[i];
			break;
		}
	}
	if (path == NULL) {
		fprintf(stderr, "[cfg] dns: resolvectl not found (systemd-resolved), internal names will not resolve\n");
		return -1;
	}

	/* 셸을 거치지 않는다. 이름은 net_domain_ok 를 지난 글자뿐이지만, 인자로 넘기면 그런
	 * 검사에 기대지 않아도 된다. */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		execv(path, argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[cfg] dns: %s %s failed\n", argv[0], argv[1]);
		return -1;
	}

	return 0;
}

static void dns_apply(netcfg_t *n, const net_config_t *want)
{
	char ips[NET_MAX_DNS][INET_ADDRSTRLEN];
	char doms[NET_MAX_DOMAINS][NET_DOMAIN_MAX + 2];
	char *argv[3 + NET_MAX_DOMAINS + 1];
	int i, k;

	if (want->n_domains == 0) {
		argv[0] = "resolvectl";
		argv[1] = "revert";
		argv[2] = n->ifname;
		argv[3] = NULL;
		if (run_resolvectl(argv) == 0) {
			printf("[cfg] dns: none\n");
		}
		return;
	}

	k = 0;
	argv[k++] = "resolvectl";
	argv[k++] = "dns";
	argv[k++] = n->ifname;
	for (i = 0; i < want->n_dns; i++) {
		argv[k++] = (char *)ip4(want->dns[i], ips[i]);
	}
	argv[k] = NULL;
	if (run_resolvectl(argv) < 0) {
		return;
	}

	k = 0;
	argv[k++] = "resolvectl";
	argv[k++] = "domain";
	argv[k++] = n->ifname;
	for (i = 0; i < want->n_domains; i++) {
		snprintf(doms[i], sizeof(doms[i]), "~%s", want->domains[i]);
		argv[k++] = doms[i];
	}
	argv[k] = NULL;
	if (run_resolvectl(argv) < 0) {
		return;
	}

	for (i = 0; i < want->n_domains; i++) {
		printf("[cfg] dns: %s -> %s%s%s\n", want->domains[i], ips[0],
				want->n_dns > 1 ? ", " : "", want->n_dns > 1 ? ips[1] : "");
	}
}

static int ifr_ioctl(int sock, const netcfg_t *n, unsigned long req, struct ifreq *ifr, const char *what)
{
	memcpy(ifr->ifr_name, n->ifname, IFNAMSIZ);
	if (ioctl(sock, req, ifr) < 0) {
		fprintf(stderr, "[cfg] %s on %s failed: %s\n", what, n->ifname, strerror(errno));
		return -1;
	}

	return 0;
}

/* 처음 한 번만 부르는 것이 아니다. 다시 핸드셰이크했을 때와 keepalive 응답으로 새 설정이
 * 왔을 때에도 부른다. 통째로 지우고 다시 넣으면 바뀌지 않은 경로까지 잠깐 사라져 그 사이의
 * 연결이 끊기므로, 지금 넣어 둔 것(applied)과 다른 부분만 고친다. */
int netcfg_apply(netcfg_t *n, const net_config_t *want)
{
	net_config_t *cur = &n->applied;
	char ib[INET_ADDRSTRLEN];
	struct ifreq ifr;
	int sock;
	int i;
	int ret = -1;

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	/* 주소를 바꾸면 커널이 예전 주소의 대역 경로를 지우고 새 대역 경로를 넣는다. */
	if (!n->has_applied || cur->tun_ip != want->tun_ip || cur->prefix_len != want->prefix_len) {
		memset(&ifr, 0, sizeof(ifr));
		sin_set(&ifr.ifr_addr, want->tun_ip);
		if (ifr_ioctl(sock, n, SIOCSIFADDR, &ifr, "SIOCSIFADDR") < 0) {
			goto out;
		}
		memset(&ifr, 0, sizeof(ifr));
		sin_set(&ifr.ifr_netmask, prefix_mask(want->prefix_len));
		if (ifr_ioctl(sock, n, SIOCSIFNETMASK, &ifr, "SIOCSIFNETMASK") < 0) {
			goto out;
		}
		printf("[cfg] address %s/%u\n", ip4(want->tun_ip, ib), want->prefix_len);
	}

	if (!n->has_applied || cur->mtu != want->mtu) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_mtu = want->mtu;
		if (ifr_ioctl(sock, n, SIOCSIFMTU, &ifr, "SIOCSIFMTU") < 0) {
			goto out;
		}
		printf("[cfg] mtu %u\n", want->mtu);
	}

	/* 장치가 내려가 있으면 경로를 넣을 수 없다. */
	if (!n->has_applied) {
		memset(&ifr, 0, sizeof(ifr));
		if (ifr_ioctl(sock, n, SIOCGIFFLAGS, &ifr, "SIOCGIFFLAGS") < 0) {
			goto out;
		}
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ifr_ioctl(sock, n, SIOCSIFFLAGS, &ifr, "SIOCSIFFLAGS") < 0) {
			goto out;
		}
	}

	if (n->has_applied) {
		for (i = 0; i < cur->n_routes; i++) {
			if (!route_in(want, &cur->routes[i])) {
				route_ctl(sock, n, &cur->routes[i], SIOCDELRT);
			}
		}
	}
	for (i = 0; i < want->n_routes; i++) {
		if (!n->has_applied || !route_in(cur, &want->routes[i])) {
			route_ctl(sock, n, &want->routes[i], SIOCADDRT);
		}
	}

	if (!n->has_applied ? want->n_domains > 0 : !net_dns_equal(cur, want)) {
		dns_apply(n, want);
	}

	*cur = *want;
	n->has_applied = 1;
	ret = 0;

out:
	close(sock);

	return ret;
}
