#ifndef NETCFG_H
#define NETCFG_H

/* 서버가 준 터널 설정(주소, prefix, MTU, 경로)을 tun 장치에 맞춘다.
 *
 * `ip addr add` / `ip link set mtu ... up` / `ip route add` 를 프로그램 안에서 하는 것이다.
 * 전에는 사용자가 클라이언트를 띄운 뒤 직접 주소를 붙였다 (test/client.sh). 이제 주소와
 * 경로는 서버의 정책에서 나온다 — 관리자가 한 곳을 고치면 붙어 있는 기기가 따라온다.
 *
 * Windows 클라이언트의 netcfg_apply (windows/core/tunnel.c)와 같은 규칙을 따른다:
 * 지금 넣어 둔 것과 다른 부분만 고치고, /0 과 서버 주소를 덮는 경로는 넣지 않는다. */

#include <net/if.h>
#include <netinet/in.h>

#include "proto.h"

/* 서버가 -n / -m 으로 받는 범위와 같다. */
#define NETCFG_PREFIX_MIN	8
#define NETCFG_PREFIX_MAX	30
#define NETCFG_MTU_MIN		576
#define NETCFG_SERVERS_MAX	4	/* client.c 의 서버 목록과 같다 */

typedef struct netcfg {
	char ifname[IFNAMSIZ];
	/* 이 주소들을 덮는 경로는 넣지 않는다. 서버를 여럿 적었으면 모두 — 지금 붙은 서버만 빼면
	 * 그 서버가 죽고 다른 서버로 넘어갈 때 새 서버로 가는 패킷이 죽은 터널로 들어간다. */
	struct in_addr servers[NETCFG_SERVERS_MAX];
	int n_servers;
	net_config_t applied;
	int has_applied;
} netcfg_t;

/* 서버가 준 설정을 그대로 쓸 수 있는가. 서버는 인증된 상대지만, 받은 값을 커널에 넣기
 * 전에 말이 되는지는 본다. */
int netcfg_usable(const net_config_t *c);

/* want 에 맞춘다. 주소나 MTU 를 넣지 못하면 -1. 경로 하나가 들어가지 않는 것은 터널
 * 전체를 내릴 이유가 아니어서 로그만 남긴다. */
int netcfg_apply(netcfg_t *n, const net_config_t *want);

#endif
