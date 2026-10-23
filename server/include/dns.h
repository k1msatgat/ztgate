#ifndef DNS_H
#define DNS_H

/* 기기에 내려 줄 내부 DNS (proto.h 의 net_config).
 *
 *   # dns.conf — 내부 DNS. domain 에 적은 이름(과 그 아래 이름)만 server 로 묻는다
 *   server 10.101.0.53
 *   domain corp.example
 *
 * server 는 NET_MAX_DNS 개, domain 은 NET_MAX_DOMAINS 개까지. domain 이 없으면 server 를
 * 적어도 내려 주지 않는다 — 어느 이름을 물을지 모르는 DNS 는 쓸 곳이 없고, 모든 이름을
 * 회사 DNS 로 보내는 설정은 두지 않는다. 그 DNS 서버에 닿으려면 ACL 이 udp/53 을 열어
 * 주어야 한다 (내려 준 경로 안이어야 클라이언트가 터널로 보낸다).
 *
 * SIGHUP 으로 다시 읽는다. 틀린 파일이면 이전 것을 그대로 쓴다. */

#include "proto.h"

/* 읽은 domain 수를 돌려준다. 형식이 틀리면 -1 이고 이전 것이 남는다. */
int dns_load(const char *path);

/* cfg 의 dns / domains 칸을 채운다. 읽은 것이 없으면 둘 다 0개. */
void dns_fill(net_config_t *cfg);

#endif
