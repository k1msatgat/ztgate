#ifndef FLOW_H
#define FLOW_H

/* 흐름 표 (vpn_server -F). 서버 쪽에서 클라이언트로 가는 패킷은 그 클라이언트가 먼저 연 흐름의
 * 답일 때만 들인다.
 *
 * ACL 은 클라이언트가 보낸 패킷(UDP → tun)에만 걸린다. 반대 방향(tun → 클라이언트)은 지금까지
 * 아무것도 거르지 않아, 서버 뒤의 장비가 먼저 클라이언트 PC 에 연결을 걸 수 있었다 — 회사망의
 * 감염된 장비가 재택 노트북으로 옮겨 가는 길이다. 흐름 표는 ACL 이 허용한 패킷의 5-tuple 을
 * 적어 두고, 들어오는 패킷이 그 반대 방향일 때만 통과시킨다. ICMP 오류(목적지 도달 불가 등)는
 * 그 안에 담긴 원래 패킷의 흐름으로 본다.
 *
 * 연결의 상태(SYN / FIN)는 따지지 않는다. 마지막으로 본 뒤 TCP 는 5분, UDP 는 1분, ICMP 는
 * 30초가 지나면 잊는다. 표가 차면 가장 오래 안 쓴 흐름을 지운다. 클라이언트끼리(터널 대역 안)는
 * 보내는 쪽의 ACL 을 이미 지났으므로 보지 않는다.
 *
 * 워커가 여럿이어도 된다: 버킷을 몇 묶음으로 나눠 묶음마다 잠근다. */

#include <stdint.h>

#define FLOW_MAX	65536

/* 표를 쓴다. 켜지 않으면 flow_* 는 아무것도 하지 않고 flow_inbound_ok 는 늘 1 이다. */
void flow_enable(void);
int flow_enabled(void);

/* 클라이언트가 보낸 IPv4 패킷이 ACL 을 지났다. 그 흐름을 적는다 (이미 있으면 시각만). */
void flow_outbound(const uint8_t *ip, int len);

/* 클라이언트로 가는 IPv4 패킷이 열린 흐름의 답이면 1. */
int flow_inbound_ok(const uint8_t *ip, int len);

/* 지금 표에 있는 흐름 수 (상태 소켓). */
int flow_count(void);

#endif
