#ifndef WFP_H
#define WFP_H

/* 터널이 끊긴 동안 내부망으로 나가는 연결을 막는다 (정책의 BlockWhenDown, policy.h).
 *
 * 터널이 내려가면 서버가 내려 준 경로도 사라져, 내부 주소(10.x 등)로 가는 패킷이 지금 붙어 있는
 * 망(호텔, 카페)으로 그대로 나간다. 그 망의 누군가가 그 주소를 흉내 내면 사용자는 사내 서버라고
 * 믿고 자격 증명을 넘길 수 있다. Windows 필터링 플랫폼(WFP)에 "이 대역으로의 연결 거부" 필터를
 * 걸어 막는다. 서버로 가는 연결은 늘 허용한다.
 *
 * 필터는 동적 세션에 건다 — 서비스가 죽으면 Windows 가 거둬 간다. 막다가 서비스가 죽어 PC 가 영영
 * 내부망에 닿지 못하는 일은 없지만, 서비스가 죽어 있는 동안은 막지 않는다.
 *
 * 서비스(SYSTEM)만 부른다. */

#include <winsock2.h>
#include <windows.h>

#include "proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* nets 로의 연결을 막는다 (allow 의 주소들은 그 안이어도 허용). 이전에 건 것은 바꾼다. 0 성공. */
int wfp_block(const net_route_t *nets, int n, const struct in_addr *allow, int n_allow);

/* 건 것을 모두 푼다. */
void wfp_clear(void);

#ifdef __cplusplus
}
#endif

#endif
