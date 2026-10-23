#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "proto.h"
#include "secure.h"
#include "policy.h"

#define MAX_PEERS 4096
#define IDX_SLOT_BIT 16
#define IDX_SLOT_MASK ((1u << IDX_SLOT_BIT) -1)

_Static_assert(MAX_PEERS <= (1 << IDX_SLOT_BIT), "MAX_PEERS exceeds slot bits");

/* 감사 로그가 "이 세션이 이 목적지에 닿았다"를 목적지마다 한 번씩만 적으려고 기억하는
 * 자리 (audit.c). */
#define AUDIT_FLOWS 8

typedef struct audit_flow {
    uint32_t dst;
    uint16_t dport;
    uint8_t proto;
    uint8_t allowed;
    uint8_t used;
    time_t at;		/* 마지막으로 적은 때, CLOCK_MONOTONIC 초 */
} audit_flow_t;

typedef struct peer {
    int32_t used;
    uint32_t session_idx;
    secure_session_t secure;	/* 세션 키, 보낼 counter, 받은 counter 의 창 */
    struct in_addr inner;
    struct sockaddr_in outer;
    socklen_t outer_len;
    time_t last_seen;	/* CLOCK_MONOTONIC 초 */

    time_t established_at;	/* CLOCK_MONOTONIC 초 */

    /* 터널로 오간 데이터 패킷. rx 는 클라이언트 -> 서버(ACL 을 통과한 것만), tx 는 반대. */
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t acl_denied;

    /* 이 세션을 연 기기. 포인터가 아니라 ID 로 들고 있다가 쓸 때마다 목록에서 찾는다.
     * 목록에서 지워진 기기는 다음 keepalive 에서 찾지 못해 세션이 끊긴다. */
    uint8_t device_id[DEVICE_ID_LEN];

    /* 이 기기가 마지막으로 서명해서 보고한 포스처. 핸드셰이크와 keepalive 마다 바뀐다.
     * ACL 이 포스처 조건이 걸린 규칙을 볼 때 쓴다. */
    posture_report_t posture;

    /* 마지막으로 받아들인 keepalive 의 counter. 예전 포스처 보고의 재전송을 걸러낸다. */
    uint64_t ka_counter;
    int32_t ka_seen;

    /* 등록 코드로 연 세션. 기기의 ID 와 키를 받는 것 말고는 아무것도 하지 않는다 —
     * 터널 패킷은 받지도 보내지도 않는다. device_id 에는 코드에서 뽑은 임시 ID 가 있다. */
    int32_t enroll;
    int32_t enrolled;			/* 이 세션으로 등록이 끝났다 */
    uint8_t enrolled_id[DEVICE_ID_LEN];	/* 그때 올린 기기. 같은 요청이 다시 오면 같은 답을 한다 */

    /* 이 세션에 로그인한 사용자 (LOGIN). logged_in 이 0 이면 아무도 로그인하지 않았다.
     * user.expires 가 지나면 ACL 은 이 사용자를 없는 것으로 본다 (policy.c). */
    int32_t logged_in;
    user_identity_t user;

    audit_flow_t flows[AUDIT_FLOWS];
    int32_t flow_next;
} peer_t;

void peer_check_expired(void);
void peer_touch(peer_t *peer, const struct sockaddr_in *outer, socklen_t len);
void peer_init(void);
/* 인증을 마친 기기 id 의 세션을 터널 주소 inner 에 연다. */
peer_t *peer_register(struct in_addr inner, const uint8_t id[DEVICE_ID_LEN],
                        const struct sockaddr_in *outer, socklen_t len);
peer_t *peer_find_idx(uint32_t idx);
/* reason 은 감사 로그에 남는 단어다 (audit.h). */
void peer_drop(peer_t *peer, const char *reason);
peer_t *peer_lookup(struct in_addr inner);
peer_t *peer_find_device(const uint8_t id[DEVICE_ID_LEN]);
void peer_dump(void);

/* slot i 의 세션. 비어 있으면 NULL. 상태를 내보낼 때 표를 훑는 데 쓴다. */
const peer_t *peer_at(int i);

#endif
