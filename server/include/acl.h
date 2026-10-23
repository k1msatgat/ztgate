#ifndef ACL_H
#define ACL_H

#include <netinet/in.h>

#include "proto.h"
#include "policy.h"

#define MAX_RULES     1024
#define ACL_ANY_PROTO 0

/* 규칙의 action 은 ACL_DENY / ACL_ALLOW 둘뿐이다. ACL_DENY_POSTURE 와 ACL_DENY_USER 는
 * acl_check 의 판정으로만 나온다 — 허용 규칙에 걸렸지만 그 규칙이 요구하는 포스처에
 * 못 미쳤거나, 그 규칙이 정한 사용자 / 그룹이 아니다 (로그인하지 않았거나 만료). */
enum acl_action {
    ACL_DENY  = 0,
    ACL_ALLOW = 1,
    ACL_DENY_POSTURE = 2,
    ACL_DENY_USER = 3
};

struct acl_rule {
    struct in_addr src_addr;
    struct in_addr src_mask;
    struct in_addr dst_addr;
    struct in_addr dst_mask;
    unsigned char  proto;  
    unsigned short dport_lo;
    unsigned short dport_hi;
    int            action;

    /* 이 규칙으로 허용받으려면 채워야 하는 포스처 (allow 규칙에만 붙는다). */
    posture_req_t  require;

    /* 이 규칙으로 허용받을 수 있는 사용자 / 그룹. 비어 있으면 기기만으로 된다. */
    user_req_t     users;

    /* 이 규칙이 어느 기기의 것인가 (tag=). 출발지 주소와 함께 규칙을 고른다. 비어 있으면 모든 기기. */
    tag_set_t      tags;
};

void acl_init(void);
/* 읽은 규칙 수를 돌려준다. 파일을 못 읽거나 형식이 틀리면 -1 이고, 그때는 이전에
 * 읽어 둔 규칙이 그대로 남는다. */
int  acl_load(const char *path);
/* posture 는 이 패킷을 보낸 세션이 마지막으로 보고한 값이고, who 는 그 세션에 로그인한
 * 사용자다 (없으면 NULL). tags 는 그 세션을 연 기기의 태그 (없으면 NULL). */
int  acl_check(const unsigned char *pkt, int len, const posture_report_t *posture,
               const user_identity_t *who, const tag_set_t *tags);
void acl_dump(void);
int  acl_count(void);

/* src 에서 출발하는 패킷을 허용하는 규칙들의 목적지 대역 (터널 대역 안과 any 는 뺀다).
 * 그 기기에 내려 줄 경로 목록이다. 채운 개수를 돌려준다. max 개를 넘어 빠진 규칙의 수는
 * dropped 에 적는다. */
int  acl_routes(struct in_addr src, const tag_set_t *tags, struct in_addr subnet, int subnet_bits,
		net_route_t *out, int max, int *dropped);

#endif /* ACL_H */
