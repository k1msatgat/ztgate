#ifndef POLICY_H
#define POLICY_H

/* 포스처 조건. "이 상태여야 한다"를 적는 한 가지 문법을 두 곳에서 쓴다.
 *
 *   기기 목록   그 기기를 터널에 들일 것인가        (device.c)
 *   ACL 규칙    들어온 뒤 그 목적지에 가도 되는가   (acl.c)
 *
 *   firewall=on   antivirus=on   min-build=N
 *
 * 적은 것만 검사한다. 아무것도 적지 않은 조건은 누구나 채운다.
 */

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

/* 설정 파일(기기 목록, 등록 대기 목록, ACL) 한 줄의 길이, 줄바꿈 포함. 키(64자)에 포스처 조건,
 * 태그 넷, 커넥터 대역 넷, 이름표까지 적어도 들어간다. 이보다 긴 줄은 잘라 읽지 않고 거부한다 —
 * 잘린 뒷부분이 다음 줄로 읽히면 엉뚱한 규칙이 된다. */
#define CONF_LINE_MAX	512

/* fgets 로 읽은 줄이 다 들어왔으면 1 (줄바꿈으로 끝났거나 파일의 마지막 줄). */
#define CONF_LINE_WHOLE(line, fp)	(strchr((line), '\n') != NULL || feof(fp))

typedef struct posture_req {
	uint8_t need_firewall;
	uint8_t need_antivirus;
	uint32_t min_build;
} posture_req_t;

/* "firewall=on" 같은 단어 하나를 req 에 더한다. 모르는 단어면 -1. */
int posture_req_parse(const char *tok, posture_req_t *req);

/* 보고된 포스처가 조건을 채우면 1. */
int posture_req_ok(const posture_req_t *req, const posture_report_t *posture);

/* 조건이 하나도 없으면 1. */
int posture_req_empty(const posture_req_t *req);

/* ---- 사용자 -------------------------------------------------------------------
 *
 * 기기 인증은 "이 장비가 등록된 그 장비인가"까지만 말한다. 같은 노트북을 누가 쓰고
 * 있는지는 모른다. 사용자는 IdP 에 로그인해 받은 토큰(JWT)을 세션 안에서 보내고
 * (idp.h), 서버는 그 토큰이 말하는 사용자와 그룹을 세션에 붙여 둔다.
 *
 * ACL 규칙에는 포스처 조건과 같은 자리에 적는다.
 *
 *   user=alice   group=dev
 *
 * 여러 개를 적으면 그중 하나에 해당하면 된다. 로그인하지 않은 세션이나 토큰이 만료된
 * 세션은 어느 것에도 해당하지 않는다.
 *
 * 이름에 쓸 수 있는 글자를 정해 둔다: 영문, 숫자, . _ @ + - /. 이름은 감사 로그와 상태
 * 소켓의 JSON 에 그대로 들어가는데, 따옴표나 역슬래시가 없으면 이스케이프할 일이 없다.
 * IdP 가 이 밖의 글자를 쓰는 이름을 주면 그 토큰은 받지 않는다. */

#define USER_NAME_MAX	(LOGIN_USER_MAX + 1)	/* NUL 포함 */
#define USER_GROUPS_MAX	16
#define USER_REQ_MAX	4

typedef struct user_identity {
	char name[USER_NAME_MAX];
	char groups[USER_GROUPS_MAX][USER_NAME_MAX];
	uint8_t n_groups;
	int64_t expires;	/* 토큰의 exp. 벽시계 초 (Unix time) */
} user_identity_t;

typedef struct user_req {
	uint8_t n;
	uint8_t is_group[USER_REQ_MAX];
	char who[USER_REQ_MAX][USER_NAME_MAX];
} user_req_t;

/* 쓸 수 있는 글자로만 된 1..63 자면 1. */
int user_name_valid(const char *name);

/* "user=alice" / "group=dev" 를 req 에 더한다. 0: 더했다, 1: 사용자 조건이 아니다
 * (다른 파서에 넘긴다), -1: 사용자 조건인데 이름이 틀렸거나 자리가 없다. */
int user_req_parse(const char *tok, user_req_t *req);

/* who 가 조건을 채우면 1. 조건이 없으면 누구든(로그인하지 않았어도) 채운다. who 가
 * NULL 이거나 now 에 만료됐으면 조건이 있는 한 채우지 못한다. */
int user_req_ok(const user_req_t *req, const user_identity_t *who, int64_t now);

int user_req_empty(const user_req_t *req);

/* ---- 기기 태그 -------------------------------------------------------------------
 *
 * 기기를 역할로 묶는다. 기기 목록(과 등록 코드)에 붙이고, ACL 규칙에서 그 규칙이 어느 기기의
 * 것인지를 고른다.
 *
 *   devices.conf   2bd5...  a24d...  10.0.0.3  tag=eng tag=laptop
 *   acl.conf       any  10.20.0.0/16  tcp  443  allow  tag=eng
 *
 * 규칙의 태그는 출발지 주소와 같은 자리다 — 그 기기에 태그가 하나도 맞지 않으면 그 규칙은 그
 * 기기의 것이 아니고 다음 규칙을 본다. 터널 주소를 하나씩 적지 않고 "엔지니어 노트북"처럼
 * 적게 된다. 사용자(user= / group=)는 그 기기를 지금 누가 쓰는가이고, 태그는 기기가 무엇인가다.
 *
 * 이름은 영문 소문자, 숫자, _ - 의 1..32 자. 기기 하나, 규칙 하나에 TAG_MAX 개까지. */
#define TAG_MAX		4
#define TAG_NAME_MAX	32

typedef struct tag_set {
	uint8_t n;
	char name[TAG_MAX][TAG_NAME_MAX + 1];
} tag_set_t;

/* "tag=eng" 를 더한다. 0: 더했다, 1: 태그가 아니다 (다른 파서에 넘긴다), -1: 태그인데 이름이
 * 틀렸거나 자리가 없다. 같은 이름을 두 번 적으면 한 번으로 친다. */
int tag_parse(const char *tok, tag_set_t *t);

/* 규칙의 태그(want)를 기기의 태그(have)가 채우면 1. want 가 비었으면 누구나. have 가 NULL 이면
 * 태그가 없는 기기다. */
int tag_match(const tag_set_t *want, const tag_set_t *have);

#endif
