#ifndef DEVICE_H
#define DEVICE_H

/* 등록된 기기 목록.
 *
 * 지금까지 서버는 터널 IP 를 자칭한 누구에게나 세션을 줬다. 이제 관리자가 미리
 * 등록해 둔 기기만 받는다. 기기마다 ID(이름표), 키(그 기기와 서버만 아는 비밀),
 * 배정된 터널 IP 를 가진다. 값은 기기에서 `vpn_client enroll` (또는 GUI 의
 * [기기 등록...])로 만들고 관리자가 이 파일에 옮겨 적는다.
 *
 *   # id(32 hex)                      key(64 hex)   tunnel-ip   [요구하는 포스처 ...]
 *   2bd5d6e0610d2b7c07f884d0c5afb043  a24d4c3d...   10.0.0.3    firewall=on antivirus=on min-build=22000
 *
 * 포스처 조건은 생략할 수 있고, 적은 것만 검사한다. 기기마다 따로 둘 수 있다 —
 * "누구인가"에 따라 요구 수준이 달라지는 것이 신원 기반 정책이다.
 */

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "proto.h"
#include "policy.h"

#define MAX_DEVICES 4096
#define CONNECTOR_MAX_NETS 4

/* 서버가 준 nonce 에 클라이언트가 답해야 하는 시간. 같은 PC 에서 서명 한 번이면
 * 되는 일이라 길 이유가 없고, 짧을수록 엿들은 값을 써먹을 틈이 줄어든다. */
#define NONCE_TTL_SEC 5

typedef struct device {
	uint8_t id[DEVICE_ID_LEN];
	uint8_t key[AUTH_KEY_LEN];
	struct in_addr tun_ip;

	/* 이 기기에 요구하는 포스처. 못 미치면 터널에 들이지 않는다. */
	posture_req_t require;

	/* 커넥터라면 그것이 맡은 내부망 (connector=10.101.0.0/16). 비어 있으면 일반 기기다.
	 * server.c 의 "커넥터" 주석. */
	net_route_t connector[CONNECTOR_MAX_NETS];
	uint8_t n_connector;

	/* 진행 중인 핸드셰이크. CHALLENGE 로 내준 nonce 를 서명이 맞는 AUTH 가 오거나
	 * 수명이 다할 때까지 기억한다. 그동안 다시 온 REQ 에는 같은 nonce 를 내준다.
	 * 출발지 주소가 아니라 기기에 매달아 둔다 — NAT 뒤에서는 REQ 와 AUTH 사이에
	 * 출발지 포트가 바뀔 수 있다. */
	uint8_t nonce[AUTH_NONCE_LEN];
	time_t nonce_at;	/* CLOCK_MONOTONIC 초 */
	int nonce_valid;
} device_t;

void device_init(void);

/* 읽은 기기 수를 돌려준다. 파일을 못 읽거나 형식이 틀리면 -1 이고, 그때는 이전에
 * 읽어 둔 목록이 그대로 남는다. 진행 중이던 핸드셰이크의 nonce 는 사라진다. */
int device_load(const char *path);

device_t *device_find(const uint8_t id[DEVICE_ID_LEN]);
device_t *device_find_ip(struct in_addr tun_ip);

/* 보고된 포스처가 이 기기의 정책을 채우면 1. */
int device_posture_ok(const device_t *dev, const posture_report_t *posture);

/* 기기 줄의 터널 IP 뒤에 오는 단어 하나 — 포스처 조건 또는 connector=<대역>. 등록 대기
 * 목록(enroll.c)도 같은 단어를 받는다. 모르는 단어거나 대역이 틀리면 -1. */
int device_token_parse(const char *tok, device_t *d);

/* dst 를 맡은 커넥터 기기. 없으면 NULL. 대역이 겹치면 더 좁은 쪽이 맡는다. */
const device_t *device_connector_for(struct in_addr dst);

/* dst 가 이 커넥터가 맡은 대역 안이면 1. */
int device_connector_has(const device_t *dev, struct in_addr dst);

/* 로그에 쓸 ID 문자열. dst 는 DEVICE_ID_STRLEN 이상이어야 한다. */
#define DEVICE_ID_STRLEN (DEVICE_ID_LEN * 2 + 1)
const char *device_id_str(const uint8_t id[DEVICE_ID_LEN], char *dst);

void device_dump(void);

int device_count(void);

#endif
