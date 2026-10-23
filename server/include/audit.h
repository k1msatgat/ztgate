#ifndef AUDIT_H
#define AUDIT_H

/* 감사 로그. 누가 언제 들어와 어디에 닿았고 왜 거절됐는지를 한 줄에 한 사건씩 JSON 으로
 * 남긴다.
 *
 * 서버가 stdout 에 찍는 로그는 사람이 따라 읽으라고 쓴 것이다. 패킷마다 한 줄이라
 * 양이 많고, 문장이라 프로그램이 읽으려면 정규식으로 뜯어야 하며, 기기 ID 와 세션과
 * 목적지가 서로 다른 줄에 흩어져 있다. "어제 이 기기가 어디에 접근했는가"에 답하려면
 * 처음부터 따라가며 다시 맞춰야 한다. 상태 소켓은 지금의 상태만 보여 주고 지나간 일은
 * 모른다.
 *
 * 여기에는 패킷이 아니라 사건을 적는다.
 *
 *   session_open    기기가 인증을 통과해 세션이 열렸다
 *   session_close   세션이 닫혔다 (이유, 그동안 오간 양)
 *   auth_denied     핸드셰이크가 거절됐다 (이유)
 *   access          세션이 어떤 목적지에 닿았다 / 막혔다 (목적지마다 한 번씩)
 *   reload          기기 목록이나 ACL 을 다시 읽었다
 *   enrolled        등록 코드로 기기가 목록에 올랐다
 *   login           세션에 사용자가 로그인했다 / 토큰이 거절됐다
 *   logout          로그인했던 사용자의 토큰이 만료돼 세션에서 떨어졌다
 *
 * 값은 전부 주소, 숫자, 16진수, 우리가 정한 단어라 따옴표를 이스케이프할 일이 없다.
 * 바깥에서 온 문자열은 적지 않는다. 사용자와 그룹 이름은 IdP 가 서명한 토큰에서 오지만,
 * 쓸 수 있는 글자를 정해 두고(policy.h) 그 밖의 글자가 있으면 토큰을 받지 않는다.
 *
 * 사용자가 로그인한 세션의 사건에는 "user" 가 붙는다 — "이 기기가"가 아니라 "이 사람이
 * 이 기기로" 어디에 닿았는지가 남는다.
 *
 * 파일을 주지 않으면(-a) 아무것도 하지 않는다. */

#include <stdint.h>
#include <netinet/in.h>

#include "proto.h"
#include "peer.h"

/* 덧붙여 쓰도록 연다 (없으면 600 으로 만든다). 성공 0, 실패 -1. */
int audit_open(const char *path);

/* 같은 경로를 다시 연다. 로그를 돌리는 쪽이 파일 이름을 바꾼 뒤 SIGHUP 을 보내면
 * 새 파일에 이어 쓴다. */
void audit_reopen(void);

void audit_close(void);

void audit_session_open(const peer_t *peer);

/* reason: "expired" (60초 무응답), "posture" (정책에 못 미침), "device_removed",
 * "replaced" (같은 기기가 다시 인증), "evicted" (표가 가득 참), "error",
 * "closed" (클라이언트가 DISCONNECT 로 끝냄), "shutdown" (서버가 끝남), "rekey" (키의 수명이 다함) */
void audit_session_close(const peer_t *peer, const char *reason);

/* id 는 상대가 댄 기기 ID 다. 등록된 기기인지와 관계없이 적는다. */
void audit_auth_denied(const uint8_t id[DEVICE_ID_LEN], const struct sockaddr_in *src, uint8_t reason);

/* 패킷 하나의 판정. 같은 세션의 같은 목적지(주소, 프로토콜, 포트)와 같은 판정은 한동안
 * 다시 적지 않는다 — 패킷마다 적으면 stdout 로그와 다를 것이 없다. why 는 막힌 이유
 * ("acl", "posture", "user", "no_acl_file") 이고 통과했으면 NULL. */
void audit_access(peer_t *peer, const uint8_t *ip, int len, int allowed, const char *why);

void audit_reload(const char *what, int ok, int count);

/* 등록 코드로 기기가 목록에 올랐다. label 은 관리자가 코드를 만들 때 붙인 이름이다. */
void audit_enrolled(const uint8_t id[DEVICE_ID_LEN], struct in_addr tun_ip,
		const struct sockaddr_in *src, const char *label);

/* LOGIN 의 결과. status 는 login_status_t. 성공이면 peer->user 를 적는다. */
void audit_login(const peer_t *peer, int status);

/* 로그인했던 사용자를 세션에서 뗐다. reason: "expired" */
void audit_logout(const peer_t *peer, const char *reason);

#endif
