#ifndef STATUS_H
#define STATUS_H

/* 서버의 상태를 밖에서 읽는 창구.
 *
 * 서버가 아는 것(누가 붙어 있는가, 무엇을 얼마나 거절했는가)은 지금까지 로그로만
 * 나갔다. 로그는 일어난 일의 기록이지 지금의 상태가 아니라서, "현재 세션"을 알려면
 * register / drop / expire 를 처음부터 따라가며 다시 계산해야 했다.
 *
 * 유닉스 소켓 하나를 열어 두고, 접속하면 JSON 한 덩어리를 쓰고 닫는다. 읽기 전용이다
 * — 접속한 쪽이 보낸 것은 읽지 않으므로 이 소켓으로 서버에 시킬 수 있는 일이 없다.
 * 누가 읽을 수 있는지는 소켓 파일의 권한(600)이 정한다.
 */

#include <stdint.h>

#include "proto.h"

typedef struct server_stats {
	uint64_t handshake_ok;
	uint64_t deny[DENY_POSTURE + 1];	/* DENY 사유별. 핸드셰이크와 세션 중 거절을 합친 값 */
	uint64_t keepalive_dropped;		/* 순서가 뒤바뀐 포스처 보고, 짧은 keepalive */
	uint64_t bad_tag;			/* 세션 키로 열리지 않은 패킷 (위조 / 손상 / 다른 세션의 것) */
	uint64_t replayed;			/* 이미 받은 counter 로 다시 온 패킷 */
	uint64_t unknown_session;
	uint64_t auth_rate_limited;		/* 한 주소에서 초당 -r 개를 넘게 온 AUTH 를 열어 보지 않고 버렸다 */
	uint64_t version_mismatch;		/* 이 서버가 받지 않는 프로토콜 버전의 패킷 (올리지 않은 클라이언트) */
	uint64_t spoofed_src;
	uint64_t acl_denied;
	uint64_t acl_denied_posture;
	uint64_t acl_denied_user;		/* user= / group= 규칙에 걸렸는데 그 사용자가 아니다 */
	uint64_t login_ok;
	uint64_t login_failed;
	uint64_t connector_offline;		/* 커넥터가 맡은 대역으로 가는데 커넥터가 붙어 있지 않다 */
	uint64_t connector_dropped;		/* 커넥터가 보낸 답의 목적지에 클라이언트가 없다 */
	uint64_t flow_dropped;			/* 클라이언트가 연 흐름의 답이 아니라 들이지 않았다 (-F) */
} server_stats_t;

extern server_stats_t stats;

/* path 에 소켓을 만들고 듣는다. 성공하면 fd, 실패하면 -1. */
int status_listen(const char *path);

/* 기다리던 접속 하나를 받아 상태를 쓰고 닫는다. 한 번에 다 쓰지 못하면 그 접속을 epfd 에
 * EPOLLOUT 으로 걸어 두고, 이어 쓰는 것은 status_writable 이 한다. */
void status_serve(int epfd, int lfd, int acl_enabled);

/* fd 가 상태를 쓰는 중인 접속이면 이어 쓰고 1. 아니면 0. */
int status_writable(int epfd, int fd);

/* 오래 다 읽지 않는 접속을 끊는다. 이벤트 루프가 돌 때마다 부른다. */
void status_tick(int epfd);

#endif
