#ifndef SESSION_H
#define SESSION_H

/* 클라이언트 쪽 프로토콜 (버전 5): 핸드셰이크, 등록, 열린 세션의 패킷.
 *
 * Linux 클라이언트(client.c)와 부하 생성기(tools/loadgen)가 함께 쓴다. 터널(TUN)과 경로는
 * 다루지 않는다 — UDP 소켓 하나와 세션 키만 다룬다. 동작은 Windows 클라이언트의
 * windows/core/tunnel.c 에 있는 do_handshake / tunnel_enroll 과 같다.
 *
 * 소켓은 부르는 쪽이 만들어 서버에 connect() 해 둔다. 그러면 서버가 아닌 곳에서 온
 * 패킷은 커널이 걸러 준다 (Windows 는 같은 확인을 from_server 로 직접 한다). */

#include <stdint.h>

#include "proto.h"
#include "secure.h"

#define HS_TIMEOUT_MSEC	1000
#define HS_RETRY	5

#define HS_OK		0
#define HS_FAIL		(-1)	/* 응답 없음 / 오류 */
#define HS_DENIED	(-2)	/* 서버가 거절했다. 다시 보내도 같은 답이 온다 */

#define ENROLL_TRIES		3
#define ENROLL_TIMEOUT_MSEC	1500

/* session_enroll 의 결과. 0 이상은 서버가 답한 enroll_status_t 다. */
#define SESSION_ENROLL_BAD_CODE		(-1)	/* 코드의 글자 수나 글자가 틀렸다 */
#define SESSION_ENROLL_REJECTED		(-2)	/* 서버가 코드를 모른다 (잘못 적음 / 만료 / 이미 씀) */
#define SESSION_ENROLL_NO_RESPONSE	(-3)
#define SESSION_ENROLL_ERROR		(-4)

typedef struct vpn_session {
	int sock;			/* 서버에 connect() 한 UDP 소켓 */
	uint32_t idx;			/* 0 이면 열린 세션이 없다 */
	secure_session_t secure;
	net_config_t cfg;		/* 수락에 실려 온 터널 설정 */
	uint8_t deny_reason;		/* HS_DENIED 일 때 서버가 댄 사유 */
} vpn_session_t;

/* 등록된 기기로 세션을 연다. 열려 있던 세션은 닫고 새로 연다. posture 는 AUTH 에 실을
 * 이번 보고다. HS_OK / HS_FAIL / HS_DENIED. */
int session_handshake(vpn_session_t *s, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t key[AUTH_KEY_LEN], const posture_report_t *posture);

/* 등록 코드로 서버에 이 기기(id, key)를 올린다 (proto.h 의 "기기 등록"). 코드에서 뽑은
 * 임시 신원으로 평소의 핸드셰이크를 돌고, 그 세션으로 id 와 key 를 보낸다. 끝나면
 * 등록용 세션은 닫는다. 0 이상이면 서버의 답(enroll_status_t), 음수는 SESSION_ENROLL_*. */
int session_enroll(vpn_session_t *s, const char *code, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t key[AUTH_KEY_LEN], const posture_report_t *posture);

/* KEEPALIVE: 지금의 포스처를 세션 키로 감싸 보낸다. 성공 0, 실패 -1. */
int session_send_keepalive(vpn_session_t *s, const posture_report_t *posture);

/* pkt 의 PKT_HDR_LEN 뒤에 놓인 len 바이트를 감싸 보낸다. cap 은 pkt 의 크기로, 뒤에
 * tag 가 붙을 자리(AEAD_TAG_LEN)가 있어야 한다. 성공 0, 실패 -1. */
int session_send(vpn_session_t *s, uint8_t type, uint8_t *pkt, size_t cap, size_t len);

/* DISCONNECT: 이 세션을 끝낸다고 서버에 알린다 (disconnect_reason_t). 한 번 보내고 답을
 * 기다리지 않는다. 열린 세션이 없으면 아무것도 하지 않는다. 성공 0, 실패 -1. */
int session_send_disconnect(vpn_session_t *s, uint8_t reason);

void session_close(vpn_session_t *s);

const char *session_deny_name(uint8_t reason);

/* LOGIN 답의 status (login_status_t) 를 사람이 읽을 말로. */
const char *session_login_name(uint8_t status);

#endif
