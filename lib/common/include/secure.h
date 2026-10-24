#ifndef SECURE_H
#define SECURE_H

/* 세션 암호화. 핸드셰이크에서 세션 키를 뽑고, 그 키로 패킷을 감싸고 푼다.
 *
 * 서버와 Windows 클라이언트가 이 파일 하나를 함께 쓴다. 암호 알고리즘은 crypt.h 가
 * OS 별 구현으로 이어 준다.
 *
 * 인증만 있던 때에는 "누가 세션을 여는가"는 지켰지만 열린 뒤의 패킷은 그대로 보였고,
 * 세션 번호(4B)만 알면 누구든 끼워 넣을 수 있었다. 이제 세션마다 키를 따로 뽑아
 * 모든 패킷을 암호화하고 tag 를 붙인다.
 *
 * 세션 키
 *   secret = ECDH(이번 핸드셰이크의 일회용 키 쌍)
 *   prk    = HKDF-Extract(salt = 기기 키, ikm = secret)
 *   keys   = HKDF-Expand(prk, "ztgate v6 session" | SHA-256(AUTH 패킷 | RES 의 앞부분), 96B)
 *            = C->S 키 | S->C 키 | RES_HANDSHAKE 키
 *
 *   - 기기 키가 들어간다: 기기 키를 모르는 쪽은 사이에 끼어 자기 일회용 키를 내밀어도
 *     같은 세션 키에 닿지 못한다. 서버가 따로 인증서를 갖지 않아도 서로가 확인된다.
 *   - 일회용 키가 들어간다: 기기 키가 나중에 새도 지난 세션은 풀리지 않는다.
 *   - 주고받은 패킷의 해시가 들어간다: 도중에 한 바이트라도 바뀌었으면 양쪽의 키가
 *     달라져 첫 패킷부터 열리지 않는다.
 *   - 방향마다 키가 다르다: 양쪽이 counter 를 0 부터 세도 같은 (키, nonce) 가 생기지
 *     않고, 한쪽이 보낸 패킷을 그쪽으로 되돌려 보내도 열리지 않는다. */

#include <stddef.h>
#include <stdint.h>

#include "proto.h"
#include "crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

PROTO_STATIC_ASSERT(ECDH_PUB_LEN == VPN_PUB_LEN, "ecdh public key size");
PROTO_STATIC_ASSERT(AEAD_TAG_LEN == VPN_TAG_LEN, "aead tag size");
PROTO_STATIC_ASSERT(AUTH_MAC_LEN == VPN_HASH_LEN, "mac size");
PROTO_STATIC_ASSERT(AUTH_KEY_LEN == VPN_KEY_LEN, "device key size");

typedef struct secure_keys {
	uint8_t c2s[VPN_KEY_LEN];
	uint8_t s2c[VPN_KEY_LEN];
	uint8_t res[VPN_KEY_LEN];
} secure_keys_t;

/* auth_pkt 는 AUTH 패킷 전체(AUTH_PACKET_LEN), res_head 는 RES_HANDSHAKE 의 헤더와
 * pub_s (RES_HS_HEAD_LEN). 양쪽이 와이어에서 본 바이트 그대로를 넣어야 한다. */
int secure_derive(const uint8_t device_key[AUTH_KEY_LEN],
		const uint8_t secret[VPN_SECRET_LEN],
		const uint8_t *auth_pkt, const uint8_t *res_head,
		secure_keys_t *keys);

/* RES_HANDSHAKE 한 통. pkt 는 헤더 | pub_s | 페이로드 | tag 이고 페이로드를 그 자리에서
 * 감싼다 / 푼다. seal 은 패킷 길이를, open 은 페이로드 길이를 돌려주고 실패하면 -1. */
int secure_res_seal(const uint8_t key[VPN_KEY_LEN], uint8_t *pkt, size_t cap, size_t payload_len);
int secure_res_open(const uint8_t key[VPN_KEY_LEN], uint8_t *pkt, size_t len);

/* 핸드셰이크 중의 DENY 에 붙는 mac. */
int secure_deny_mac(const uint8_t device_key[AUTH_KEY_LEN], uint8_t reason,
		const uint8_t auth_mac[AUTH_MAC_LEN], uint8_t out[AUTH_MAC_LEN]);

/* 등록 코드에서 등록용 임시 신원을 뽑는다 (proto.h 의 "기기 등록").
 *
 *   id  = HMAC-SHA256("ztgate enroll id",  코드) 의 앞 16B
 *   key = HMAC-SHA256("ztgate enroll key", 코드)
 *
 * 코드는 줄표와 공백을 빼고 대문자로 바꾼 25자다. O 는 0 으로, I 와 L 은 1 로 읽는다.
 * 글자 수가 맞지 않거나 쓰지 않는 글자가 있으면 -1. */
int secure_enroll_identity(const char *code, uint8_t id[DEVICE_ID_LEN], uint8_t key[AUTH_KEY_LEN]);

/* 고정 키 쌍 둘(기기, 서버)에서 기기 키를 뽑는다 (proto.h 의 "기기 등록", v8).
 *
 *   secret = ECDH(mine, peer_pub)                     crypt_ecdh_derive 와 같다
 *   key    = HMAC-SHA256(secret, "ztgate v8 static" | client_pub | server_pub)
 *
 * 기기는 (기기 비밀키, 서버 공개키), 서버는 (서버 비밀키, 기기 공개키)로 같은 값을 얻는다. 두
 * 공개키를 넣는 순서는 역할로 정한다 — 기기가 앞. 이 값은 지금까지의 기기 키 자리에 들어간다. */
PROTO_STATIC_ASSERT(VPN_PUB_LEN == VPN_PUB_LEN_WIRE, "public key size on the wire");
int secure_static_key(crypt_ecdh_t *mine, const uint8_t peer_pub[VPN_PUB_LEN],
		const uint8_t client_pub[VPN_PUB_LEN], const uint8_t server_pub[VPN_PUB_LEN],
		uint8_t key[AUTH_KEY_LEN]);

/* AUTH 의 기기 ID 와 포스처를 감싸고 푼다 (proto.h 의 "기기 ID 와 포스처는 평문으로 다니지 않는다", v9).
 *
 *   k = HMAC-SHA256(ECDH, "ztgate v9 auth" | pub_c | server_pub)
 *
 * seal: 클라이언트. eph 는 AUTH 의 pub_c 의 짝(이번 핸드셰이크의 일회용 키). auth 의 헤더, pub_c,
 *       nonce, 그리고 평문 ID(AUTH_OFF_ID)와 포스처(AUTH_OFF_POSTURE)를 먼저 채워 둔다. 그 자리에서
 *       감싸고 tag 를 붙인다. mac 은 그 뒤에 만든다.
 * open: 서버. mine 은 server_pub 의 짝. 받은 AUTH 는 그대로 두고 plain 에 ID | 포스처를 푼다.
 *       tag 가 틀리거나 pub_c 가 곡선 위의 점이 아니면 -1. */
int secure_auth_seal(crypt_ecdh_t *eph, const uint8_t server_pub[VPN_PUB_LEN], uint8_t *auth);
int secure_auth_open(crypt_ecdh_t *mine, const uint8_t server_pub[VPN_PUB_LEN],
		const uint8_t *auth, uint8_t plain[AUTH_SEALED_PLAIN_LEN]);

/* ---- 열린 세션 -------------------------------------------------------------- */

/* 이미 받은 counter 를 기억하는 창의 폭. UDP 는 순서를 바꿔 전달할 수 있으므로 가장
 * 큰 값보다 작다고 버릴 수는 없고, 최근 64개 안에서 "처음 보는 값인가"를 따진다. */
#define SECURE_WINDOW 64

typedef struct secure_session {
	crypt_aead_t *tx;
	crypt_aead_t *rx;
	uint64_t tx_counter;	/* 다음에 보낼 값 */
	uint64_t rx_max;	/* 받아들인 가장 큰 값 */
	uint64_t rx_seen;	/* 비트 i: rx_max - i 를 받았다 */
	int rx_any;
} secure_session_t;

/* 키를 싣는다. 이미 열려 있던 것은 닫고 counter 와 창을 처음으로 돌린다. */
int secure_session_open(secure_session_t *s, const uint8_t tx_key[VPN_KEY_LEN],
		const uint8_t rx_key[VPN_KEY_LEN]);
void secure_session_close(secure_session_t *s);
int secure_session_ready(const secure_session_t *s);

#define SECURE_BAD	(-1)	/* 짧거나 tag 가 맞지 않는다 */
#define SECURE_REPLAY	(-2)	/* 이미 받은 counter 이거나 창보다 오래됐다 */

/* pkt 의 PKT_HDR_LEN 뒤에 놓인 payload_len 바이트를 그 자리에서 감싸고, 앞에 헤더와
 * counter 를, 뒤에 tag 를 쓴다. 보낼 길이(payload_len + PKT_OVERHEAD)를 돌려준다. */
int secure_seal(secure_session_t *s, uint8_t type, uint32_t session_idx,
		uint8_t *pkt, size_t cap, size_t payload_len);

/* 받은 패킷을 그 자리에서 푼다. 평문은 pkt + PKT_HDR_LEN 에 남고 그 길이를 돌려준다.
 * 실패한 패킷은 세션의 상태(창)를 바꾸지 않는다 — 위조 패킷으로 진짜 패킷이 버려지게
 * 할 수 없다. */
int secure_open(secure_session_t *s, uint8_t *pkt, size_t len, uint64_t *counter);

#ifdef __cplusplus
}
#endif

#endif
