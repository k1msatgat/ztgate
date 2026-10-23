#ifndef CRYPT_H
#define CRYPT_H

/* 암호 도구의 창구.
 *
 * 알고리즘은 직접 구현하지 않는다. Linux 쪽은 OpenSSL(lib/common/src/crypt_openssl.c), Windows
 * 클라이언트는 OS 에 내장된 CNG(windows/core/crypt.c)가 이 선언을 채운다. 직접 짠
 * 구현은 테스트 벡터를 통과해도 타이밍 같은 부채널까지 검증하기 어렵고, OS 와
 * 라이브러리의 구현은 보안 패치와 함께 갱신된다.
 *
 * 양쪽이 같은 선언을 채우게 한 것은 그 위의 프로토콜 코드(secure.c)를 하나만 두기
 * 위해서다. 키를 어떻게 뽑고 패킷을 어떻게 감싸는지가 서버와 클라이언트에 따로
 * 적혀 있으면, 한쪽만 고친 순간 서로의 패킷을 열지 못한다.
 *
 * 고른 것은 모두 표준이라 구현이 달라도 같은 입력에 같은 값이 나온다. 정말 그런지는
 * 양쪽의 selftest 가 같은 표준 벡터로 확인한다 (crypt_selftest).
 *
 *   해시 / MAC   SHA-256, HMAC-SHA256
 *   키 합의      ECDH P-256
 *   패킷 암호    AES-256-GCM
 *
 * 곡선과 암호를 이렇게 고른 기준은 "양쪽 OS 가 기본으로 주는가"다. CNG 가 버전을 가리지
 * 않고 주는 것이 이 조합이고, 그래야 클라이언트에 암호 라이브러리를 실어 보내지 않는다.
 *
 * 값을 돌려주는 함수는 성공 0, 실패 -1 이다. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VPN_HASH_LEN		32	/* SHA-256, HMAC-SHA256 */
#define VPN_KEY_LEN		32	/* AES-256 */
#define VPN_NONCE_LEN		12	/* GCM */
#define VPN_TAG_LEN		16	/* GCM */
#define VPN_PUB_LEN		64	/* P-256 공개키: X(32) | Y(32), 빅엔디언 */
#define VPN_PRIV_LEN		32
#define VPN_SECRET_LEN	32

/* 예측할 수 없는 난수로 채운다. */
int crypt_random(uint8_t *buf, size_t len);

int crypt_sha256(const uint8_t *msg, size_t len, uint8_t out[VPN_HASH_LEN]);

int crypt_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t len,
		uint8_t out[VPN_HASH_LEN]);

/* 같으면 1. 걸리는 시간이 내용에 좌우되지 않는다. memcmp 는 처음 다른 바이트에서
 * 멈추므로 응답까지 걸린 시간이 "앞에서 몇 바이트가 맞았는가"를 알려 준다. */
int crypt_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* 컴파일러가 지워 버리지 못하는 방식으로 0 을 채운다. */
void crypt_wipe(void *p, size_t len);

/* ---- 키 합의 ---------------------------------------------------------------
 * 핸드셰이크마다 한 번 쓰고 버리는 키 쌍. 세션 키를 기기 키에서만 뽑으면, 나중에
 * 기기 키가 새는 날 그동안 녹화해 둔 트래픽이 전부 풀린다. 버려진 일회용 키가
 * 섞여 있으면 기기 키를 알아도 지난 세션은 풀 수 없다. */
typedef struct crypt_ecdh crypt_ecdh_t;

/* 새 키 쌍을 만들고 공개키를 pub 에 적는다. 실패하면 NULL. */
crypt_ecdh_t *crypt_ecdh_new(uint8_t pub[VPN_PUB_LEN]);

/* 주어진 키 쌍을 그대로 쓴다. 표준 벡터로 확인할 때만 쓴다. */
crypt_ecdh_t *crypt_ecdh_import(const uint8_t priv[VPN_PRIV_LEN],
		const uint8_t pub[VPN_PUB_LEN]);

/* secret = SHA-256(공유점의 X 좌표). 상대의 공개키가 곡선 위의 점이 아니면 실패한다.
 *
 * X 좌표를 그대로 내주지 않고 해시를 거치는 것은 CNG 때문이다. CNG 는 날것의 공유
 * 비밀을 버전에 따라 내주지 않거나 바이트 순서를 뒤집어 준다. 해시를 거친 값은
 * 어느 버전에서나 같고, 어차피 이 값은 곧바로 키 유도에 들어간다. */
int crypt_ecdh_derive(crypt_ecdh_t *e, const uint8_t peer_pub[VPN_PUB_LEN],
		uint8_t secret[VPN_SECRET_LEN]);

void crypt_ecdh_free(crypt_ecdh_t *e);

/* 키 쌍의 비밀 스칼라(빅엔디언 32B)를 꺼낸다. 서버가 자기 고정 키를 파일로 둘 때만 쓴다
 * (vpn_server genkey). 그래서 Linux(OpenSSL) 쪽에만 있다. */
int crypt_ecdh_export(crypt_ecdh_t *e, uint8_t priv[VPN_PRIV_LEN]);

/* ---- 패킷 암호 -------------------------------------------------------------
 * 키 하나에 묶인 AES-256-GCM. 암호화와 위조 방지를 한 번에 한다. aad 는 암호화하지
 * 않지만 tag 가 함께 덮는 부분이다 (우리 헤더).
 *
 * 같은 키로 같은 nonce 를 두 번 쓰면 GCM 은 무너진다. 그걸 지키는 것은 부르는 쪽의
 * 일이다 (secure.c: 방향마다 다른 키, 패킷마다 늘어나는 counter). */
typedef struct crypt_aead crypt_aead_t;

crypt_aead_t *crypt_aead_new(const uint8_t key[VPN_KEY_LEN]);

/* buf 의 len 바이트를 그 자리에서 암호화하고 tag 를 적는다. */
int crypt_aead_seal(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, uint8_t tag[VPN_TAG_LEN]);

/* tag 가 맞으면 buf 를 그 자리에서 풀고 0. 틀리면 -1 이고 buf 의 내용은 쓰면 안 된다. */
int crypt_aead_open(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, const uint8_t tag[VPN_TAG_LEN]);

void crypt_aead_free(crypt_aead_t *a);

/* 표준 테스트 벡터로 위의 것들을 확인하고 한 줄씩 찍는다. 모두 맞으면 0.
 * 구현은 secure.c 에 하나만 있다 — 서버와 클라이언트가 같은 벡터를 본다. */
int crypt_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
