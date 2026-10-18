/* crypt.h 의 CNG 구현 (Windows 클라이언트). Linux 쪽(서버, Linux 클라이언트)은 lib/common/src/crypt_openssl.c (OpenSSL) 다.
 *
 * CNG 의 호출 순서는 어느 알고리즘이나 같다.
 *   알고리즘 공급자 열기  ->  객체 만들기(키를 여기서 준다)  ->  쓰기  ->  역순으로 닫기
 *
 * 공급자를 여는 것은 느리다 (레지스트리와 DLL 을 뒤진다). 패킷마다 암호화하므로 한 번
 * 열어 프로세스가 끝날 때까지 들고 있는다. */

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#include "crypt.h"

static BCRYPT_ALG_HANDLE alg_sha256;
static BCRYPT_ALG_HANDLE alg_hmac;
static BCRYPT_ALG_HANDLE alg_ecdh;
static BCRYPT_ALG_HANDLE alg_gcm;
static INIT_ONCE alg_once = INIT_ONCE_STATIC_INIT;

/* 터널은 워커 스레드에서, selftest 나 기기 등록은 다른 스레드에서 돌 수 있다.
 * InitOnce 가 "한 번만, 끝난 뒤에 보이게"를 맡는다. */
static BOOL CALLBACK alg_open(PINIT_ONCE once, PVOID param, PVOID *context)
{
	(void)once;
	(void)param;
	(void)context;

	/* BCRYPT_ALG_HANDLE_HMAC_FLAG 를 줘야 SHA-256 이 아니라 HMAC-SHA256 이 된다. */
	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0)) ||
			!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_hmac, BCRYPT_SHA256_ALGORITHM, NULL,
					BCRYPT_ALG_HANDLE_HMAC_FLAG)) ||
			!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_ecdh, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0)) ||
			!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_gcm, BCRYPT_AES_ALGORITHM, NULL, 0))) {
		return FALSE;
	}

	/* AES 공급자의 기본 운용 방식은 CBC 다. */
	return BCRYPT_SUCCESS(BCryptSetProperty(alg_gcm, BCRYPT_CHAINING_MODE,
				(PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
}

static int alg_ready(void)
{
	return InitOnceExecuteOnce(&alg_once, alg_open, NULL, NULL) ? 0 : -1;
}

int crypt_random(uint8_t *buf, size_t len)
{
	if (len > MAXDWORD) {
		return -1;
	}

	return BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len,
				BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? 0 : -1;
}

static int hash(BCRYPT_ALG_HANDLE alg, const uint8_t *key, size_t key_len,
		const uint8_t *msg, size_t len, uint8_t out[VPN_HASH_LEN])
{
	BCRYPT_HASH_HANDLE h = NULL;
	int ret = -1;

	if (key_len > MAXDWORD || len > MAXDWORD) {
		return -1;
	}

	/* 해시 객체 버퍼를 NULL / 0 으로 주면 CNG 가 내부에서 할당한다. */
	if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0))) {
		return -1;
	}

	if (BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)msg, (ULONG)len, 0)) &&
			BCRYPT_SUCCESS(BCryptFinishHash(h, out, VPN_HASH_LEN, 0))) {
		ret = 0;
	}

	BCryptDestroyHash(h);

	return ret;
}

int crypt_sha256(const uint8_t *msg, size_t len, uint8_t out[VPN_HASH_LEN])
{
	if (alg_ready() < 0) {
		return -1;
	}

	return hash(alg_sha256, NULL, 0, msg, len, out);
}

int crypt_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t len,
		uint8_t out[VPN_HASH_LEN])
{
	if (alg_ready() < 0) {
		return -1;
	}

	return hash(alg_hmac, key, key_len, msg, len, out);
}

/* 다른 바이트를 만나도 멈추지 않고 끝까지 본다. volatile 이 없으면 컴파일러가 이것을
 * memcmp 로 되돌려 놓을 수 있다. */
int crypt_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile uint8_t diff = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		diff |= (uint8_t)(a[i] ^ b[i]);
	}

	return diff == 0;
}

void crypt_wipe(void *p, size_t len)
{
	SecureZeroMemory(p, len);
}

/* ---- ECDH P-256 ------------------------------------------------------------- */

struct crypt_ecdh {
	BCRYPT_KEY_HANDLE key;
};

/* CNG 가 타원곡선 키를 주고받는 모양: 머리(종류, 좌표 길이) 뒤에 X | Y, 개인키가
 * 있으면 그 뒤에 d. 좌표는 빅엔디언이라 와이어의 X | Y 를 그대로 옮기면 된다. */
typedef struct ecc_blob {
	BCRYPT_ECCKEY_BLOB head;
	uint8_t xy[VPN_PUB_LEN];
	uint8_t d[VPN_PRIV_LEN];
} ecc_blob_t;

#define ECC_PUBLIC_BLOB_LEN	(sizeof(BCRYPT_ECCKEY_BLOB) + VPN_PUB_LEN)
#define ECC_PRIVATE_BLOB_LEN	(ECC_PUBLIC_BLOB_LEN + VPN_PRIV_LEN)

static crypt_ecdh_t *ecdh_wrap(BCRYPT_KEY_HANDLE key)
{
	crypt_ecdh_t *e = malloc(sizeof(*e));

	if (e == NULL) {
		BCryptDestroyKey(key);
		return NULL;
	}
	e->key = key;

	return e;
}

crypt_ecdh_t *crypt_ecdh_new(uint8_t pub[VPN_PUB_LEN])
{
	BCRYPT_KEY_HANDLE key = NULL;
	ecc_blob_t blob;
	ULONG len = 0;

	if (alg_ready() < 0) {
		return NULL;
	}

	if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(alg_ecdh, &key, 256, 0))) {
		return NULL;
	}

	if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key, 0)) ||
			!BCRYPT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)&blob,
					(ULONG)ECC_PUBLIC_BLOB_LEN, &len, 0)) ||
			len != ECC_PUBLIC_BLOB_LEN || blob.head.cbKey != VPN_PUB_LEN / 2) {
		BCryptDestroyKey(key);
		return NULL;
	}
	memcpy(pub, blob.xy, VPN_PUB_LEN);

	return ecdh_wrap(key);
}

crypt_ecdh_t *crypt_ecdh_import(const uint8_t priv[VPN_PRIV_LEN], const uint8_t pub[VPN_PUB_LEN])
{
	BCRYPT_KEY_HANDLE key = NULL;
	ecc_blob_t blob;
	NTSTATUS status;

	if (alg_ready() < 0) {
		return NULL;
	}

	blob.head.dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
	blob.head.cbKey = VPN_PUB_LEN / 2;
	memcpy(blob.xy, pub, VPN_PUB_LEN);
	memcpy(blob.d, priv, VPN_PRIV_LEN);

	status = BCryptImportKeyPair(alg_ecdh, NULL, BCRYPT_ECCPRIVATE_BLOB, &key, (PUCHAR)&blob,
			(ULONG)ECC_PRIVATE_BLOB_LEN, 0);
	SecureZeroMemory(&blob, sizeof(blob));

	return BCRYPT_SUCCESS(status) ? ecdh_wrap(key) : NULL;
}

int crypt_ecdh_derive(crypt_ecdh_t *e, const uint8_t peer_pub[VPN_PUB_LEN],
		uint8_t secret[VPN_SECRET_LEN])
{
	BCRYPT_KEY_HANDLE peer = NULL;
	BCRYPT_SECRET_HANDLE agreed = NULL;
	BCryptBuffer param;
	BCryptBufferDesc params;
	ecc_blob_t blob;
	ULONG len = 0;
	int ret = -1;

	blob.head.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
	blob.head.cbKey = VPN_PUB_LEN / 2;
	memcpy(blob.xy, peer_pub, VPN_PUB_LEN);

	/* 곡선 위에 있지 않은 점은 여기서 걸러진다 (BCRYPT_NO_KEY_VALIDATION 을 주지 않는다). */
	if (!BCRYPT_SUCCESS(BCryptImportKeyPair(alg_ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer,
				(PUCHAR)&blob, (ULONG)ECC_PUBLIC_BLOB_LEN, 0))) {
		return -1;
	}

	if (!BCRYPT_SUCCESS(BCryptSecretAgreement(e->key, peer, &agreed, 0))) {
		goto out;
	}

	/* 공유점의 X 좌표를 SHA-256 에 넣은 값을 받는다. 날것의 값을 달라고 하면
	 * (BCRYPT_KDF_RAW_SECRET) 바이트 순서가 뒤집혀 나온다. */
	param.cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM);
	param.BufferType = KDF_HASH_ALGORITHM;
	param.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = 1;
	params.pBuffers = &param;

	if (BCRYPT_SUCCESS(BCryptDeriveKey(agreed, BCRYPT_KDF_HASH, &params, secret,
				VPN_SECRET_LEN, &len, 0)) && len == VPN_SECRET_LEN) {
		ret = 0;
	}

out:
	if (agreed) {
		BCryptDestroySecret(agreed);
	}
	BCryptDestroyKey(peer);

	return ret;
}

void crypt_ecdh_free(crypt_ecdh_t *e)
{
	if (e == NULL) {
		return;
	}

	BCryptDestroyKey(e->key);
	free(e);
}

/* ---- AES-256-GCM ------------------------------------------------------------ */

struct crypt_aead {
	BCRYPT_KEY_HANDLE key;
};

crypt_aead_t *crypt_aead_new(const uint8_t key[VPN_KEY_LEN])
{
	crypt_aead_t *a;

	if (alg_ready() < 0) {
		return NULL;
	}

	a = malloc(sizeof(*a));
	if (a == NULL) {
		return NULL;
	}

	if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg_gcm, &a->key, NULL, 0,
				(PUCHAR)key, VPN_KEY_LEN, 0))) {
		free(a);
		return NULL;
	}

	return a;
}

static void gcm_info(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *info,
		const uint8_t nonce[VPN_NONCE_LEN], const uint8_t *aad, size_t aad_len,
		const uint8_t tag[VPN_TAG_LEN])
{
	BCRYPT_INIT_AUTH_MODE_INFO(*info);
	info->pbNonce = (PUCHAR)nonce;
	info->cbNonce = VPN_NONCE_LEN;
	info->pbAuthData = (PUCHAR)aad;
	info->cbAuthData = (ULONG)aad_len;
	info->pbTag = (PUCHAR)tag;
	info->cbTag = VPN_TAG_LEN;
}

int crypt_aead_seal(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, uint8_t tag[VPN_TAG_LEN])
{
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	ULONG out = 0;

	if (aad_len > MAXDWORD || len > MAXDWORD) {
		return -1;
	}

	/* 입력과 출력에 같은 버퍼를 줘도 된다. tag 는 info.pbTag 에 적힌다. */
	gcm_info(&info, nonce, aad, aad_len, tag);

	return BCRYPT_SUCCESS(BCryptEncrypt(a->key, buf, (ULONG)len, &info, NULL, 0,
				buf, (ULONG)len, &out, 0)) && out == len ? 0 : -1;
}

int crypt_aead_open(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, const uint8_t tag[VPN_TAG_LEN])
{
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	ULONG out = 0;

	if (aad_len > MAXDWORD || len > MAXDWORD) {
		return -1;
	}

	/* tag 가 틀리면 STATUS_AUTH_TAG_MISMATCH 가 돌아온다. */
	gcm_info(&info, nonce, aad, aad_len, tag);

	return BCRYPT_SUCCESS(BCryptDecrypt(a->key, buf, (ULONG)len, &info, NULL, 0,
				buf, (ULONG)len, &out, 0)) && out == len ? 0 : -1;
}

void crypt_aead_free(crypt_aead_t *a)
{
	if (a == NULL) {
		return;
	}

	BCryptDestroyKey(a->key);
	free(a);
}
