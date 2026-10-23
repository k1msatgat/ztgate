/* crypt.h 의 OpenSSL 구현. Linux 쪽(서버, Linux 클라이언트, 부하 생성기)이 모두 이것을 쓴다.
 * Windows 클라이언트 쪽은 windows/core/crypt.c (CNG) 다. */

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include "crypt.h"

/* rand() 는 쓸 수 없다. nonce 가 예측되면 공격자가 미리 서명을 받아 둘 수 있다. 커널의
 * getrandom 은 요청한 길이가 256 바이트 이하이면 한 번에 다 채워 주므로 부분 읽기를
 * 따로 처리하지 않는다. */
int crypt_random(uint8_t *buf, size_t len)
{
	return getrandom(buf, len, 0) == (ssize_t)len ? 0 : -1;
}

int crypt_sha256(const uint8_t *msg, size_t len, uint8_t out[VPN_HASH_LEN])
{
	return SHA256(msg, len, out) != NULL ? 0 : -1;
}

int crypt_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t len,
		uint8_t out[VPN_HASH_LEN])
{
	unsigned int out_len = 0;

	if (HMAC(EVP_sha256(), key, (int)key_len, msg, len, out, &out_len) == NULL) {
		return -1;
	}

	return out_len == VPN_HASH_LEN ? 0 : -1;
}

int crypt_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	return CRYPTO_memcmp(a, b, len) == 0;
}

void crypt_wipe(void *p, size_t len)
{
	OPENSSL_cleanse(p, len);
}

/* ---- ECDH P-256 ------------------------------------------------------------- */

struct crypt_ecdh {
	EVP_PKEY *pkey;
};

/* 와이어의 X | Y 를 OpenSSL 이 받는 점 표기(0x04 | X | Y)로 바꿔 키 객체를 만든다.
 * 곡선 위에 있지 않은 점이면 여기서 실패한다. priv 를 주면 키 쌍이 된다. */
static EVP_PKEY *ec_key(const uint8_t *priv, const uint8_t pub[VPN_PUB_LEN])
{
	static const uint16_t one = 1;
	uint8_t point[1 + VPN_PUB_LEN];
	uint8_t scalar[VPN_PRIV_LEN];
	char group[] = "prime256v1";
	OSSL_PARAM params[4];
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	int n = 0;
	int i;

	point[0] = 0x04;
	memcpy(point + 1, pub, VPN_PUB_LEN);

	params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	params[n++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point));

	if (priv != NULL) {
		/* 큰 수 매개변수는 이 장비의 바이트 순서로 넘긴다. 우리 값은 빅엔디언이다. */
		for (i = 0; i < VPN_PRIV_LEN; i++) {
			scalar[i] = *(const uint8_t *)&one ? priv[VPN_PRIV_LEN - 1 - i] : priv[i];
		}
		params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, scalar, sizeof(scalar));
	}
	params[n] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx != NULL) {
		if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
				EVP_PKEY_fromdata(ctx, &pkey, priv != NULL ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
					params) <= 0) {
			pkey = NULL;
		}
		EVP_PKEY_CTX_free(ctx);
	}

	OPENSSL_cleanse(scalar, sizeof(scalar));

	return pkey;
}

static crypt_ecdh_t *ecdh_wrap(EVP_PKEY *pkey)
{
	crypt_ecdh_t *e;

	if (pkey == NULL) {
		return NULL;
	}

	e = malloc(sizeof(*e));
	if (e == NULL) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	e->pkey = pkey;

	return e;
}

crypt_ecdh_t *crypt_ecdh_new(uint8_t pub[VPN_PUB_LEN])
{
	uint8_t point[1 + VPN_PUB_LEN];
	size_t len = 0;
	EVP_PKEY *pkey;

	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (pkey == NULL) {
		return NULL;
	}

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point), &len) <= 0 ||
			len != sizeof(point) || point[0] != 0x04) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	memcpy(pub, point + 1, VPN_PUB_LEN);

	return ecdh_wrap(pkey);
}

crypt_ecdh_t *crypt_ecdh_import(const uint8_t priv[VPN_PRIV_LEN], const uint8_t pub[VPN_PUB_LEN])
{
	return ecdh_wrap(ec_key(priv, pub));
}

int crypt_ecdh_export(crypt_ecdh_t *e, uint8_t priv[VPN_PRIV_LEN])
{
	BIGNUM *d = NULL;
	int ret = -1;

	if (EVP_PKEY_get_bn_param(e->pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) > 0 &&
			BN_bn2binpad(d, priv, VPN_PRIV_LEN) == VPN_PRIV_LEN) {
		ret = 0;
	}
	BN_clear_free(d);

	return ret;
}

int crypt_ecdh_derive(crypt_ecdh_t *e, const uint8_t peer_pub[VPN_PUB_LEN],
		uint8_t secret[VPN_SECRET_LEN])
{
	uint8_t x[32];
	size_t len = sizeof(x);
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *peer;
	int ret = -1;

	peer = ec_key(NULL, peer_pub);
	if (peer == NULL) {
		return -1;
	}

	ctx = EVP_PKEY_CTX_new(e->pkey, NULL);
	if (ctx == NULL ||
			EVP_PKEY_derive_init(ctx) <= 0 ||
			EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
			EVP_PKEY_derive(ctx, x, &len) <= 0 || len != sizeof(x)) {
		goto out;
	}

	ret = crypt_sha256(x, sizeof(x), secret);

out:
	OPENSSL_cleanse(x, sizeof(x));
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);

	return ret;
}

void crypt_ecdh_free(crypt_ecdh_t *e)
{
	if (e == NULL) {
		return;
	}

	EVP_PKEY_free(e->pkey);
	free(e);
}

/* ---- AES-256-GCM ------------------------------------------------------------ */

struct crypt_aead {
	EVP_CIPHER_CTX *ctx;
	uint8_t key[VPN_KEY_LEN];
};

crypt_aead_t *crypt_aead_new(const uint8_t key[VPN_KEY_LEN])
{
	crypt_aead_t *a = malloc(sizeof(*a));

	if (a == NULL) {
		return NULL;
	}

	a->ctx = EVP_CIPHER_CTX_new();
	if (a->ctx == NULL) {
		free(a);
		return NULL;
	}
	memcpy(a->key, key, VPN_KEY_LEN);

	return a;
}

int crypt_aead_seal(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, uint8_t tag[VPN_TAG_LEN])
{
	uint8_t none[16];
	int n;

	/* GCM 의 기본 nonce 길이가 12 바이트다. */
	if (EVP_EncryptInit_ex(a->ctx, EVP_aes_256_gcm(), NULL, a->key, nonce) <= 0) {
		return -1;
	}
	if (aad_len > 0 && EVP_EncryptUpdate(a->ctx, NULL, &n, aad, (int)aad_len) <= 0) {
		return -1;
	}
	if (len > 0 && EVP_EncryptUpdate(a->ctx, buf, &n, buf, (int)len) <= 0) {
		return -1;
	}
	if (EVP_EncryptFinal_ex(a->ctx, none, &n) <= 0) {
		return -1;
	}

	return EVP_CIPHER_CTX_ctrl(a->ctx, EVP_CTRL_AEAD_GET_TAG, VPN_TAG_LEN, tag) > 0 ? 0 : -1;
}

int crypt_aead_open(crypt_aead_t *a, const uint8_t nonce[VPN_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		uint8_t *buf, size_t len, const uint8_t tag[VPN_TAG_LEN])
{
	uint8_t want[VPN_TAG_LEN];
	uint8_t none[16];
	int n;

	memcpy(want, tag, sizeof(want));

	if (EVP_DecryptInit_ex(a->ctx, EVP_aes_256_gcm(), NULL, a->key, nonce) <= 0) {
		return -1;
	}
	if (aad_len > 0 && EVP_DecryptUpdate(a->ctx, NULL, &n, aad, (int)aad_len) <= 0) {
		return -1;
	}
	if (len > 0 && EVP_DecryptUpdate(a->ctx, buf, &n, buf, (int)len) <= 0) {
		return -1;
	}
	if (EVP_CIPHER_CTX_ctrl(a->ctx, EVP_CTRL_AEAD_SET_TAG, VPN_TAG_LEN, want) <= 0) {
		return -1;
	}

	/* tag 는 여기서 확인된다. 틀리면 0 이하가 온다. */
	return EVP_DecryptFinal_ex(a->ctx, none, &n) > 0 ? 0 : -1;
}

void crypt_aead_free(crypt_aead_t *a)
{
	if (a == NULL) {
		return;
	}

	EVP_CIPHER_CTX_free(a->ctx);
	OPENSSL_cleanse(a->key, sizeof(a->key));
	free(a);
}
