#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypt.h"
#include "dpop.h"
#include "proto.h"

static EVP_PKEY *key;
static char jwk_x[48], jwk_y[48];

static void b64url(const unsigned char *in, size_t len, char *out)
{
	static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i, o = 0;

	for (i = 0; i + 2 < len; i += 3) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4 | in[i + 1] >> 4];
		out[o++] = a[(in[i + 1] & 15) << 2 | in[i + 2] >> 6];
		out[o++] = a[in[i + 2] & 63];
	}
	if (len - i == 1) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4];
	}
	else if (len - i == 2) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4 | in[i + 1] >> 4];
		out[o++] = a[(in[i + 1] & 15) << 2];
	}
	out[o] = '\0';
}

int dpop_load(const char *path)
{
	unsigned char pt[65];
	size_t ptlen = 0;
	struct stat st;
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL && errno == ENOENT) {
		/* 처음부터 0600 으로 만든다. */
		int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

		key = EVP_EC_gen("P-256");
		if (fd < 0 || key == NULL || (fp = fdopen(fd, "w")) == NULL ||
				!PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL)) {
			fprintf(stderr, "dpop: cannot create %s\n", path);
			return -1;
		}
		fclose(fp);
		printf("[dpop] new device key %s\n", path);
	}
	else {
		if (fp == NULL || fstat(fileno(fp), &st) < 0 || (st.st_mode & 077) != 0) {
			fprintf(stderr, "dpop: %s: must exist with mode 600\n", path);
			if (fp) fclose(fp);
			return -1;
		}
		key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}
	if (key == NULL || !EVP_PKEY_is_a(key, "EC") ||
			!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof(pt), &ptlen) ||
			ptlen != 65 || pt[0] != 4) {
		fprintf(stderr, "dpop: %s is not a P-256 key\n", path);
		EVP_PKEY_free(key);
		key = NULL;
		return -1;
	}
	b64url(pt + 1, 32, jwk_x);
	b64url(pt + 33, 32, jwk_y);
	return 0;
}

int dpop_ready(void)
{
	return key != NULL;
}

int dpop_jkt(char out[64])
{
	char canon[200];
	unsigned char h[32];

	if (!key) {
		return -1;
	}
	snprintf(canon, sizeof(canon), "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", jwk_x, jwk_y);
	if (crypt_sha256((const uint8_t *)canon, strlen(canon), h) < 0) {
		return -1;
	}
	b64url(h, sizeof(h), out);
	return 0;
}

int dpop_proof(const char *token, size_t token_len, char *out, size_t cap)
{
	char header[256], payload[256], hb[400], pb[400], ath[48], jti[24], sigb[90];
	unsigned char h[32], r[16], der[80], raw[64];
	size_t derlen = sizeof(der);
	const unsigned char *p;
	EVP_MD_CTX *md = NULL;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *br, *bs;
	int n, ret = -1;

	if (!key || crypt_sha256((const uint8_t *)token, token_len, h) < 0 || crypt_random(r, sizeof(r)) < 0) {
		return -1;
	}
	b64url(h, sizeof(h), ath);
	b64url(r, sizeof(r), jti);
	snprintf(header, sizeof(header),
			"{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}}",
			jwk_x, jwk_y);
	snprintf(payload, sizeof(payload), "{\"htm\":\"%s\",\"htu\":\"%s\",\"iat\":%lld,\"jti\":\"%s\",\"ath\":\"%s\"}",
			DPOP_HTM, DPOP_HTU, (long long)time(NULL), jti, ath);
	b64url((const unsigned char *)header, strlen(header), hb);
	b64url((const unsigned char *)payload, strlen(payload), pb);
	n = snprintf(out, cap, "%s.%s", hb, pb);
	if (n < 0 || (size_t)n + 90 > cap) {
		return -1;
	}

	/* ES256: DER 서명을 JWS 의 r | s (각 32B) 로. */
	md = EVP_MD_CTX_new();
	if (md == NULL || EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1 ||
			EVP_DigestSign(md, der, &derlen, (const unsigned char *)out, (size_t)n) != 1) {
		goto done;
	}
	p = der;
	sig = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
	if (sig == NULL) {
		goto done;
	}
	ECDSA_SIG_get0(sig, &br, &bs);
	if (BN_bn2binpad(br, raw, 32) != 32 || BN_bn2binpad(bs, raw + 32, 32) != 32) {
		goto done;
	}
	b64url(raw, sizeof(raw), sigb);
	n += snprintf(out + n, cap - (size_t)n, ".%s", sigb);
	ret = n;

done:
	ECDSA_SIG_free(sig);
	EVP_MD_CTX_free(md);
	return ret;
}
