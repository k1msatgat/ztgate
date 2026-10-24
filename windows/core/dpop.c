#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dpop.h"
#include "crypt.h"

#pragma comment(lib, "ncrypt.lib")

typedef struct pub_blob {
	BCRYPT_ECCKEY_BLOB head;
	BYTE xy[64];
} pub_blob_t;

static void b64url(const BYTE *in, size_t len, char *out)
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

/* 키를 연다. 없으면 TPM 에, 안 되면 소프트웨어 저장소에 만든다. */
static NCRYPT_KEY_HANDLE open_key(int machine)
{
	static const LPCWSTR providers[] = { MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER };
	const DWORD flags = machine ? NCRYPT_MACHINE_KEY_FLAG : 0;
	NCRYPT_KEY_HANDLE key = 0;

	for (int pass = 0; pass < 2 && !key; pass++) {
		for (size_t i = 0; i < sizeof(providers) / sizeof(providers[0]) && !key; i++) {
			NCRYPT_PROV_HANDLE prov = 0;

			if (NCryptOpenStorageProvider(&prov, providers[i], 0) != ERROR_SUCCESS) {
				continue;
			}
			/* 첫 바퀴는 있는 키를 찾고, 둘째 바퀴에 만든다 (TPM 을 먼저). */
			if (pass == 0) {
				if (NCryptOpenKey(prov, &key, DPOP_KEY_NAME, 0, flags) != ERROR_SUCCESS) {
					key = 0;
				}
			}
			else if (NCryptCreatePersistedKey(prov, &key, BCRYPT_ECDSA_P256_ALGORITHM, DPOP_KEY_NAME, 0, flags) != ERROR_SUCCESS ||
					NCryptFinalizeKey(key, 0) != ERROR_SUCCESS) {
				if (key) {
					NCryptDeleteKey(key, 0);
				}
				key = 0;
			}
			NCryptFreeObject(prov);
		}
	}
	return key;
}

int dpop_make_proof(int machine, const char *htm, const char *htu, const char *token, size_t token_len,
		char *out, size_t cap)
{
	char x[48], y[48], jti[24], ath[48], header[256], payload[1024], hb[400], pb[1400], sigb[90];
	BYTE r[16], h[32], sig[64];
	pub_blob_t blob;
	DWORD len = 0;
	NCRYPT_KEY_HANDLE key;
	int n, ret = -1;

	key = open_key(machine);
	if (!key) {
		return -1;
	}
	if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, (PBYTE)&blob, sizeof(blob), &len, 0) != ERROR_SUCCESS ||
			len != sizeof(blob) || crypt_random(r, sizeof(r)) < 0) {
		goto out;
	}
	b64url(blob.xy, 32, x);
	b64url(blob.xy + 32, 32, y);
	b64url(r, sizeof(r), jti);
	snprintf(header, sizeof(header),
			"{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}}", x, y);
	if (token) {
		if (crypt_sha256((const uint8_t *)token, token_len, h) < 0) {
			goto out;
		}
		b64url(h, sizeof(h), ath);
		n = snprintf(payload, sizeof(payload), "{\"htm\":\"%s\",\"htu\":\"%s\",\"iat\":%lld,\"jti\":\"%s\",\"ath\":\"%s\"}",
				htm, htu, (long long)time(NULL), jti, ath);
	}
	else {
		n = snprintf(payload, sizeof(payload), "{\"htm\":\"%s\",\"htu\":\"%s\",\"iat\":%lld,\"jti\":\"%s\"}",
				htm, htu, (long long)time(NULL), jti);
	}
	if (n < 0 || (size_t)n >= sizeof(payload)) {
		goto out;
	}
	b64url((const BYTE *)header, strlen(header), hb);
	b64url((const BYTE *)payload, strlen(payload), pb);
	n = snprintf(out, cap, "%s.%s", hb, pb);
	if (n < 0 || (size_t)n + 90 > cap) {
		goto out;
	}

	/* CNG 의 ECDSA 서명은 이미 r | s (각 32B) 다 — JWS 가 원하는 모양. */
	if (crypt_sha256((const uint8_t *)out, (size_t)n, h) < 0 ||
			NCryptSignHash(key, NULL, h, sizeof(h), sig, sizeof(sig), &len, 0) != ERROR_SUCCESS || len != 64) {
		goto out;
	}
	b64url(sig, sizeof(sig), sigb);
	n += snprintf(out + n, cap - (size_t)n, ".%s", sigb);
	ret = n;

out:
	NCryptFreeObject(key);
	return ret;
}
