#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <string.h>

#include "tpm.h"

#pragma comment(lib, "ncrypt.lib")

/* BCRYPT_ECCKEY_BLOB 와 X | Y (P-256). */
typedef struct tpm_pub_blob {
	BCRYPT_ECCKEY_BLOB head;
	uint8_t xy[VPN_PUB_LEN];
} tpm_pub_blob_t;

static NCRYPT_PROV_HANDLE open_provider(void)
{
	NCRYPT_PROV_HANDLE prov = 0;

	if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) {
		return 0;
	}
	return prov;
}

int tpm_available(void)
{
	NCRYPT_PROV_HANDLE prov = open_provider();

	if (!prov) {
		return 0;
	}
	NCryptFreeObject(prov);
	return 1;
}

static int export_pub(NCRYPT_KEY_HANDLE key, uint8_t pub[VPN_PUB_LEN])
{
	tpm_pub_blob_t blob;
	DWORD len = 0;

	if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, (PBYTE)&blob, sizeof(blob), &len, 0) != ERROR_SUCCESS ||
			len != sizeof(blob) || blob.head.cbKey != VPN_PUB_LEN / 2) {
		return -1;
	}
	memcpy(pub, blob.xy, VPN_PUB_LEN);
	return 0;
}

static NCRYPT_KEY_HANDLE open_key(NCRYPT_PROV_HANDLE prov, int machine, const wchar_t *name)
{
	NCRYPT_KEY_HANDLE key = 0;

	if (NCryptOpenKey(prov, &key, name, 0, machine ? NCRYPT_MACHINE_KEY_FLAG : 0) != ERROR_SUCCESS) {
		return 0;
	}
	return key;
}

void tpm_delete(int machine, const wchar_t *name)
{
	NCRYPT_PROV_HANDLE prov = open_provider();
	NCRYPT_KEY_HANDLE key;

	if (!prov) {
		return;
	}
	key = open_key(prov, machine, name);
	if (key) {
		NCryptDeleteKey(key, 0);	/* 성공하면 핸들도 풀린다 */
	}
	NCryptFreeObject(prov);
}

int tpm_create(int machine, const wchar_t *name, uint8_t pub[VPN_PUB_LEN])
{
	NCRYPT_PROV_HANDLE prov;
	NCRYPT_KEY_HANDLE key = 0;
	int ret = -1;

	tpm_delete(machine, name);
	prov = open_provider();
	if (!prov) {
		return -1;
	}
	/* 내보내기 정책을 주지 않는다 — 기본값이 "내보낼 수 없음"이다. */
	if (NCryptCreatePersistedKey(prov, &key, BCRYPT_ECDH_P256_ALGORITHM, name, 0,
				machine ? NCRYPT_MACHINE_KEY_FLAG : 0) != ERROR_SUCCESS ||
			NCryptFinalizeKey(key, 0) != ERROR_SUCCESS ||
			export_pub(key, pub) < 0) {
		if (key) {
			NCryptDeleteKey(key, 0);
			key = 0;
		}
		goto out;
	}
	ret = 0;

out:
	if (key) {
		NCryptFreeObject(key);
	}
	NCryptFreeObject(prov);
	return ret;
}

int tpm_public(int machine, const wchar_t *name, uint8_t pub[VPN_PUB_LEN])
{
	NCRYPT_PROV_HANDLE prov = open_provider();
	NCRYPT_KEY_HANDLE key;
	int ret = -1;

	if (!prov) {
		return -1;
	}
	key = open_key(prov, machine, name);
	if (key) {
		ret = export_pub(key, pub);
		NCryptFreeObject(key);
	}
	NCryptFreeObject(prov);
	return ret;
}

int tpm_ecdh(int machine, const wchar_t *name, const uint8_t peer_pub[VPN_PUB_LEN],
		uint8_t secret[VPN_SECRET_LEN])
{
	NCRYPT_PROV_HANDLE prov = open_provider();
	NCRYPT_KEY_HANDLE key = 0, peer = 0;
	NCRYPT_SECRET_HANDLE agreed = 0;
	BCryptBuffer param;
	BCryptBufferDesc params;
	tpm_pub_blob_t blob;
	uint8_t raw[VPN_PUB_LEN / 2];
	DWORD len = 0;
	int ret = -1;

	if (!prov) {
		return -1;
	}
	key = open_key(prov, machine, name);
	if (!key) {
		goto out;
	}

	blob.head.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
	blob.head.cbKey = VPN_PUB_LEN / 2;
	memcpy(blob.xy, peer_pub, VPN_PUB_LEN);
	if (NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &peer, (PBYTE)&blob, sizeof(blob), 0) != ERROR_SUCCESS ||
			NCryptSecretAgreement(key, peer, &agreed, 0) != ERROR_SUCCESS) {
		goto out;
	}

	/* crypt.c 와 같이 SHA-256(X). TPM 공급자가 해시 KDF 를 하지 못하면 날것의 값(작은 끝부터 온다)을
	 * 받아 뒤집어 우리가 해시한다. */
	param.cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM);
	param.BufferType = KDF_HASH_ALGORITHM;
	param.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = 1;
	params.pBuffers = &param;
	if (NCryptDeriveKey(agreed, BCRYPT_KDF_HASH, &params, secret, VPN_SECRET_LEN, &len, 0) == ERROR_SUCCESS &&
			len == VPN_SECRET_LEN) {
		ret = 0;
		goto out;
	}
	if (NCryptDeriveKey(agreed, BCRYPT_KDF_RAW_SECRET, NULL, raw, sizeof(raw), &len, 0) == ERROR_SUCCESS &&
			len == sizeof(raw)) {
		for (int i = 0; i < (int)sizeof(raw) / 2; i++) {
			uint8_t t = raw[i];

			raw[i] = raw[sizeof(raw) - 1 - i];
			raw[sizeof(raw) - 1 - i] = t;
		}
		ret = crypt_sha256(raw, sizeof(raw), secret) < 0 ? -1 : 0;
		crypt_wipe(raw, sizeof(raw));
	}

out:
	if (agreed) NCryptFreeObject(agreed);
	if (peer) NCryptFreeObject(peer);
	if (key) NCryptFreeObject(key);
	NCryptFreeObject(prov);
	return ret;
}

int tpm_selftest(void)
{
	static const wchar_t name[] = L"ztgate-selftest";
	uint8_t tpm_pub[VPN_PUB_LEN], sw_pub[VPN_PUB_LEN];
	uint8_t a[VPN_SECRET_LEN], b[VPN_SECRET_LEN];
	crypt_ecdh_t *sw;
	int ret = -1;

	if (!tpm_available()) {
		return 1;
	}
	if (tpm_create(0, name, tpm_pub) < 0) {
		return -1;
	}
	sw = crypt_ecdh_new(sw_pub);
	if (sw && tpm_ecdh(0, name, sw_pub, a) == 0 && crypt_ecdh_derive(sw, tpm_pub, b) == 0 &&
			crypt_equal(a, b, sizeof(a))) {
		ret = 0;
	}
	crypt_ecdh_free(sw);
	tpm_delete(0, name);
	return ret;
}
