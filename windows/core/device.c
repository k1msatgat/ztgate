#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "device.h"
#include "secure.h"
#include "tpm.h"

/* GUI 의 연결 설정(HKCU\Software\ztgate\vpn_gui)과 같은 뿌리 아래에 둔다.
 * 콘솔 클라이언트와 GUI 가 같은 신원을 쓰도록 프로그램 이름 아래가 아니라 옆에 둔다. */
#define DEVICE_REG_PATH	L"Software\\ztgate\\device"
#define DEVICE_REG_ID	L"id"
#define DEVICE_REG_KEY	L"key"
#define DEVICE_REG_SERVER_PUB	L"server_pub"
#define DEVICE_REG_TPM		L"tpm_key"	/* TPM 키의 이름. 있으면 key 는 없다 */

/* 신원을 두는 곳. 기본은 지금 로그온한 사용자의 것(HKCU)이다. 서비스는 사용자가 아니라
 * 시스템 계정으로 돌고, 로그온한 사람이 없을 때에도 터널을 열어야 하므로 PC 의 것(HKLM)
 * 을 쓴다. 그때 키는 시스템 계정의 DPAPI 로 감싸인다 — 레지스트리의 값은 일반 사용자도
 * 읽을 수 있지만 풀 수 있는 것은 시스템 계정으로 도는 프로세스뿐이다. 사용자 계정에
 * 둘 때의 "같은 사용자로 도는 다른 프로세스가 키를 풀 수 있다"가 여기서는 없다. */
static HKEY device_root = HKEY_CURRENT_USER;

void device_use_machine_store(void)
{
	device_root = HKEY_LOCAL_MACHINE;
}

int device_machine_store(void)
{
	return device_root == HKEY_LOCAL_MACHINE;
}

/* TPM 의 비밀키와 서버 공개키로 기기 키를 뽑는다 (secure_static_key 와 같은 값). */
static int tpm_device_key(device_t *dev)
{
	uint8_t pub[VPN_PUB_LEN], secret[VPN_SECRET_LEN];
	int ret = -1;

	if (!dev->has_server_pub ||
			tpm_public(device_machine_store(), dev->tpm_name, pub) < 0 ||
			tpm_ecdh(device_machine_store(), dev->tpm_name, dev->server_pub, secret) < 0) {
		return -1;
	}
	ret = secure_static_key_from_secret(secret, pub, dev->server_pub, dev->key);
	crypt_wipe(secret, sizeof(secret));
	return ret;
}

int device_tpm_begin(device_t *dev, uint8_t pub[VPN_PUB_LEN_WIRE])
{
	uint8_t r[4];

	if (!tpm_available() || crypt_random(r, sizeof(r)) < 0) {
		return -1;
	}
	swprintf(dev->tpm_name, sizeof(dev->tpm_name) / sizeof(dev->tpm_name[0]), L"%ls-%02x%02x%02x%02x",
			TPM_KEY_NAME, r[0], r[1], r[2], r[3]);
	if (tpm_create(device_machine_store(), dev->tpm_name, pub) < 0) {
		dev->tpm_name[0] = L'\0';
		return -1;
	}
	dev->tpm = 1;
	return 0;
}

int device_tpm_finish(device_t *dev, int ok)
{
	if (!dev->tpm) {
		return 0;
	}
	if (ok && tpm_device_key(dev) == 0) {
		return 0;
	}
	tpm_delete(device_machine_store(), dev->tpm_name);
	dev->tpm = 0;
	dev->tpm_name[0] = L'\0';
	return ok ? -1 : 0;
}

/* 키를 레지스트리에 그대로 쓰면 그 하이브를 읽을 수 있는 누구나(백업 파일, 다른
 * 계정의 관리자, 디스크를 떼어 간 사람) 키를 얻는다. DPAPI(CryptProtectData)는
 * 현재 사용자의 로그온 자격 증명에서 유도한 키로 암호화하므로, 저장된 값은 같은
 * PC 의 같은 사용자로 로그온해야만 풀린다. 키 관리(어디에 암호화 키를 둘 것인가)를
 * OS 에 맡기는 것이다.
 *
 * 막지 못하는 것: 같은 사용자로 도는 다른 프로세스는 똑같이 CryptUnprotectData 를
 * 부를 수 있다. 그것까지 막으려면 TPM 에 키를 두고 꺼낼 수 없게 해야 한다. */
static int key_protect(const uint8_t *key, DATA_BLOB *sealed)
{
	DATA_BLOB plain;

	plain.pbData = (BYTE *)key;
	plain.cbData = AUTH_KEY_LEN;

	/* 이 프로그램은 서비스나 워커 스레드에서도 돌 수 있어 UI 를 띄우면 안 된다. */
	if (!CryptProtectData(&plain, L"ztgate device key", NULL, NULL, NULL,
			CRYPTPROTECT_UI_FORBIDDEN, sealed)) {
		return -1;
	}

	return 0;
}

static int key_unprotect(const BYTE *sealed, DWORD sealed_len, uint8_t *key)
{
	DATA_BLOB in;
	DATA_BLOB plain;
	int ret = -1;

	in.pbData = (BYTE *)sealed;
	in.cbData = sealed_len;

	if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
			CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
		return -1;
	}

	if (plain.cbData == AUTH_KEY_LEN) {
		memcpy(key, plain.pbData, AUTH_KEY_LEN);
		ret = 0;
	}

	/* 평문 키가 해제된 힙에 남지 않게 지우고 돌려준다. 컴파일러가 "곧 해제될
	 * 메모리"에 대한 memset 을 최적화로 없앨 수 있어 SecureZeroMemory 를 쓴다. */
	SecureZeroMemory(plain.pbData, plain.cbData);
	LocalFree(plain.pbData);

	return ret;
}

int device_load(device_t *out)
{
	BYTE sealed[1024];
	DWORD len;
	LSTATUS err;

	memset(out, 0, sizeof(*out));

	len = sizeof(out->id);
	err = RegGetValueW(device_root, DEVICE_REG_PATH, DEVICE_REG_ID,
			RRF_RT_REG_BINARY, NULL, out->id, &len);
	if (err == ERROR_FILE_NOT_FOUND) {
		return DEVICE_NOT_ENROLLED;
	}
	if (err != ERROR_SUCCESS || len != sizeof(out->id)) {
		return DEVICE_ERROR;
	}

	/* TPM 신원이면 기기 키는 아래에서 서버 공개키를 읽은 뒤 TPM 으로 뽑는다. */
	len = sizeof(out->tpm_name);
	if (RegGetValueW(device_root, DEVICE_REG_PATH, DEVICE_REG_TPM, RRF_RT_REG_SZ, NULL,
				out->tpm_name, &len) == ERROR_SUCCESS && out->tpm_name[0] != L'\0') {
		out->tpm = 1;
	}
	else {
		len = sizeof(sealed);
		err = RegGetValueW(device_root, DEVICE_REG_PATH, DEVICE_REG_KEY,
				RRF_RT_REG_BINARY, NULL, sealed, &len);
		if (err != ERROR_SUCCESS) {
			return DEVICE_ERROR;
		}

		if (key_unprotect(sealed, len, out->key) < 0) {
			return DEVICE_ERROR;
		}
	}

	/* 없으면 고정하지 않는다 (손으로 올린 기기, v9 이전에 등록한 기기). */
	len = sizeof(out->server_pub);
	err = RegGetValueW(device_root, DEVICE_REG_PATH, DEVICE_REG_SERVER_PUB,
			RRF_RT_REG_BINARY, NULL, out->server_pub, &len);
	if (err == ERROR_SUCCESS && len == sizeof(out->server_pub)) {
		out->has_server_pub = 1;
	}
	else if (err != ERROR_FILE_NOT_FOUND) {
		SecureZeroMemory(out, sizeof(*out));
		return DEVICE_ERROR;
	}

	/* TPM 이 지워졌거나(초기화, 메인보드 교체) 키가 없어졌으면 이 신원은 더 쓸 수 없다. 다시 등록한다. */
	if (out->tpm && tpm_device_key(out) < 0) {
		SecureZeroMemory(out, sizeof(*out));
		return DEVICE_ERROR;
	}

	return DEVICE_OK;
}

int device_generate(device_t *out)
{
	/* rand() 는 쓸 수 없다. 시드와 출력 몇 개로 다음 값을 맞힐 수 있는 생성기라
	 * 키가 예측된다. OS 의 암호학적 난수 생성기를 쓴다. */
	memset(out, 0, sizeof(*out));
	return BCRYPT_SUCCESS(BCryptGenRandom(NULL, out->id, sizeof(out->id), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
		BCRYPT_SUCCESS(BCryptGenRandom(NULL, out->key, sizeof(out->key), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ?
		DEVICE_OK : DEVICE_ERROR;
}

int device_save(const device_t *dev)
{
	DATA_BLOB sealed = { 0 };
	wchar_t old_tpm[40] = L"";
	DWORD old_len = sizeof(old_tpm);
	HKEY reg = NULL;
	int ret = DEVICE_ERROR;

	/* TPM 신원은 기기 키를 디스크에 두지 않는다. */
	if (!dev->tpm && key_protect(dev->key, &sealed) < 0) {
		goto out;
	}
	/* 갈아 치우는 신원이 쓰던 TPM 키는 저장이 끝난 뒤 지운다. */
	RegGetValueW(device_root, DEVICE_REG_PATH, DEVICE_REG_TPM, RRF_RT_REG_SZ, NULL, old_tpm, &old_len);

	if (RegCreateKeyExW(device_root, DEVICE_REG_PATH, 0, NULL, 0,
			KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &reg, NULL) != ERROR_SUCCESS) {
		goto out;
	}

	if (RegSetValueExW(reg, DEVICE_REG_ID, 0, REG_BINARY,
				dev->id, sizeof(dev->id)) != ERROR_SUCCESS) {
		goto out;
	}
	if (dev->tpm) {
		if (RegSetValueExW(reg, DEVICE_REG_TPM, 0, REG_SZ, (const BYTE *)dev->tpm_name,
					(DWORD)((wcslen(dev->tpm_name) + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
			goto out;
		}
		RegDeleteValueW(reg, DEVICE_REG_KEY);
	}
	else {
		if (RegSetValueExW(reg, DEVICE_REG_KEY, 0, REG_BINARY,
					sealed.pbData, sealed.cbData) != ERROR_SUCCESS) {
			goto out;
		}
		RegDeleteValueW(reg, DEVICE_REG_TPM);
	}
	/* 새 신원에 서버 공개키가 없으면 예전 신원의 것을 남기지 않는다. */
	if (dev->has_server_pub) {
		if (RegSetValueExW(reg, DEVICE_REG_SERVER_PUB, 0, REG_BINARY,
					dev->server_pub, sizeof(dev->server_pub)) != ERROR_SUCCESS) {
			goto out;
		}
	}
	else {
		LSTATUS err = RegDeleteValueW(reg, DEVICE_REG_SERVER_PUB);

		if (err != ERROR_SUCCESS && err != ERROR_FILE_NOT_FOUND) {
			goto out;
		}
	}

	ret = DEVICE_OK;
	if (old_tpm[0] != L'\0' && (!dev->tpm || wcscmp(old_tpm, dev->tpm_name) != 0)) {
		tpm_delete(device_machine_store(), old_tpm);
	}

out:
	if (reg) {
		RegCloseKey(reg);
	}
	if (sealed.pbData) {
		LocalFree(sealed.pbData);
	}

	return ret;
}

int device_enroll(device_t *out)
{
	if (device_generate(out) != DEVICE_OK || device_save(out) != DEVICE_OK) {
		SecureZeroMemory(out, sizeof(*out));
		return DEVICE_ERROR;
	}

	return DEVICE_OK;
}
