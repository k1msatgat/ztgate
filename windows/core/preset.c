#include <winsock2.h>
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "preset.h"
#include "crypt.h"
#include "secure.h"
#include "device.h"

int preset_parse(const wchar_t *servers, const wchar_t *port, const wchar_t *code, preset_t *out)
{
	uint8_t id[DEVICE_ID_LEN], key[AUTH_KEY_LEN];
	int ok;

	memset(out, 0, sizeof(*out));

	if (servers[0] == L'\0') {
		return code[0] != L'\0' ? PRESET_NO_SERVER : PRESET_BAD_SERVER;
	}
	if (tunnel_check_servers(servers) < 0) {
		return PRESET_BAD_SERVER;
	}
	wcscpy_s(out->servers, TUNNEL_SERVERS_LEN, servers);

	out->port = PRESET_DEFAULT_PORT;
	if (port[0] != L'\0') {
		wchar_t *stop;
		const unsigned long v = wcstoul(port, &stop, 10);

		if (*stop != L'\0' || port[0] < L'0' || port[0] > L'9' || v == 0 || v > 65535) {
			return PRESET_BAD_PORT;
		}
		out->port = (uint16_t)v;
	}

	if (code[0] == L'\0') {
		return PRESET_OK;
	}
	/* 형식은 등록할 때 쓰는 그 함수가 본다 (글자, 길이, 줄표와 공백). */
	for (const wchar_t *c = code; *c != L'\0'; c++) {
		if (*c >= 0x80) {
			return PRESET_BAD_CODE;
		}
	}
	if (WideCharToMultiByte(CP_UTF8, 0, code, -1, out->code, (int)sizeof(out->code), NULL, NULL) == 0) {
		memset(out->code, 0, sizeof(out->code));
		return PRESET_BAD_CODE;
	}
	ok = secure_enroll_identity(out->code, id, key) == 0;
	crypt_wipe(key, sizeof(key));
	if (!ok) {
		crypt_wipe(out->code, sizeof(out->code));
		return PRESET_BAD_CODE;
	}
	return PRESET_OK;
}

/* 서버가 무엇이라 답했는가로 갈린다. 다시 해도 같은 답일 것(코드가 틀렸다, 만료됐다, 이미 쓰였다,
 * 그 주소가 서버에 있다)이면 코드를 지우고, 닿지 못했거나 어느 쪽의 일시적인 실패면 둔다. */
static const preset_step_t after_result[] = {
	[TUNNEL_ENROLL_OK]		= { PRESET_NONE, 1 },
	[TUNNEL_ENROLL_BAD_CODE]	= { PRESET_FAILED, 1 },
	[TUNNEL_ENROLL_NO_RESPONSE]	= { PRESET_WAITING, 0 },
	[TUNNEL_ENROLL_REJECTED]	= { PRESET_FAILED, 1 },
	[TUNNEL_ENROLL_CONFLICT]	= { PRESET_FAILED, 1 },
	[TUNNEL_ENROLL_SERVER_FAILED]	= { PRESET_WAITING, 0 },
	[TUNNEL_ENROLL_ERROR]		= { PRESET_WAITING, 0 },
};

preset_step_t preset_after(int device, int result)
{
	const preset_step_t skip = { PRESET_NONE, 1 };
	const preset_step_t retry = { PRESET_WAITING, 0 };

	if (device == DEVICE_OK) {
		return skip;
	}
	if (device != DEVICE_NOT_ENROLLED || result < 0 || result >= (int)(sizeof(after_result) / sizeof(after_result[0]))) {
		return retry;
	}
	return after_result[result];
}

ULONGLONG preset_retry_ms(unsigned tries)
{
	const ULONGLONG cap = 30ull * 60 * 1000;
	ULONGLONG ms = 30ull * 1000;

	for (unsigned i = 1; i < tries && ms < cap; i++) {
		ms *= 2;
	}
	return ms < cap ? ms : cap;
}

/* ---- 레지스트리 ------------------------------------------------------------- */
static int set_values(HKEY key, const preset_t *p, int with_code)
{
	const DWORD port = p->port;
	wchar_t code[PRESET_CODE_LEN];
	LSTATUS err;

	err = RegSetValueExW(key, L"servers", 0, REG_SZ, (const BYTE *)p->servers,
			(DWORD)((wcslen(p->servers) + 1) * sizeof(wchar_t)));
	if (err == ERROR_SUCCESS) {
		err = RegSetValueExW(key, L"port", 0, REG_DWORD, (const BYTE *)&port, sizeof(port));
	}
	if (err == ERROR_SUCCESS && with_code) {
		if (MultiByteToWideChar(CP_UTF8, 0, p->code, -1, code, PRESET_CODE_LEN) == 0) {
			return -1;
		}
		err = RegSetValueExW(key, L"code", 0, REG_SZ, (const BYTE *)code,
				(DWORD)((wcslen(code) + 1) * sizeof(wchar_t)));
		SecureZeroMemory(code, sizeof(code));
	}
	return err == ERROR_SUCCESS ? 0 : -1;
}

int preset_defaults_save(const preset_t *p)
{
	HKEY key;
	int ret;

	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, PRESET_REG_PATH, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) !=
			ERROR_SUCCESS) {
		return -1;
	}
	ret = set_values(key, p, 0);
	RegCloseKey(key);
	return ret;
}

int preset_enroll_save(const preset_t *p)
{
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
	HKEY key = NULL;
	int ret = -1;

	if (p->code[0] == '\0' ||
			!ConvertStringSecurityDescriptorToSecurityDescriptorW(PRESET_ENROLL_SDDL, SDDL_REVISION_1,
				&sa.lpSecurityDescriptor, NULL)) {
		return -1;
	}
	/* 키가 이미 있었으면 만들 때의 보안 설명자는 쓰이지 않는다. 값을 적기 전에 다시 건다. */
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, PRESET_ENROLL_PATH, 0, NULL, 0, KEY_SET_VALUE | WRITE_DAC, &sa,
				&key, NULL) == ERROR_SUCCESS &&
			RegSetKeySecurity(key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				sa.lpSecurityDescriptor) == ERROR_SUCCESS) {
		ret = set_values(key, p, 1);
	}
	if (key) {
		RegCloseKey(key);
	}
	LocalFree(sa.lpSecurityDescriptor);
	return ret;
}

int preset_enroll_load(preset_t *out)
{
	wchar_t servers[TUNNEL_SERVERS_LEN], port[8], code[PRESET_CODE_LEN];
	DWORD v = 0, len;
	LSTATUS err;
	int ret;

	memset(out, 0, sizeof(*out));
	len = sizeof(code);
	err = RegGetValueW(HKEY_LOCAL_MACHINE, PRESET_ENROLL_PATH, L"code", RRF_RT_REG_SZ, NULL, code, &len);
	if (err == ERROR_FILE_NOT_FOUND) {
		return 0;
	}
	if (err != ERROR_SUCCESS) {
		return -1;
	}
	len = sizeof(servers);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, PRESET_ENROLL_PATH, L"servers", RRF_RT_REG_SZ, NULL, servers, &len) !=
			ERROR_SUCCESS) {
		servers[0] = L'\0';
	}
	len = sizeof(v);
	port[0] = L'\0';
	if (RegGetValueW(HKEY_LOCAL_MACHINE, PRESET_ENROLL_PATH, L"port", RRF_RT_REG_DWORD, NULL, &v, &len) ==
			ERROR_SUCCESS) {
		swprintf(port, sizeof(port) / sizeof(port[0]), L"%lu", v);
	}

	/* 적은 쪽(preset)이 이미 봤지만, 관리자가 손으로 고칠 수도 있는 곳이다. */
	ret = preset_parse(servers, port, code, out) == PRESET_OK && out->code[0] != '\0' ? 1 : -1;
	SecureZeroMemory(code, sizeof(code));
	return ret;
}

void preset_enroll_drop(void)
{
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, PRESET_ENROLL_PATH, KEY_WOW64_64KEY, 0);
}

/* ---- selftest --------------------------------------------------------------- */
static int st(const char *name, int ok)
{
	printf("%-28s %s\n", name, ok ? "ok" : "FAIL");
	return !ok;
}

static int step_is(preset_step_t s, preset_phase_t phase, int drop)
{
	return s.phase == phase && s.drop == drop;
}

int preset_selftest(void)
{
	static const wchar_t code[] = L"7K2QF-9XWM4-ABCDE-FGHJK-MNPQR";
	preset_t p;
	int failed = 0;

	failed |= st("preset: server, port, code", preset_parse(L"vpn.example.com", L"443", code, &p) == PRESET_OK &&
			wcscmp(p.servers, L"vpn.example.com") == 0 && p.port == 443 &&
			strcmp(p.code, "7K2QF-9XWM4-ABCDE-FGHJK-MNPQR") == 0);
	failed |= st("preset: server only", preset_parse(L"a.example.com, 10.0.0.2", L"", L"", &p) == PRESET_OK &&
			p.port == PRESET_DEFAULT_PORT && p.code[0] == '\0');
	failed |= st("preset: lower case code", preset_parse(L"a", L"9000", L"7k2qf 9xwm4 abcde fghjk mnpqr", &p) == PRESET_OK);
	failed |= st("preset: code without server", preset_parse(L"", L"9000", code, &p) == PRESET_NO_SERVER);
	failed |= st("preset: nothing", preset_parse(L"", L"", L"", &p) == PRESET_BAD_SERVER);
	failed |= st("preset: bad server", preset_parse(L"vpn example!", L"9000", L"", &p) == PRESET_BAD_SERVER);
	failed |= st("preset: bad port", preset_parse(L"a", L"0", L"", &p) == PRESET_BAD_PORT &&
			preset_parse(L"a", L"65536", L"", &p) == PRESET_BAD_PORT &&
			preset_parse(L"a", L"90x", L"", &p) == PRESET_BAD_PORT &&
			preset_parse(L"a", L"-1", L"", &p) == PRESET_BAD_PORT);
	failed |= st("preset: short code", preset_parse(L"a", L"", L"7K2QF-9XWM4", &p) == PRESET_BAD_CODE &&
			p.code[0] == '\0');
	failed |= st("preset: code with U", preset_parse(L"a", L"", L"UK2QF-9XWM4-ABCDE-FGHJK-MNPQR", &p) == PRESET_BAD_CODE);
	failed |= st("preset: code not ascii", preset_parse(L"a", L"", L"7K2QF-9XWM4-ABCDE-FGHJK-MNPQ\x00c9", &p) == PRESET_BAD_CODE);

	failed |= st("preset: enrolled", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_OK), PRESET_NONE, 1));
	failed |= st("preset: already enrolled", step_is(preset_after(DEVICE_OK, TUNNEL_ENROLL_OK), PRESET_NONE, 1));
	failed |= st("preset: identity unreadable", step_is(preset_after(DEVICE_ERROR, TUNNEL_ENROLL_OK), PRESET_WAITING, 0));
	failed |= st("preset: no response", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_NO_RESPONSE), PRESET_WAITING, 0));
	failed |= st("preset: rejected", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_REJECTED), PRESET_FAILED, 1));
	failed |= st("preset: conflict", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_CONFLICT), PRESET_FAILED, 1));
	failed |= st("preset: bad code", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_BAD_CODE), PRESET_FAILED, 1));
	failed |= st("preset: server failed", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_SERVER_FAILED), PRESET_WAITING, 0));
	failed |= st("preset: local error", step_is(preset_after(DEVICE_NOT_ENROLLED, TUNNEL_ENROLL_ERROR), PRESET_WAITING, 0));
	failed |= st("preset: unknown result", step_is(preset_after(DEVICE_NOT_ENROLLED, 99), PRESET_WAITING, 0));

	failed |= st("preset: retry backoff", preset_retry_ms(1) == 30000 && preset_retry_ms(2) == 60000 &&
			preset_retry_ms(7) == 30ull * 60 * 1000 && preset_retry_ms(100) == 30ull * 60 * 1000);
	return failed;
}
