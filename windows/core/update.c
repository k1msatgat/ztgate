#include <windows.h>
#include <winhttp.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "update.h"
#include "crypt.h"
#include "json.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "version.lib")

#define MANIFEST_MAX	(16 * 1024)
#define MSI_MAX		(64 * 1024 * 1024)
#define STATE_REG_PATH	L"Software\\ztgate\\service"
#define RETRY_SAME_SEC	(24 * 3600)

/* url 을 GET 해 받은 것을 (*out, *len) 에. 2xx 가 아니면 실패. 돌려보내기는 같은 체계 안에서만 따른다
 * (WinHTTP 의 기본: https -> http 로는 가지 않는다). */
static int http_get(const wchar_t *url, int allow_http, size_t max, char **out, size_t *len)
{
	URL_COMPONENTS u;
	wchar_t host[256], path[2048];
	HINTERNET s = NULL, c = NULL, r = NULL;
	DWORD status = 0, sl = sizeof(status);
	char *buf = NULL;
	size_t n = 0;
	int ret = -1;

	memset(&u, 0, sizeof(u));
	u.dwStructSize = sizeof(u);
	u.lpszHostName = host;
	u.dwHostNameLength = sizeof(host) / sizeof(host[0]);
	u.lpszUrlPath = path;
	u.dwUrlPathLength = sizeof(path) / sizeof(path[0]);
	if (!WinHttpCrackUrl(url, 0, 0, &u) || (u.nScheme != INTERNET_SCHEME_HTTPS && !allow_http)) {
		return -1;
	}

	s = WinHttpOpen(L"ztgate-update", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	if (!s) {
		return -1;
	}
	WinHttpSetTimeouts(s, 10000, 10000, 15000, 30000);
	c = WinHttpConnect(s, host, u.nPort, 0);
	r = c ? WinHttpOpenRequest(c, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
			u.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0) : NULL;
	if (!r || !WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
			!WinHttpReceiveResponse(r, NULL) ||
			!WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX, &status, &sl, WINHTTP_NO_HEADER_INDEX) ||
			status < 200 || status >= 300) {
		goto out;
	}

	buf = malloc(max + 1);
	if (!buf) {
		goto out;
	}
	for (;;) {
		DWORD got = 0;

		if (!WinHttpReadData(r, buf + n, (DWORD)(max - n < 65536 ? max - n : 65536), &got)) {
			goto out;
		}
		if (got == 0) {
			break;
		}
		n += got;
		if (n >= max) {
			goto out;	/* 너무 크다 */
		}
	}
	buf[n] = '\0';
	*out = buf;
	*len = n;
	buf = NULL;
	ret = 0;

out:
	free(buf);
	if (r) WinHttpCloseHandle(r);
	if (c) WinHttpCloseHandle(c);
	WinHttpCloseHandle(s);
	return ret;
}

/* "0.9.1" -> 0x0000000900010000 처럼 네 칸을 16비트씩. 틀리면 0. */
static unsigned long long version_parse(const char *s)
{
	unsigned long long v = 0;
	int parts = 0;

	while (parts < 4) {
		char *end;
		unsigned long p = strtoul(s, &end, 10);

		if (end == s || p > 0xFFFF) {
			return 0;
		}
		v = v << 16 | p;
		parts++;
		if (*end == '\0') {
			break;
		}
		if (*end != '.') {
			return 0;
		}
		s = end + 1;
	}
	return v << (16 * (4 - parts));
}

static unsigned long long version_self(void)
{
	wchar_t path[MAX_PATH];
	VS_FIXEDFILEINFO *fi;
	UINT fl = 0;
	DWORD dummy, sz;
	void *data;
	unsigned long long v = 0;

	if (!GetModuleFileNameW(NULL, path, MAX_PATH) || (sz = GetFileVersionInfoSizeW(path, &dummy)) == 0) {
		return 0;
	}
	data = malloc(sz);
	if (data && GetFileVersionInfoW(path, 0, sz, data) && VerQueryValueW(data, L"\\", (void **)&fi, &fl) && fl) {
		v = (unsigned long long)fi->dwFileVersionMS << 32 | fi->dwFileVersionLS;
	}
	free(data);
	return v;
}

static int hex32(const char *s, uint8_t out[32])
{
	for (int i = 0; i < 32; i++) {
		unsigned int b;

		if (sscanf(s + 2 * i, "%2x", &b) != 1) {
			return -1;
		}
		out[i] = (uint8_t)b;
	}
	return s[64] == '\0' ? 0 : -1;
}

/* 같은 버전을 하루 안에 다시 하지 않는다. */
static int tried_recently(const char *version)
{
	char last[32] = "";
	DWORD len = sizeof(last), at = 0, al = sizeof(at);

	if (RegGetValueA(HKEY_LOCAL_MACHINE, "Software\\ztgate\\service", "update_tried", RRF_RT_REG_SZ, NULL, last, &len) != ERROR_SUCCESS ||
			RegGetValueW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, L"update_tried_at", RRF_RT_REG_DWORD, NULL, &at, &al) != ERROR_SUCCESS) {
		return 0;
	}
	return strcmp(last, version) == 0 && (DWORD)time(NULL) - at < RETRY_SAME_SEC;
}

static void mark_tried(const char *version)
{
	HKEY key;
	DWORD now = (DWORD)time(NULL);

	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) != ERROR_SUCCESS) {
		return;
	}
	RegSetValueExA(key, "update_tried", 0, REG_SZ, (const BYTE *)version, (DWORD)strlen(version) + 1);
	RegSetValueExW(key, L"update_tried_at", 0, REG_DWORD, (const BYTE *)&now, sizeof(now));
	RegCloseKey(key);
}

/* %ProgramData%\ztgate\update — SYSTEM 과 관리자만. 사용자가 받은 MSI 를 바꿔치기하지 못하게. */
static int update_dir(wchar_t *dir, size_t cap)
{
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
	wchar_t base[MAX_PATH];
	int ok;

	if (!GetEnvironmentVariableW(L"ProgramData", base, MAX_PATH)) {
		return -1;
	}
	swprintf(dir, cap, L"%ls\\ztgate", base);
	CreateDirectoryW(dir, NULL);
	swprintf(dir, cap, L"%ls\\ztgate\\update", base);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
				SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
		return -1;
	}
	ok = CreateDirectoryW(dir, &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
	if (ok) {
		/* 이미 있던 폴더의 권한도 맞춘다 (누가 먼저 만들어 두었을 수 있다). */
		SetFileSecurityW(dir, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor);
	}
	LocalFree(sa.lpSecurityDescriptor);
	return ok ? 0 : -1;
}

/* 맨 바깥 객체의 문자열 값. 없으면 -1. */
static int str_field(const char *s, const json_tok_t *t, const char *key, char *out, size_t cap)
{
	int i = json_get(s, t, 0, key);

	return i < 0 ? -1 : json_string(s, t, i, out, cap);
}

int update_check(const wchar_t *manifest_url, int allow_http, update_log_fn log)
{
	json_tok_t tok[32];
	char *man = NULL, *msi = NULL;
	size_t man_len = 0, msi_len = 0;
	char version[32], msi_url[1024], sha_hex[80];
	wchar_t wurl[1024], dir[MAX_PATH], file[MAX_PATH], cmd[2 * MAX_PATH + 64];
	uint8_t want[32], got[32];
	unsigned long long newv, mine;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE f;
	DWORD written;
	int n, ret = -1;

	if (http_get(manifest_url, allow_http, MANIFEST_MAX, &man, &man_len) < 0) {
		log("update: cannot fetch the manifest");
		return -1;
	}
	n = json_parse(man, man_len, tok, 32);
	if (n < 1 || tok[0].type != JSON_OBJECT ||
			str_field(man, tok, "version", version, sizeof(version)) < 0 ||
			str_field(man, tok, "msi", msi_url, sizeof(msi_url)) < 0 ||
			str_field(man, tok, "sha256", sha_hex, sizeof(sha_hex)) < 0 ||
			hex32(sha_hex, want) < 0 || (newv = version_parse(version)) == 0) {
		log("update: the manifest is not usable");
		goto out;
	}
	mine = version_self();
	if (newv <= mine) {
		ret = 0;
		goto out;
	}
	if (tried_recently(version)) {
		ret = 0;
		goto out;
	}

	log("update: %s is available, downloading", version);
	MultiByteToWideChar(CP_UTF8, 0, msi_url, -1, wurl, 1024);
	if (http_get(wurl, allow_http, MSI_MAX, &msi, &msi_len) < 0) {
		log("update: cannot download the installer");
		goto out;
	}
	if (crypt_sha256((const uint8_t *)msi, msi_len, got) < 0 || !crypt_equal(got, want, sizeof(got))) {
		log("update: the installer does not match the manifest's sha256, not installing");
		goto out;
	}
	if (update_dir(dir, MAX_PATH) < 0) {
		log("update: cannot prepare the update folder");
		goto out;
	}
	swprintf(file, MAX_PATH, L"%ls\\ztgate-%hs.msi", dir, version);
	f = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE || !WriteFile(f, msi, (DWORD)msi_len, &written, NULL) || written != msi_len) {
		if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
		log("update: cannot write the installer");
		goto out;
	}
	CloseHandle(f);

	/* msiexec 는 따로 돈다. MSI 가 이 서비스를 멈추고 새 것으로 다시 띄운다. */
	mark_tried(version);
	swprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"msiexec.exe /i \"%ls\" /qn /norestart /l*v \"%ls.log\"", file, file);
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		log("update: cannot start msiexec (%lu)", GetLastError());
		goto out;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	log("update: installing %s", version);
	ret = 1;

out:
	free(man);
	free(msi);
	return ret;
}
