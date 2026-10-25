#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "update.h"
#include "crypt.h"
#include "json.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")

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

/* 정확히 2n 글자의 16진수 -> n 바이트. */
static int hex_bytes(const char *s, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < 2 * n; i++) {
		if (!isxdigit((unsigned char)s[i])) {
			return -1;
		}
	}
	if (s[2 * n] != '\0') {
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		unsigned int b;

		sscanf(s + 2 * i, "%2x", &b);
		out[i] = (uint8_t)b;
	}
	return 0;
}

/* ECDSA P-256 / SHA-256, 서명은 r | s (CNG 의 형식 그대로). 곡선 위의 점이 아닌 공개키는 가져오기에서 걸린다. */
static int p256_verify(const uint8_t pub[UPDATE_PUB_LEN], const uint8_t *msg, size_t len, const uint8_t sig[64])
{
	struct { BCRYPT_ECCKEY_BLOB h; uint8_t xy[UPDATE_PUB_LEN]; } blob;
	BCRYPT_ALG_HANDLE alg = NULL;
	BCRYPT_KEY_HANDLE key = NULL;
	uint8_t hash[32];
	int ok = 0;

	if (crypt_sha256(msg, len, hash) < 0) {
		return 0;
	}
	blob.h.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
	blob.h.cbKey = 32;
	memcpy(blob.xy, pub, UPDATE_PUB_LEN);
	if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) &&
			BCRYPT_SUCCESS(BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &key, (PUCHAR)&blob, sizeof(blob), 0)) &&
			BCRYPT_SUCCESS(BCryptVerifySignature(key, NULL, hash, sizeof(hash), (PUCHAR)sig, 64, 0))) {
		ok = 1;
	}
	if (key) BCryptDestroyKey(key);
	if (alg) BCryptCloseAlgorithmProvider(alg, 0);
	return ok;
}

int update_verify(const char *version, const char *sha_hex, const char *sig_hex,
		const uint8_t (*keys)[UPDATE_PUB_LEN], int n_keys)
{
	static const char label[] = "ztgate update v1\n";
	char msg[sizeof(label) + 32 + 1 + 64];
	uint8_t sig[64];
	int n, i;

	if (hex_bytes(sig_hex, sig, sizeof(sig)) < 0) {
		return 0;
	}
	n = snprintf(msg, sizeof(msg), "%s%s\n%s", label, version, sha_hex);
	if (n < 0 || (size_t)n >= sizeof(msg)) {
		return 0;
	}
	for (i = 0; i < n_keys; i++) {
		if (p256_verify(keys[i], (const uint8_t *)msg, (size_t)n, sig)) {
			return 1;
		}
	}
	return 0;
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

int update_check(const wchar_t *manifest_url, int allow_http, const uint8_t (*keys)[UPDATE_PUB_LEN], int n_keys,
		update_log_fn log)
{
	json_tok_t tok[32];
	char *man = NULL, *msi = NULL;
	size_t man_len = 0, msi_len = 0;
	char version[32], msi_url[1024], sha_hex[80], sig_hex[160];
	wchar_t wurl[1024], dir[MAX_PATH], file[MAX_PATH], cmd[2 * MAX_PATH + 64];
	uint8_t want[32], got[32];
	unsigned long long newv, mine;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE f;
	DWORD written;
	int n, ret = -1;

	if (n_keys <= 0) {
		log("update: no usable UpdatePublicKey policy (missing or not 128 hex), not updating");
		return -1;
	}
	if (http_get(manifest_url, allow_http, MANIFEST_MAX, &man, &man_len) < 0) {
		log("update: cannot fetch the manifest");
		return -1;
	}
	n = json_parse(man, man_len, tok, 32);
	if (n < 1 || tok[0].type != JSON_OBJECT ||
			str_field(man, tok, "version", version, sizeof(version)) < 0 ||
			str_field(man, tok, "msi", msi_url, sizeof(msi_url)) < 0 ||
			str_field(man, tok, "sha256", sha_hex, sizeof(sha_hex)) < 0 ||
			hex_bytes(sha_hex, want, sizeof(want)) < 0 || (newv = version_parse(version)) == 0) {
		log("update: the manifest is not usable");
		goto out;
	}
	/* 서명부터 본다. 맞지 않는 매니페스트는 버전도 믿지 않는다. */
	if (str_field(man, tok, "sig", sig_hex, sizeof(sig_hex)) < 0 ||
			!update_verify(version, sha_hex, sig_hex, keys, n_keys)) {
		log("update: the manifest is not signed by an UpdatePublicKey key, ignoring it");
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

/* ---- selftest ---------------------------------------------------------------
 * tools/update/ztgate_update_sign.py 가 만든 매니페스트다 (openssl 로 서명). 여기서 CNG 로 맞으면 도구와
 * 서비스가 같은 것에 서명하고 확인한다는 뜻이다. */

static const char st_pub_a[] =
	"ac8ae8b75a48ca50ab3785aeb2a2e218c26e2be85f9c817f4f53677f1e4919eb"
	"8c14fa3ab8fd698137a80e0f5c2c866ed2bcfa7b9f0fc623be7317ea27b28fa1";
static const char st_pub_b[] =		/* 다른 키 */
	"c5d7edabe824dca9cf0ddff3eca9e0306f55d464407f165967b6adfac179cab4"
	"0843b5ba92bf12a71092199667e589c15eca601bd0dbd4dc10bb7120bce85ee0";
static const char st_sha[] = "3a03ad80fb48b7ca3d5b51e735aca8c2694c6043e3d6cefa75cfd63cb89d2da0";
static const char st_sig[] =
	"750d542b9acdbce4cb914a148a444a746e22db6e32081d761211b1032f538127"
	"f1117e05adcacb943a9e91eb4fc3d9983e546220de722873e972f2a2bc64efbe";

static int st_report(const char *name, int ok)
{
	printf("%-28s %s\n", name, ok ? "ok" : "FAIL");
	return !ok;
}

int update_selftest(void)
{
	uint8_t k[3][UPDATE_PUB_LEN];	/* a, b, a — k + 1 부터 둘이면 [b, a] */
	const uint8_t (*keys)[UPDATE_PUB_LEN] = (const uint8_t (*)[UPDATE_PUB_LEN])k;
	char sha[sizeof(st_sha)], sig[sizeof(st_sig)];
	int failed = 0;

	hex_bytes(st_pub_a, k[0], UPDATE_PUB_LEN);
	hex_bytes(st_pub_b, k[1], UPDATE_PUB_LEN);
	memcpy(k[2], k[0], UPDATE_PUB_LEN);

	failed |= st_report("update: signed manifest", update_verify("0.9.3", st_sha, st_sig, keys, 1) == 1);
	failed |= st_report("update: another version", update_verify("0.9.4", st_sha, st_sig, keys, 1) == 0);
	memcpy(sha, st_sha, sizeof(sha));
	sha[63] = sha[63] == '0' ? '1' : '0';
	failed |= st_report("update: another installer", update_verify("0.9.3", sha, st_sig, keys, 1) == 0);
	memcpy(sig, st_sig, sizeof(sig));
	sig[10] = sig[10] == '0' ? '1' : '0';
	failed |= st_report("update: altered signature", update_verify("0.9.3", st_sha, sig, keys, 1) == 0);
	failed |= st_report("update: short signature", update_verify("0.9.3", st_sha, "abcd", keys, 1) == 0);
	failed |= st_report("update: another key", update_verify("0.9.3", st_sha, st_sig, keys + 1, 1) == 0);
	failed |= st_report("update: second of two keys", update_verify("0.9.3", st_sha, st_sig, keys + 1, 2) == 1);
	failed |= st_report("update: no key", update_verify("0.9.3", st_sha, st_sig, keys, 0) == 0);
	return failed;
}
