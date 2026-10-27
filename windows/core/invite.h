#ifndef ZTGATE_INVITE_H
#define ZTGATE_INVITE_H

/* 초대 링크: ztgate://enroll?server=vpn.example.com&port=9000&code=7K2QF-9XWM4-...
 *
 * 관리 도구(ztgate_ctl 의 enroll_create, 웹 콘솔)가 서버의 server.env 에 적힌 PUBLIC_ADDRESS 로
 * 만들어 준다. 사용자는 메일이나 메신저로 받은 링크를 누르거나(MSI 가 ztgate: 를 GUI 에 묶는다)
 * 등록 창에 붙여 넣는다. 서버 주소와 포트를 따로 받아 적지 않아도 된다.
 *
 * 링크에는 코드가 그대로 들어 있다 — 코드와 같은 비밀이고, 한 번 쓰이면 끝난다. */

#include "tunnel.h"

typedef struct invite {
	wchar_t servers[TUNNEL_SERVERS_LEN];	/* tunnel_check_servers 를 통과한 글자 */
	uint16_t port;
	char code[64];				/* 코어가 형식을 다시 본다 (secure_enroll_identity) */
} invite_t;

static __inline int invite_hex(wchar_t c)
{
	if (c >= L'0' && c <= L'9') {
		return c - L'0';
	}
	if (c >= L'a' && c <= L'f') {
		return c - L'a' + 10;
	}
	if (c >= L'A' && c <= L'F') {
		return c - L'A' + 10;
	}
	return -1;
}

/* 값 하나의 %XX 를 풀어 UTF-8 로 모은 뒤 넓은 글자로. 0 성공. */
static __inline int invite_value(const wchar_t *s, size_t n, wchar_t *out, size_t cap)
{
	char bytes[TUNNEL_SERVERS_LEN * 3];
	size_t m = 0;

	for (size_t i = 0; i < n; i++) {
		int hi, lo;

		if (m + 1 >= sizeof(bytes)) {
			return -1;
		}
		if (s[i] == L'%' && i + 2 < n &&
				(hi = invite_hex(s[i + 1])) >= 0 && (lo = invite_hex(s[i + 2])) >= 0) {
			bytes[m++] = (char)(hi * 16 + lo);
			i += 2;
		}
		else if (s[i] < 0x80) {
			bytes[m++] = s[i] == L'+' ? ' ' : (char)s[i];
		}
		else {
			return -1;	/* 링크는 ASCII 다. 국제 도메인은 %XX 로 온다 */
		}
	}
	bytes[m] = '\0';
	return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, -1, out, (int)cap) > 0 ? 0 : -1;
}

/* link 를 풀어 out 에. 셋(server, port, code)이 모두 있고 맞으면 0. 대소문자는 가리지 않는다 —
 * 등록 창의 칸은 적은 것을 대문자로 바꾼다. */
static __inline int invite_parse(const wchar_t *link, invite_t *out)
{
	static const wchar_t prefix[] = L"ztgate://enroll?";
	const size_t plen = sizeof(prefix) / sizeof(prefix[0]) - 1;
	const wchar_t *p;
	int have = 0;

	memset(out, 0, sizeof(*out));
	while (*link == L' ' || *link == L'"') {
		link++;
	}
	if (_wcsnicmp(link, prefix, plen) != 0) {
		return -1;
	}
	for (p = link + plen; *p != L'\0' && *p != L'"' && *p != L' ' && *p != L'#';) {
		const wchar_t *eq = p, *end;
		wchar_t value[TUNNEL_SERVERS_LEN];

		while (*eq != L'=' && *eq != L'&' && *eq != L'\0' && *eq != L'"' && *eq != L' ' && *eq != L'#') {
			eq++;
		}
		if (*eq != L'=') {
			return -1;
		}
		for (end = eq + 1; *end != L'&' && *end != L'\0' && *end != L'"' && *end != L' ' && *end != L'#'; end++) {
		}
		if (invite_value(eq + 1, (size_t)(end - eq - 1), value, TUNNEL_SERVERS_LEN) < 0) {
			return -1;
		}

		if (eq - p == 6 && _wcsnicmp(p, L"server", 6) == 0) {
			if (tunnel_check_servers(value) < 0) {
				return -1;
			}
			wcscpy_s(out->servers, TUNNEL_SERVERS_LEN, value);
			have |= 1;
		}
		else if (eq - p == 4 && _wcsnicmp(p, L"port", 4) == 0) {
			wchar_t *stop;
			const unsigned long v = wcstoul(value, &stop, 10);

			if (*stop != L'\0' || v == 0 || v > 65535) {
				return -1;
			}
			out->port = (uint16_t)v;
			have |= 2;
		}
		else if (eq - p == 4 && _wcsnicmp(p, L"code", 4) == 0) {
			if (value[0] == L'\0' || WideCharToMultiByte(CP_UTF8, 0, value, -1, out->code,
						(int)sizeof(out->code), NULL, NULL) == 0) {
				return -1;
			}
			have |= 4;
		}
		/* 모르는 이름은 건너뛴다 (뒤의 버전이 더할 수 있다). */
		p = *end == L'&' ? end + 1 : end;
	}
	return have == 7 ? 0 : -1;
}

/* 링크처럼 보이는가 (대소문자 무시). 붙여 넣은 칸이 코드인지 링크인지 가를 때 쓴다. */
static __inline int invite_like(const wchar_t *s)
{
	while (*s == L' ' || *s == L'"') {
		s++;
	}
	return _wcsnicmp(s, L"ztgate:", 7) == 0;
}

#endif
