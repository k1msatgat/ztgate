#include "framework.h"
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <time.h>
#include <map>
#include <vector>

#include "Oidc.h"

/* 서버가 JWT 와 JWKS 를 읽는 것과 같은 파서를 쓴다. 문법을 엄격하게 보고 메모리를 따로
 * 잡지 않는다 (server/include/json.h). */
extern "C" {
#include "json.h"
}

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#endif

namespace oidc {
namespace {

const ULONGLONG LOGIN_WAIT_MS = 5 * 60 * 1000;	/* 사람이 브라우저에서 로그인을 마치는 데 */
const int HTTP_TIMEOUT_MS = 10000;
const size_t HTTP_BODY_MAX = 256 * 1024;	/* 설정 문서와 토큰 응답은 수 KB 다 */
const int JSON_TOKENS = 4096;			/* Keycloak 의 설정 문서가 천 개 남짓 */
const char CALLBACK_PATH[] = "/callback";

/* ---- 글자 ------------------------------------------------------------------ */
std::string Utf8(const CString &s)
{
	const int n = WideCharToMultiByte(CP_UTF8, 0, s, s.GetLength(), nullptr, 0, nullptr, nullptr);
	std::string out(n > 0 ? n : 0, '\0');

	if (n > 0) {
		WideCharToMultiByte(CP_UTF8, 0, s, s.GetLength(), &out[0], n, nullptr, nullptr);
	}

	return out;
}

std::wstring Wide(const std::string &s)
{
	const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
	std::wstring out(n > 0 ? n : 0, L'\0');

	if (n > 0) {
		MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n);
	}

	return out;
}

CString WideC(const std::string &s)
{
	return CString(Wide(s).c_str());
}

std::string StripSlash(std::string s)
{
	while (!s.empty() && s.back() == '/') {
		s.pop_back();
	}

	return s;
}

bool Unreserved(unsigned char ch)
{
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
		ch == '-' || ch == '.' || ch == '_' || ch == '~';
}

std::string Encode(const std::string &s)
{
	static const char hex[] = "0123456789ABCDEF";
	std::string out;

	for (unsigned char ch : s) {
		if (Unreserved(ch)) {
			out += (char)ch;
		}
		else {
			out += '%';
			out += hex[ch >> 4];
			out += hex[ch & 15];
		}
	}

	return out;
}

int HexValue(char ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

std::string Decode(const std::string &s)
{
	std::string out;

	for (size_t i = 0; i < s.size(); i++) {
		if (s[i] == '+') {
			out += ' ';
		}
		else if (s[i] == '%' && i + 2 < s.size() && HexValue(s[i + 1]) >= 0 && HexValue(s[i + 2]) >= 0) {
			out += (char)(HexValue(s[i + 1]) * 16 + HexValue(s[i + 2]));
			i += 2;
		}
		else {
			out += s[i];
		}
	}

	return out;
}

/* "a=1&b=2" -> {a: 1, b: 2}. 같은 이름이 두 번 오면 처음 것을 쓴다. */
std::map<std::string, std::string> Query(const std::string &qs)
{
	std::map<std::string, std::string> out;
	size_t start = 0;

	while (start <= qs.size()) {
		size_t end = qs.find('&', start);
		if (end == std::string::npos) {
			end = qs.size();
		}

		const std::string pair = qs.substr(start, end - start);
		const size_t eq = pair.find('=');
		if (!pair.empty()) {
			out.emplace(Decode(pair.substr(0, eq)), eq == std::string::npos ? std::string() : Decode(pair.substr(eq + 1)));
		}
		start = end + 1;
	}

	return out;
}

void Wipe(std::string &s)
{
	if (!s.empty()) {
		SecureZeroMemory(&s[0], s.size());
	}
	s.clear();
}

/* ---- 주소 ------------------------------------------------------------------ */
struct Url {
	bool https;
	std::wstring host;
	INTERNET_PORT port;
	std::wstring path;	/* 질의까지 */
};

bool Loopback(const std::wstring &host)
{
	return host == L"127.0.0.1" || host == L"[::1]" || _wcsicmp(host.c_str(), L"localhost") == 0;
}

/* 토큰과 코드가 오가는 주소다. https 만 받는다 — 평문 http 면 같은 망의 누구나 토큰을
 * 가져간다. 이 PC 안(127.0.0.1)은 예외로 둔다 (시험용 IdP). */
bool ParseUrl(const std::string &url, Url *u)
{
	const std::wstring w = Wide(url);
	URL_COMPONENTS c;

	ZeroMemory(&c, sizeof(c));
	c.dwStructSize = sizeof(c);
	c.dwSchemeLength = (DWORD)-1;
	c.dwHostNameLength = (DWORD)-1;
	c.dwUrlPathLength = (DWORD)-1;
	c.dwExtraInfoLength = (DWORD)-1;

	if (w.empty() || !WinHttpCrackUrl(w.c_str(), (DWORD)w.size(), 0, &c)) {
		return false;
	}
	if (c.nScheme != INTERNET_SCHEME_HTTPS && c.nScheme != INTERNET_SCHEME_HTTP) {
		return false;
	}

	u->https = c.nScheme == INTERNET_SCHEME_HTTPS;
	u->host.assign(c.lpszHostName, c.dwHostNameLength);
	u->port = c.nPort;
	u->path.clear();
	if (c.dwUrlPathLength > 0) {
		u->path.assign(c.lpszUrlPath, c.dwUrlPathLength);
	}
	if (c.dwExtraInfoLength > 0) {
		u->path.append(c.lpszExtraInfo, c.dwExtraInfoLength);
	}
	if (u->path.empty()) {
		u->path = L"/";
	}

	return !u->host.empty() && (u->https || Loopback(u->host));
}

/* ---- HTTP (WinHTTP) ----------------------------------------------------------
 * 인증서 검증은 WinHTTP 의 기본(시스템 저장소)대로 한다. 끄는 옵션을 두지 않는다. */
struct Handle {
	HINTERNET h = nullptr;
	~Handle() { if (h) WinHttpCloseHandle(h); }
};

struct Response {
	DWORD status = 0;
	std::string body;
	~Response() { Wipe(body); }	/* 토큰이 들어 있다 */
};

Result Http(const std::string &url, const std::string *form, Response *r, CString *detail,
		const std::string *dpop = nullptr)
{
	Url u;
	Handle session, conn, req;
	DWORD status = 0;
	DWORD len = sizeof(status);
	BOOL ok;

	if (!ParseUrl(url, &u)) {
		detail->Format(_T("쓸 수 없는 주소: %s"), (LPCTSTR)WideC(url));
		return RESULT_CONFIG;
	}

	session.h = WinHttpOpen(L"ztgate", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
			WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!session.h) {
		detail->Format(_T("WinHttpOpen 실패 (%lu)"), GetLastError());
		return RESULT_NETWORK;
	}
	WinHttpSetTimeouts(session.h, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS);

	conn.h = WinHttpConnect(session.h, u.host.c_str(), u.port, 0);
	req.h = conn.h ? WinHttpOpenRequest(conn.h, form ? L"POST" : L"GET", u.path.c_str(), nullptr,
			WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, u.https ? WINHTTP_FLAG_SECURE : 0) : nullptr;
	if (!req.h) {
		detail->Format(_T("%s 요청을 만들지 못함 (%lu)"), u.host.c_str(), GetLastError());
		return RESULT_NETWORK;
	}

	/* 토큰 요청(POST)은 리다이렉트를 따라가지 않는다. 307 / 308 을 따라가면 코드나 refresh
	 * token 이 든 본문을 그 응답이 가리키는 다른 곳으로 다시 보낸다. */
	if (form) {
		DWORD off = WINHTTP_DISABLE_REDIRECTS;

		WinHttpSetOption(req.h, WINHTTP_OPTION_DISABLE_FEATURE, &off, sizeof(off));
	}

	if (form) {
		std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";

		if (dpop && !dpop->empty()) {
			headers += L"DPoP: " + Wide(*dpop) + L"\r\n";
		}
		ok = WinHttpSendRequest(req.h, headers.c_str(),
				(DWORD)-1L, const_cast<char *>(form->data()), (DWORD)form->size(), (DWORD)form->size(), 0);
	}
	else {
		ok = WinHttpSendRequest(req.h, L"Accept: application/json\r\n", (DWORD)-1L,
				WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	}
	if (!ok || !WinHttpReceiveResponse(req.h, nullptr)) {
		detail->Format(_T("%s 에 닿지 못함 (%lu)"), u.host.c_str(), GetLastError());
		return RESULT_NETWORK;
	}

	WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
	r->status = status;

	for (;;) {
		DWORD avail = 0;
		DWORD got = 0;

		if (!WinHttpQueryDataAvailable(req.h, &avail)) {
			detail->Format(_T("%s 의 응답을 읽지 못함 (%lu)"), u.host.c_str(), GetLastError());
			return RESULT_NETWORK;
		}
		if (avail == 0) {
			break;
		}
		if (r->body.size() + avail > HTTP_BODY_MAX) {
			detail->Format(_T("%s 의 응답이 너무 큼"), u.host.c_str());
			return RESULT_PROTOCOL;
		}

		const size_t off = r->body.size();
		r->body.resize(off + avail);
		if (!WinHttpReadData(req.h, &r->body[off], avail, &got)) {
			detail->Format(_T("%s 의 응답을 읽지 못함 (%lu)"), u.host.c_str(), GetLastError());
			return RESULT_NETWORK;
		}
		r->body.resize(off + got);
	}

	return RESULT_OK;
}

/* ---- JSON ------------------------------------------------------------------ */
class Json {
public:
	~Json() { Wipe(m_text); }

	bool Parse(const std::string &text)
	{
		m_text = text;
		m_tok.resize(JSON_TOKENS);
		m_n = json_parse(m_text.data(), m_text.size(), m_tok.data(), (int)m_tok.size());

		return m_n > 0 && m_tok[0].type == JSON_OBJECT;
	}

	bool Str(const char *key, std::string *out) const
	{
		const int i = json_get(m_text.c_str(), m_tok.data(), 0, key);

		if (i < 0 || m_tok[i].type != JSON_STRING) {
			return false;
		}

		/* 풀린 값은 원문보다 길지 않다 (이스케이프는 줄어들기만 한다). */
		std::vector<char> buf((size_t)(m_tok[i].end - m_tok[i].start) + 1);
		const int n = json_string(m_text.c_str(), m_tok.data(), i, buf.data(), buf.size());

		if (n < 0) {
			return false;
		}
		out->assign(buf.data(), (size_t)n);
		SecureZeroMemory(buf.data(), buf.size());

		return true;
	}

	bool Int(const char *key, __int64 *out) const
	{
		const int i = json_get(m_text.c_str(), m_tok.data(), 0, key);
		int64_t v;

		if (i < 0 || json_int64(m_text.c_str(), m_tok.data(), i, &v) < 0) {
			return false;
		}
		*out = v;

		return true;
	}

private:
	std::string m_text;
	std::vector<json_tok_t> m_tok;
	int m_n = 0;
};

/* ---- IdP 의 주소들 ---------------------------------------------------------- */
struct Endpoints {
	std::string authorize;
	std::string token;
	std::string revoke;	/* 없을 수 있다 */
};

/* IdP 가 잠시 답하지 못한다 (점검, 과부하). 설정이 틀린 것과 달리 다시 해 볼 일이다. */
bool Transient(DWORD status)
{
	return status == 0 || status == 429 || status >= 500;
}

/* 설정 문서의 issuer 는 설정한 주소와 같아야 한다 (OIDC Discovery 4.3). 다르면 다른 IdP 의
 * 문서를 받은 것이고, 그 IdP 가 준 토큰은 서버도 받지 않는다. */
Result Discover(const Config &cfg, Endpoints *ep, CString *detail)
{
	const std::string issuer = StripSlash(Utf8(cfg.issuer));
	Response r;
	Json j;
	std::string iss;
	Url u;
	Result res;

	res = Http(issuer + "/.well-known/openid-configuration", nullptr, &r, detail);
	if (res != RESULT_OK) {
		return res;
	}
	if (r.status != 200) {
		detail->Format(_T("IdP 의 설정 문서를 받지 못함 (HTTP %lu)"), r.status);
		return Transient(r.status) ? RESULT_NETWORK : RESULT_PROTOCOL;
	}
	if (!j.Parse(r.body) || !j.Str("issuer", &iss) || !j.Str("token_endpoint", &ep->token)) {
		*detail = _T("IdP 의 설정 문서를 읽지 못함");
		return RESULT_PROTOCOL;
	}
	if (StripSlash(iss) != issuer) {
		detail->Format(_T("IdP 가 다른 발급자를 말함: %s"), (LPCTSTR)WideC(iss));
		return RESULT_CONFIG;
	}
	if (!ParseUrl(ep->token, &u)) {
		detail->Format(_T("토큰 주소를 쓸 수 없음: %s"), (LPCTSTR)WideC(ep->token));
		return RESULT_CONFIG;
	}
	j.Str("authorization_endpoint", &ep->authorize);
	if (j.Str("revocation_endpoint", &ep->revoke) && !ParseUrl(ep->revoke, &u)) {
		ep->revoke.clear();
	}

	return RESULT_OK;
}

Result TokenRequest(const Config &cfg, const Endpoints &ep, const std::string &form, Tokens *t, CString *detail)
{
	std::string proof;
	Response r;
	Json j;
	__int64 in = 0;
	Result res;

	/* 증명을 만들지 못하면(서비스가 없다) 싣지 않고 보낸다 — 그 토큰은 묶이지 않는다. */
	if (cfg.dpop && !cfg.dpop(ep.token, &proof)) {
		proof.clear();
	}
	res = Http(ep.token, &form, &r, detail, &proof);
	if (res != RESULT_OK) {
		return res;
	}
	if (!j.Parse(r.body)) {
		detail->Format(_T("토큰 응답을 읽지 못함 (HTTP %lu)"), r.status);
		return Transient(r.status) ? RESULT_NETWORK : RESULT_PROTOCOL;
	}

	if (r.status != 200) {
		std::string err, desc;

		j.Str("error", &err);
		j.Str("error_description", &desc);
		detail->Format(_T("IdP: %s%s%s"), (LPCTSTR)WideC(err), desc.empty() ? _T("") : _T(" \x2014 "),
				(LPCTSTR)WideC(desc));

		/* invalid_grant: 코드나 refresh token 이 끝났다 (IdP 에서 로그아웃, 세션 만료). */
		if (err == "invalid_grant" || err == "access_denied" || err == "unauthorized_client") {
			return RESULT_DENIED;
		}
		return (Transient(r.status) || err == "temporarily_unavailable") ? RESULT_NETWORK : RESULT_PROTOCOL;
	}

	if (!j.Str("access_token", &t->access) || t->access.empty()) {
		*detail = _T("토큰 응답에 access_token 이 없음");
		return RESULT_PROTOCOL;
	}
	j.Str("refresh_token", &t->refresh);
	t->expires_at = (j.Int("expires_in", &in) && in > 0) ? _time64(nullptr) + in : 0;

	return RESULT_OK;
}

/* ---- PKCE -------------------------------------------------------------------- */
std::string Base64Url(const BYTE *p, size_t n)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string out;
	size_t i = 0;

	for (; i + 2 < n; i += 3) {
		const unsigned v = (unsigned)p[i] << 16 | (unsigned)p[i + 1] << 8 | p[i + 2];
		out += t[v >> 18 & 63];
		out += t[v >> 12 & 63];
		out += t[v >> 6 & 63];
		out += t[v & 63];
	}
	if (n - i == 1) {
		const unsigned v = (unsigned)p[i] << 16;
		out += t[v >> 18 & 63];
		out += t[v >> 12 & 63];
	}
	else if (n - i == 2) {
		const unsigned v = (unsigned)p[i] << 16 | (unsigned)p[i + 1] << 8;
		out += t[v >> 18 & 63];
		out += t[v >> 12 & 63];
		out += t[v >> 6 & 63];
	}

	return out;
}

bool RandomText(size_t bytes, std::string *out)
{
	std::vector<BYTE> b(bytes);

	if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, b.data(), (ULONG)bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
		return false;
	}
	*out = Base64Url(b.data(), bytes);
	SecureZeroMemory(b.data(), b.size());

	return true;
}

/* code_challenge = BASE64URL(SHA256(verifier)) */
bool S256(const std::string &verifier, std::string *challenge)
{
	BCRYPT_ALG_HANDLE alg = nullptr;
	BYTE h[32];
	NTSTATUS st;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
		return false;
	}
	st = BCryptHash(alg, nullptr, 0, (PUCHAR)verifier.data(), (ULONG)verifier.size(), h, sizeof(h));
	BCryptCloseAlgorithmProvider(alg, 0);
	if (!BCRYPT_SUCCESS(st)) {
		return false;
	}
	*challenge = Base64Url(h, sizeof(h));

	return true;
}

/* ---- 브라우저가 돌아오는 곳 (127.0.0.1) ---------------------------------------- */
struct Socket {
	SOCKET s = INVALID_SOCKET;
	~Socket() { if (s != INVALID_SOCKET) closesocket(s); }
};

/* 이 PC 안에서만 받는다. 빈 포트를 고르고, 같은 포트를 다른 프로그램이 함께 잡지 못하게
 * 한다 (SO_EXCLUSIVEADDRUSE) — 함께 잡으면 브라우저가 돌려보낸 코드를 그쪽이 받을 수 있다. */
bool Listen(Socket *l, int *port)
{
	sockaddr_in a;
	int alen = sizeof(a);
	BOOL excl = TRUE;

	l->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (l->s == INVALID_SOCKET) {
		return false;
	}
	setsockopt(l->s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&excl), sizeof(excl));

	ZeroMemory(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;

	if (bind(l->s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0 || listen(l->s, SOMAXCONN) != 0 ||
			getsockname(l->s, reinterpret_cast<sockaddr *>(&a), &alen) != 0) {
		return false;
	}
	*port = ntohs(a.sin_port);

	return true;
}

/* 요청 하나를 읽어 요청 줄의 대상("/callback?code=...")을 돌려준다. GET 만 받는다. */
bool ReadTarget(SOCKET c, std::string *target)
{
	const DWORD timeout = 5000;
	std::string req;
	char buf[2048];

	setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));

	while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
		const int n = recv(c, buf, sizeof(buf), 0);
		if (n <= 0) {
			break;
		}
		req.append(buf, (size_t)n);
	}

	const size_t eol = req.find("\r\n");
	if (eol == std::string::npos || req.compare(0, 4, "GET ") != 0) {
		return false;
	}
	const size_t sp = req.find(' ', 4);
	if (sp == std::string::npos || sp > eol) {
		return false;
	}
	*target = req.substr(4, sp - 4);

	return true;
}

std::string Page(const char *title, const char *message)
{
	return std::string("<!doctype html><html lang=\"ko\"><meta charset=\"utf-8\">"
			"<meta name=\"viewport\" content=\"width=device-width\"><title>ztgate</title>"
			"<body style=\"font-family:'Segoe UI',sans-serif;background:#f3f3f3;margin:0\">"
			"<div style=\"max-width:420px;margin:80px auto;background:#fff;border:1px solid #e0e0e0;"
			"border-radius:10px;padding:28px 32px\"><h2 style=\"margin:0 0 12px;font-weight:600\">") +
		title + "</h2><p style=\"margin:0;color:#555;line-height:1.5\">" + message +
		"</p></div></body></html>";
}

void Reply(SOCKET c, int code, const char *reason, const std::string &html)
{
	const std::string r = "HTTP/1.1 " + std::to_string(code) + " " + reason + "\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: " + std::to_string(html.size()) + "\r\n"
		"Cache-Control: no-store\r\n"
		"Connection: close\r\n\r\n" + html;

	send(c, r.data(), (int)r.size(), 0);
	shutdown(c, SD_SEND);
}

/* 브라우저가 돌아오기를 기다린다. 다른 경로(파비콘 등)와 state 가 다른 요청은 거절하고
 * 계속 기다린다. 0.25초마다 cancel 을 본다. */
Result WaitCallback(SOCKET listener, const std::string &state, HANDLE cancel, std::string *code, CString *detail)
{
	const ULONGLONG deadline = GetTickCount64() + LOGIN_WAIT_MS;

	for (;;) {
		fd_set rd;
		timeval tv = { 0, 250000 };
		std::string target;
		Socket c;

		if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
			*detail = _T("로그인을 취소함");
			return RESULT_CANCELLED;
		}
		if (GetTickCount64() >= deadline) {
			*detail = _T("브라우저에서 5분 안에 로그인을 마치지 않음");
			return RESULT_TIMEOUT;
		}

		FD_ZERO(&rd);
		FD_SET(listener, &rd);
		const int n = select(0, &rd, nullptr, nullptr, &tv);
		if (n < 0) {
			detail->Format(_T("select 실패 (%d)"), WSAGetLastError());
			return RESULT_NETWORK;
		}
		if (n == 0) {
			continue;
		}

		c.s = accept(listener, nullptr, nullptr);
		if (c.s == INVALID_SOCKET || !ReadTarget(c.s, &target)) {
			continue;
		}

		const size_t qpos = target.find('?');
		if (target.substr(0, qpos) != CALLBACK_PATH) {
			Reply(c.s, 404, "Not Found", Page("찾을 수 없음", "ztgate 로그인 창이 아닙니다."));
			continue;
		}

		std::map<std::string, std::string> q = Query(qpos == std::string::npos ? std::string() : target.substr(qpos + 1));

		if (q["state"] != state) {
			Reply(c.s, 400, "Bad Request", Page("받지 않은 요청",
					"ztgate 가 시작한 로그인이 아닙니다. ztgate 에서 다시 로그인하세요."));
			continue;
		}
		if (!q["error"].empty()) {
			Reply(c.s, 200, "OK", Page("로그인하지 못했습니다",
					"IdP 가 로그인을 마치지 않았습니다. ztgate 로 돌아가 다시 시도하세요."));
			detail->Format(_T("IdP: %s %s"), (LPCTSTR)WideC(q["error"]), (LPCTSTR)WideC(q["error_description"]));
			return RESULT_DENIED;
		}
		if (q["code"].empty()) {
			Reply(c.s, 400, "Bad Request", Page("받지 않은 요청", "로그인 코드가 없습니다."));
			continue;
		}

		*code = q["code"];
		Wipe(q["code"]);
		Reply(c.s, 200, "OK", Page("로그인했습니다", "이 창을 닫고 ztgate 로 돌아가세요."));

		return RESULT_OK;
	}
}

} /* namespace */

/* ---- 밖으로 내놓는 것 --------------------------------------------------------- */
Outcome Login(const Config &cfg, HANDLE cancel)
{
	Outcome o;
	Endpoints ep;
	Url au;
	Socket listener;
	std::string verifier, challenge, state, code, redirect, url, form;
	const std::string client = Utf8(cfg.client_id);
	const std::string scope = cfg.scope.IsEmpty() ? std::string("openid") : Utf8(cfg.scope);
	int port = 0;

	o.result = Discover(cfg, &ep, &o.detail);
	if (o.result != RESULT_OK) {
		return o;
	}
	if (ep.authorize.empty() || !ParseUrl(ep.authorize, &au)) {
		o.result = RESULT_CONFIG;
		o.detail = _T("IdP 가 쓸 수 있는 로그인 주소(authorization_endpoint)를 알려 주지 않음");
		return o;
	}

	/* verifier 는 32바이트 난수(43자), state 는 16바이트 난수. */
	if (!RandomText(32, &verifier) || !S256(verifier, &challenge) || !RandomText(16, &state)) {
		o.result = RESULT_PROTOCOL;
		o.detail = _T("난수나 해시를 만들지 못함");
		return o;
	}
	if (!Listen(&listener, &port)) {
		o.result = RESULT_NETWORK;
		o.detail.Format(_T("127.0.0.1 에서 브라우저를 기다릴 수 없음 (%d)"), WSAGetLastError());
		return o;
	}

	redirect = "http://127.0.0.1:" + std::to_string(port) + CALLBACK_PATH;
	url = ep.authorize + (ep.authorize.find('?') == std::string::npos ? "?" : "&") +
		"response_type=code&client_id=" + Encode(client) +
		"&redirect_uri=" + Encode(redirect) +
		"&scope=" + Encode(scope) + "&state=" + state +
		"&code_challenge=" + challenge + "&code_challenge_method=S256";

	/* 기본 브라우저로 연다. ShellExecute 는 셸 확장을 부를 수 있어 COM 이 필요하다. */
	{
		const HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		const INT_PTR h = reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", Wide(url).c_str(),
				nullptr, nullptr, SW_SHOWNORMAL));

		if (SUCCEEDED(co)) {
			CoUninitialize();
		}
		if (h <= 32) {
			o.result = RESULT_CONFIG;
			o.detail.Format(_T("브라우저를 열지 못함 (%d)"), (int)h);
			return o;
		}
	}

	o.result = WaitCallback(listener.s, state, cancel, &code, &o.detail);
	if (o.result != RESULT_OK) {
		Wipe(verifier);
		return o;
	}

	form = "grant_type=authorization_code&code=" + Encode(code) +
		"&redirect_uri=" + Encode(redirect) +
		"&client_id=" + Encode(client) +
		"&code_verifier=" + verifier;
	o.result = TokenRequest(cfg, ep, form, &o.tokens, &o.detail);

	Wipe(form);
	Wipe(code);
	Wipe(verifier);

	return o;
}

Outcome Refresh(const Config &cfg, const std::string &refresh_token, HANDLE cancel)
{
	Outcome o;
	Endpoints ep;
	std::string form;

	(void)cancel;	/* 요청 하나라 WinHTTP 의 시간 제한(10초) 안에 끝난다 */

	o.result = Discover(cfg, &ep, &o.detail);
	if (o.result != RESULT_OK) {
		return o;
	}

	form = "grant_type=refresh_token&refresh_token=" + Encode(refresh_token) +
		"&client_id=" + Encode(Utf8(cfg.client_id));
	o.result = TokenRequest(cfg, ep, form, &o.tokens, &o.detail);
	Wipe(form);

	/* refresh token 을 새로 주지 않는 IdP 도 있다. 그때는 쓰던 것을 계속 쓴다. */
	if (o.result == RESULT_OK && o.tokens.refresh.empty()) {
		o.tokens.refresh = refresh_token;
	}

	return o;
}

void Revoke(const Config &cfg, const std::string &refresh_token)
{
	Endpoints ep;
	Response r;
	CString detail;
	std::string form;

	if (refresh_token.empty() || Discover(cfg, &ep, &detail) != RESULT_OK || ep.revoke.empty()) {
		return;
	}

	form = "token=" + Encode(refresh_token) + "&token_type_hint=refresh_token&client_id=" +
		Encode(Utf8(cfg.client_id));
	Http(ep.revoke, &form, &r, &detail);
	Wipe(form);
}

/* ---- refresh token 보관 ------------------------------------------------------ */
static const TCHAR LOGIN_SECTION[] = _T("login");
static const TCHAR REFRESH_VALUE[] = _T("refresh");

/* DPAPI 의 추가 엔트로피: 이 토큰을 준 IdP 와 클라이언트. 다른 값으로는 풀리지 않는다. */
static std::string Binding(const Config &cfg)
{
	return "ztgate refresh\n" + StripSlash(Utf8(cfg.issuer)) + "\n" + Utf8(cfg.client_id);
}

bool SaveRefresh(const Config &cfg, const std::string &token)
{
	std::string bind = Binding(cfg);
	DATA_BLOB in;
	DATA_BLOB entropy;
	DATA_BLOB out;
	BOOL ok;

	in.cbData = (DWORD)token.size();
	in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(token.data()));
	entropy.cbData = (DWORD)bind.size();
	entropy.pbData = reinterpret_cast<BYTE *>(&bind[0]);
	ZeroMemory(&out, sizeof(out));

	if (!CryptProtectData(&in, L"ztgate refresh token", &entropy, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN, &out)) {
		return false;
	}
	ok = AfxGetApp()->WriteProfileBinary(LOGIN_SECTION, REFRESH_VALUE, out.pbData, out.cbData);
	LocalFree(out.pbData);

	return ok != FALSE;
}

bool LoadRefresh(const Config &cfg, std::string *token)
{
	std::string bind = Binding(cfg);
	BYTE *data = nullptr;
	UINT len = 0;
	DATA_BLOB in;
	DATA_BLOB entropy;
	DATA_BLOB out;
	BOOL ok;

	if (!AfxGetApp()->GetProfileBinary(LOGIN_SECTION, REFRESH_VALUE, &data, &len) || !data || len == 0) {
		delete[] data;
		return false;
	}

	in.cbData = len;
	in.pbData = data;
	entropy.cbData = (DWORD)bind.size();
	entropy.pbData = reinterpret_cast<BYTE *>(&bind[0]);
	ZeroMemory(&out, sizeof(out));
	ok = CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
	delete[] data;
	if (!ok) {
		return false;
	}

	token->assign(reinterpret_cast<const char *>(out.pbData), out.cbData);
	SecureZeroMemory(out.pbData, out.cbData);
	LocalFree(out.pbData);

	return !token->empty();
}

void ForgetRefresh()
{
	HKEY key = AfxGetApp()->GetSectionKey(LOGIN_SECTION);

	if (key) {
		RegDeleteValue(key, REFRESH_VALUE);
		RegCloseKey(key);
	}
}

void Wipe(Tokens *t)
{
	Wipe(t->access);
	Wipe(t->refresh);
	t->expires_at = 0;
}

bool IssuerUsable(const CString &issuer, CString *why)
{
	Url u;

	if (!ParseUrl(Utf8(issuer), &u) || issuer.FindOneOf(_T("?#")) >= 0) {
		*why = _T("https:// 로 시작하는 IdP 주소여야 합니다. 예) https://idp.example.com/realms/corp");
		return false;
	}

	return true;
}

} /* namespace oidc */
