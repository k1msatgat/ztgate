#pragma once

/* 사용자 로그인: 회사 IdP 에 OpenID Connect 로 로그인해 토큰을 받는다.
 *
 * 흐름은 데스크톱 앱의 표준(RFC 8252)대로 인가 코드 + PKCE(RFC 7636)다.
 *
 *   1) IdP 의 설정 문서(<issuer>/.well-known/openid-configuration)에서 주소들을 읽는다.
 *   2) 127.0.0.1 의 빈 포트에서 기다리며, 기본 브라우저로 IdP 의 로그인 화면을 연다.
 *   3) 사용자가 로그인하면 IdP 가 브라우저를 http://127.0.0.1:<포트>/callback?code=... 로
 *      돌려보낸다.
 *   4) 그 코드와 처음에 만들어 둔 verifier 로 토큰을 받는다.
 *
 * 왜 브라우저인가. 비밀번호와 MFA 는 브라우저에서 IdP 에만 들어간다 — 이 프로그램은 그것을
 * 보지 않는다. 앱 안에 웹 뷰를 띄우면 앱이 비밀번호를 가로챌 수 있는 자리가 되고, 사용자가
 * 이미 들어가 있는 회사 SSO 세션(브라우저의 쿠키)도 쓰지 못해 매번 다시 로그인해야 한다.
 *
 * PKCE: 코드는 브라우저의 주소창과 기록을 거친다. 같은 PC 의 다른 프로그램이 코드를
 * 엿봐도 verifier 없이는 토큰으로 바꾸지 못한다.
 * state: 이 프로그램이 시작하지 않은 로그인의 응답은 받지 않는다 (CSRF).
 *
 * Login / Refresh 는 블로킹이다 (네트워크, 사람의 로그인). 워커 스레드에서 부른다.
 * SaveRefresh / LoadRefresh / ForgetRefresh 는 앱의 레지스트리를 쓰므로 UI 스레드에서 부른다. */

#include <functional>
#include <string>

namespace oidc {

struct Config {
	CString issuer;		/* 예) https://idp.example.com/realms/corp */
	CString client_id;	/* IdP 에 등록한 공개 클라이언트 (client secret 없음) */
	CString scope;		/* 비어 있으면 "openid". refresh token 을 받으려면 IdP 에 따라
				 * offline_access 를, 서버용 access token 을 받으려면 그 API 의 scope 를 더한다 */

	/* 토큰 엔드포인트(htu)에 보낼 DPoP 증명을 만든다 (RFC 9449, 키는 서비스에 — dpop.h). 있으면 토큰
	 * 요청마다 DPoP 헤더로 싣고, IdP 는 이 PC 의 키에 묶인 토큰을 준다. 비어 있거나 false 면 싣지 않는다. */
	std::function<bool(const std::string &htu, std::string *proof)> dpop;
};

struct Tokens {
	std::string access;	/* 서버에 보낼 토큰 (JWT) */
	std::string refresh;	/* 브라우저 없이 새 토큰을 받는 데 쓴다. 없을 수 있다 */
	__int64 expires_at;	/* access 의 만료 (Unix time). 모르면 0 */
};

enum Result {
	RESULT_OK = 0,
	RESULT_CANCELLED,	/* cancel 이 신호됐다 */
	RESULT_TIMEOUT,		/* 브라우저에서 로그인을 마치지 않았다 */
	RESULT_DENIED,		/* IdP 가 거절했다 (로그인 거부, refresh token 만료) */
	RESULT_NETWORK,		/* IdP 에 닿지 못했다, 또는 IdP 가 잠시 답하지 못한다 (5xx). 다시 해 볼 일이다 */
	RESULT_PROTOCOL,	/* IdP 의 답이 기대한 모양이 아니다 */
	RESULT_CONFIG		/* 설정한 주소를 쓸 수 없다 */
};

struct Outcome {
	Result result;
	CString detail;		/* 로그에 남길 이유 */
	Tokens tokens;
};

/* 브라우저를 띄워 로그인한다. 사람이 로그인을 마칠 때까지(길면 5분) 돌아오지 않는다. */
Outcome Login(const Config &cfg, HANDLE cancel);

/* refresh token 으로 새 토큰을 받는다. 브라우저를 띄우지 않는다. */
Outcome Refresh(const Config &cfg, const std::string &refresh_token, HANDLE cancel);

/* IdP 에 refresh token 을 버려 달라고 한다 (RFC 7009). IdP 가 revocation_endpoint 를 알려 주지
 * 않으면 아무것도 하지 않는다. 결과는 보지 않는다 — 로그아웃은 이 PC 에서 이미 끝났다. */
void Revoke(const Config &cfg, const std::string &refresh_token);

/* refresh token 을 이 Windows 사용자의 DPAPI 로 감싸 레지스트리에 둔다. 다음에 켤 때
 * 브라우저를 다시 띄우지 않고 로그인한다. 같은 PC 의 다른 사용자는 풀 수 없다.
 * 감쌀 때 IdP 주소와 클라이언트 ID 를 함께 묶는다 — 레지스트리의 IdP 주소가 밖에서
 * 바뀌어도 그 IdP 로 이 refresh token 을 보내지 않는다 (풀리지 않는다). */
bool SaveRefresh(const Config &cfg, const std::string &token);
bool LoadRefresh(const Config &cfg, std::string *token);
void ForgetRefresh();

/* 토큰을 메모리에서 지운다. */
void Wipe(Tokens *t);

/* 설정 칸의 발급자 주소를 쓸 수 있는가. https 만 받는다 (시험용으로 http://127.0.0.1 과
 * http://localhost 는 받는다). */
bool IssuerUsable(const CString &issuer, CString *why);

} /* namespace oidc */
