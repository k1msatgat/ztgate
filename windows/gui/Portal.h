#pragma once

/* 캡티브 포털 (호텔, 카페, 공항 와이파이의 로그인 페이지) 알아보기.
 *
 * 그런 망은 로그인하기 전에는 모든 HTTP 를 자기 페이지로 돌리고 나머지는 막는다. 터널은 UDP / TCP 로
 * 서버에 닿지 못해 "다시 연결 중"에서 멈추는데, 사용자는 왜 그런지 모른다. Windows 가 하는 것(NCSI)과
 * 같은 방법으로 묻는다: http://www.msftconnecttest.com/connecttest.txt 가 정확히
 * "Microsoft Connect Test" 를 돌려주면 인터넷이 되는 것이고, 다른 것(돌려보내기, 다른 내용)이 오면
 * 누군가 가로채고 있다. 아예 답이 없으면 인터넷이 없다.
 *
 * 블로킹 호출이다 (몇 초). UI 스레드에서 부르지 않는다. */

namespace portal {

enum Result {
	UNKNOWN = 0,
	ONLINE,		/* 인터넷이 된다 — 서버 쪽 문제다 */
	CAPTIVE,	/* 로그인 페이지가 가로챈다 */
	OFFLINE		/* 인터넷에 닿지 않는다 */
};

Result Probe();

/* 브라우저로 열 주소. 포털이 가로채 자기 로그인 페이지로 보낸다. */
constexpr const wchar_t *kLoginUrl = L"http://www.msftconnecttest.com/redirect";

}
