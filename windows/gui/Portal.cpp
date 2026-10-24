#include "framework.h"
#include "Portal.h"

#include <winhttp.h>
#include <string>

#pragma comment(lib, "winhttp.lib")

namespace portal {

Result Probe()
{
	static const char kExpect[] = "Microsoft Connect Test";
	HINTERNET s = nullptr, c = nullptr, r = nullptr;
	Result res = OFFLINE;
	DWORD status = 0, len = sizeof(status), feature = WINHTTP_DISABLE_REDIRECTS;
	std::string body;

	s = WinHttpOpen(L"ztgate", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	if (!s) {
		return OFFLINE;
	}
	WinHttpSetTimeouts(s, 4000, 4000, 4000, 4000);
	c = WinHttpConnect(s, L"www.msftconnecttest.com", INTERNET_DEFAULT_HTTP_PORT, 0);
	if (!c) {
		goto out;
	}
	r = WinHttpOpenRequest(c, L"GET", L"/connecttest.txt", nullptr, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	if (!r) {
		goto out;
	}
	/* 돌려보내기를 따라가지 않는다. 돌려보낸다는 것 자체가 가로챔이다. */
	WinHttpSetOption(r, WINHTTP_OPTION_DISABLE_FEATURE, &feature, sizeof(feature));
	if (!WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
			!WinHttpReceiveResponse(r, nullptr)) {
		goto out;	/* 이름 풀기나 연결이 안 된다: 인터넷이 없다 */
	}
	WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
			&status, &len, WINHTTP_NO_HEADER_INDEX);
	for (;;) {
		char buf[256];
		DWORD got = 0;

		if (!WinHttpReadData(r, buf, sizeof(buf), &got) || got == 0 || body.size() > 4096) {
			break;
		}
		body.append(buf, got);
	}
	res = status == 200 && body.compare(0, sizeof(kExpect) - 1, kExpect) == 0 ? ONLINE : CAPTIVE;

out:
	if (r) WinHttpCloseHandle(r);
	if (c) WinHttpCloseHandle(c);
	WinHttpCloseHandle(s);
	return res;
}

}
