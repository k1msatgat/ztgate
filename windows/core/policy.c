#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "policy.h"

static int reg_str(const wchar_t *name, wchar_t *out, DWORD cap_chars)
{
	DWORD len = cap_chars * sizeof(wchar_t);

	out[0] = L'\0';
	return RegGetValueW(HKEY_LOCAL_MACHINE, POLICY_REG_PATH, name, RRF_RT_REG_SZ, NULL, out, &len) ==
		ERROR_SUCCESS && out[0] != L'\0';
}

static int reg_dword(const wchar_t *name, DWORD *out)
{
	DWORD len = sizeof(*out);

	return RegGetValueW(HKEY_LOCAL_MACHINE, POLICY_REG_PATH, name, RRF_RT_REG_DWORD, NULL, out, &len) ==
		ERROR_SUCCESS;
}

int policy_parse_nets(const wchar_t *text, net_route_t *out, int max)
{
	wchar_t buf[512];
	wchar_t *tok, *ctx = NULL;
	int n = 0;

	if (wcslen(text) >= sizeof(buf) / sizeof(buf[0])) {
		return -1;
	}
	wcscpy_s(buf, sizeof(buf) / sizeof(buf[0]), text);
	for (tok = wcstok_s(buf, L", ", &ctx); tok != NULL; tok = wcstok_s(NULL, L", ", &ctx)) {
		wchar_t *slash = wcschr(tok, L'/');
		struct in_addr a;
		unsigned long prefix;
		uint32_t mask;

		if (n == max || slash == NULL) {
			return -1;
		}
		*slash = L'\0';
		prefix = wcstoul(slash + 1, NULL, 10);
		if (InetPtonW(AF_INET, tok, &a) != 1 || prefix < 1 || prefix > 32) {
			return -1;
		}
		mask = htonl(0xFFFFFFFFu << (32 - prefix));
		out[n].addr = a.s_addr & mask;
		out[n].prefix_len = (uint8_t)prefix;
		n++;
	}
	return n;
}

int policy_load(ztgate_policy_t *p)
{
	wchar_t nets[512];
	DWORD v;
	int any = 0;

	memset(p, 0, sizeof(*p));

	if (reg_str(L"Servers", p->servers_text, sizeof(p->servers_text) / sizeof(p->servers_text[0]))) {
		any = 1;
		p->has_servers = tunnel_parse_servers(p->servers_text, &p->server_ip, p->alt_ips, &p->n_alt) == 0;
	}
	if (reg_dword(L"Port", &v)) {
		any = 1;
		p->port = v > 0 && v <= 65535 ? (uint16_t)v : 0;
	}
	if (reg_dword(L"AlwaysOn", &v)) {
		any = 1;
		p->always_on = v != 0;
	}
	if (reg_dword(L"BlockWhenDown", &v)) {
		any = 1;
		p->block_when_down = v != 0;
	}
	if (reg_str(L"InternalNetworks", nets, sizeof(nets) / sizeof(nets[0]))) {
		int n = policy_parse_nets(nets, p->internal, POLICY_NETS_MAX);

		any = 1;
		p->n_internal = n > 0 ? n : 0;
	}
	if (reg_str(L"Issuer", p->issuer, sizeof(p->issuer) / sizeof(p->issuer[0]))) {
		any = 1;
	}
	if (reg_str(L"ClientId", p->client_id, sizeof(p->client_id) / sizeof(p->client_id[0]))) {
		any = 1;
	}

	/* 서버만 적고 포트를 빠뜨리면 쓸 수 없다. 기본 포트로 채운다. */
	if (p->has_servers && p->port == 0) {
		p->port = 9000;
	}
	return any;
}
