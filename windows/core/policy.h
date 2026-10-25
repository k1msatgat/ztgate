#ifndef POLICY_H
#define POLICY_H

/* 관리 정책 — 관리자가 GPO / Intune / 레지스트리 배포로 이 PC 에 내리는 설정.
 *
 *   HKLM\SOFTWARE\Policies\ztgate
 *     Servers           REG_SZ     "203.0.113.10, 203.0.113.11"   붙을 서버 (쉼표로 넷까지)
 *     Port              REG_DWORD  9000
 *     AlwaysOn          REG_DWORD  1   서비스가 부팅하자마자 붙고 늘 붙어 있다. 사용자는 끊지 못한다
 *     BlockWhenDown     REG_DWORD  1   연결을 원하는데 터널이 열려 있지 않은 동안 내부망으로 나가는
 *                                      연결을 막는다 (WFP). 터널이 열리면 풀린다
 *     InternalNetworks  REG_SZ     "10.0.0.0/8, 172.16.0.0/12"     위에서 막을 대역. 비우면 서버가
 *                                      마지막으로 내려 준 경로와 터널 대역을 막는다
 *     Issuer, ClientId  REG_SZ     사용자 로그인의 IdP (GUI 설정 대신)
 *     UpdateUrl         REG_SZ     자동 업데이트의 매니페스트 (https://..., update.h). 비우면 하지 않는다
 *     UpdatePublicKey   REG_SZ     매니페스트 서명을 확인할 공개키 (128 hex, 쉼표로 둘까지). 없으면 업데이트하지 않는다
 *     UpdateAllowHttp   REG_DWORD  1   시험용: 평문 HTTP 매니페스트 / MSI 도 받는다
 *
 * Policies 아래는 관리자만 쓸 수 있고 모든 사용자가 읽을 수 있다 — 서비스와 GUI 가 같은 값을 본다.
 * 정책이 정한 것은 GUI 설정보다 앞서고, 사용자는 바꾸지 못한다. ADMX 템플릿은
 * windows/installer/ztgate.admx. */

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "tunnel.h"
#include "update.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POLICY_REG_PATH		L"SOFTWARE\\Policies\\ztgate"
#define POLICY_NETS_MAX		16

typedef struct ztgate_policy {
	int has_servers;
	tunnel_addr_t server_ip;
	tunnel_addr_t alt_ips[TUNNEL_ALT_SERVERS];
	int n_alt;
	uint16_t port;			/* 0 이면 정하지 않았다 */
	wchar_t servers_text[256];	/* 화면에 보일 그대로 */

	int always_on;
	int block_when_down;
	net_route_t internal[POLICY_NETS_MAX];
	int n_internal;

	wchar_t issuer[256];		/* 비어 있으면 정하지 않았다 */
	wchar_t client_id[128];

	wchar_t update_url[512];	/* 비어 있으면 자동 업데이트를 하지 않는다 */
	int update_allow_http;
	uint8_t update_keys[UPDATE_KEYS_MAX][UPDATE_PUB_LEN];
	int n_update_keys;		/* 틀린 값이 하나라도 있으면 0 — 업데이트하지 않는다 */
} ztgate_policy_t;

/* 읽는다. 정책이 하나라도 있으면 1, 없으면 0 (p 는 0 으로 채워진다). 틀린 값(주소가 아닌 서버,
 * 대역이 아닌 InternalNetworks)은 그 항목만 없는 것으로 친다. */
int policy_load(ztgate_policy_t *p);

/* "10.0.0.0/8, 172.16.0.0/12" 를 대역으로. 읽은 수, 틀리면 -1. */
int policy_parse_nets(const wchar_t *text, net_route_t *out, int max);

/* "<128 hex>, <128 hex>" 를 공개키로. 읽은 수, 틀리면 -1. */
int policy_parse_keys(const wchar_t *text, uint8_t (*out)[UPDATE_PUB_LEN], int max);

#ifdef __cplusplus
}
#endif

#endif
