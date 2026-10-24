#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <string.h>

#include "wfp.h"

#pragma comment(lib, "fwpuclnt.lib")

/* 우리 필터를 모아 두는 하위 계층. 다른 제품의 필터와 섞이지 않고, 무게(weight)는 이 안에서만 견준다. */
static const GUID ZTGATE_SUBLAYER =
	{ 0x6c1f6b2e, 0x2a8d, 0x4f43, { 0x9b, 0x4e, 0x52, 0x7a, 0x1d, 0x0c, 0x93, 0x5e } };

static HANDLE engine;

void wfp_clear(void)
{
	/* 동적 세션을 닫으면 그 세션이 만든 하위 계층과 필터가 모두 사라진다. */
	if (engine) {
		FwpmEngineClose0(engine);
		engine = NULL;
	}
}

static DWORD add_filter(const struct in_addr *addr, uint8_t prefix_len, FWP_ACTION_TYPE action, UINT8 weight)
{
	FWPM_FILTER_CONDITION0 cond;
	FWP_V4_ADDR_AND_MASK am;
	FWPM_FILTER0 f;
	UINT64 id;

	/* WFP 는 주소와 마스크를 호스트 바이트 순서로 받는다. */
	am.addr = ntohl(addr->s_addr);
	am.mask = prefix_len == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix_len);

	memset(&cond, 0, sizeof(cond));
	cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	cond.matchType = FWP_MATCH_EQUAL;
	cond.conditionValue.type = FWP_V4_ADDR_MASK;
	cond.conditionValue.v4AddrMask = &am;

	memset(&f, 0, sizeof(f));
	f.displayData.name = action == FWP_ACTION_BLOCK ? L"ztgate: internal network while the tunnel is down" :
		L"ztgate: the server";
	f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	f.subLayerKey = ZTGATE_SUBLAYER;
	f.weight.type = FWP_UINT8;
	f.weight.uint8 = weight;
	f.numFilterConditions = 1;
	f.filterCondition = &cond;
	f.action.type = action;

	return FwpmFilterAdd0(engine, &f, NULL, &id);
}

int wfp_block(const net_route_t *nets, int n, const struct in_addr *allow, int n_allow)
{
	FWPM_SESSION0 session;
	FWPM_SUBLAYER0 sub;
	DWORD err;
	int i;

	wfp_clear();
	if (n == 0) {
		return 0;
	}

	memset(&session, 0, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err != ERROR_SUCCESS) {
		engine = NULL;
		return -1;
	}

	err = FwpmTransactionBegin0(engine, 0);
	if (err != ERROR_SUCCESS) {
		wfp_clear();
		return -1;
	}

	memset(&sub, 0, sizeof(sub));
	sub.subLayerKey = ZTGATE_SUBLAYER;
	sub.displayData.name = L"ztgate";
	sub.weight = 0x100;
	err = FwpmSubLayerAdd0(engine, &sub, NULL);

	/* 서버는 내부 대역 안에 있어도 닿아야 한다 (그래야 터널을 다시 연다). 막는 것보다 무겁게. */
	for (i = 0; err == ERROR_SUCCESS && i < n_allow; i++) {
		err = add_filter(&allow[i], 32, FWP_ACTION_PERMIT, 15);
	}
	for (i = 0; err == ERROR_SUCCESS && i < n; i++) {
		struct in_addr a = { .s_addr = nets[i].addr };

		err = add_filter(&a, nets[i].prefix_len, FWP_ACTION_BLOCK, 1);
	}

	if (err != ERROR_SUCCESS) {
		FwpmTransactionAbort0(engine);
		wfp_clear();
		return -1;
	}
	if (FwpmTransactionCommit0(engine) != ERROR_SUCCESS) {
		wfp_clear();
		return -1;
	}
	return 0;
}
