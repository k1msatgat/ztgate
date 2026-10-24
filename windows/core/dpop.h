#ifndef WIN_DPOP_H
#define WIN_DPOP_H

/* DPoP — 사용자 토큰을 이 PC 의 키에 묶는다 (proto.h 의 "DPoP").
 *
 * 키는 서비스가 가진다 (PC 의 키, TPM 이 있으면 TPM 안에 — Microsoft Platform Crypto Provider, 없으면
 * 소프트웨어 키 저장소). 내보낼 수 없다. 서비스는 LOGIN 마다 이 키로 증명을 만들어 토큰에 붙이고, GUI
 * 가 IdP 에 토큰을 청할 때는 IPC 로 서비스에 증명을 받아 DPoP 헤더에 싣는다 (IPC_CMD_DPOP). 그래서 IdP
 * 가 준 토큰은 이 PC 의 키에 묶이고, 토큰을 빼 가도 이 PC 밖에서는 쓰이지 않는다. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPOP_KEY_NAME	L"ztgate-dpop"

/* 증명 한 줄 (NUL 로 끝남). token 이 있으면 ath 를 넣는다 (LOGIN), 없으면 넣지 않는다 (IdP 의 토큰
 * 엔드포인트). machine 은 PC 의 키를 쓴다 (서비스). 키가 없으면 만든다. 길이, 실패 -1. */
int dpop_make_proof(int machine, const char *htm, const char *htu, const char *token, size_t token_len,
		char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
