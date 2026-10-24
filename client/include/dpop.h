#ifndef DPOP_H
#define DPOP_H

/* DPoP — 사용자 토큰을 이 기기의 키에 묶는다 (proto.h 의 "DPoP").
 *
 *   vpn_client -D /var/lib/ztgate/dpop.pem -t <토큰 파일> run ...
 *   client/ztgate_login --dpop-key /var/lib/ztgate/dpop.pem ...      IdP 에서 이 키에 묶인 토큰을 받는다
 *
 * 키는 P-256 개인키 PEM 하나다 (0600, 없으면 만든다). ztgate_login 이 IdP 에 토큰을 청할 때 이 키로
 * 증명을 붙이면 IdP 가 토큰에 그 키의 지문을 적고, 이 클라이언트는 LOGIN 마다 같은 키로 새 증명을
 * 만들어 토큰과 함께 보낸다. 토큰 파일이 새어도 이 키 없이는 서버가 받지 않는다. */

#include <stddef.h>

/* 읽는다. 없으면 만든다. 0 성공. */
int dpop_load(const char *path);

/* 키가 있는가. */
int dpop_ready(void);

/* token 에 대한 LOGIN 증명(JWS 한 줄, NUL 로 끝남)을 out 에. 길이, 실패 -1. */
int dpop_proof(const char *token, size_t token_len, char *out, size_t cap);

/* 공개키의 RFC 7638 지문 (b64url, NUL 로 끝남). 0 성공. */
int dpop_jkt(char out[64]);

#endif
