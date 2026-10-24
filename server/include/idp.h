#ifndef IDP_H
#define IDP_H

/* 사용자 토큰(JWT)의 검증.
 *
 * 서버는 IdP 와 직접 통신하지 않는다. 관리자가 IdP 의 공개키 묶음(JWKS)을 파일로 받아
 * 두고, 서버는 그 키로 서명만 확인한다. 서버의 이벤트 루프는 스레드 하나라 HTTPS 요청을
 * 기다리는 동안 모든 터널이 멈춘다. 그리고 IdP 에 닿지 못할 때 로그인을 어떻게 할지
 * 같은 정책이 데이터 경로 안으로 들어온다. 키는 자주 바뀌지 않으므로 바뀔 때 파일을
 * 갈아 끼우고 SIGHUP 을 보내면 된다.
 *
 * 설정 파일 (-u)
 *
 *   issuer        https://idp.example.com/realms/corp    토큰의 iss 와 정확히 같아야 한다
 *   audience      ztgate                                 토큰의 aud 에 들어 있어야 한다
 *   jwks          jwks.json                              IdP 의 공개키. 상대 경로는 이 파일 기준
 *   user-claim    preferred_username                     사용자 이름을 읽을 클레임 (기본 sub)
 *   groups-claim  groups                                 그룹 목록을 읽을 클레임 (기본 groups)
 *   leeway        30                                     exp / nbf 에 봐주는 초 (기본 30)
 *   dpop          required                               기기에 묶인 토큰(cnf.jkt)만 받는다 (기본 optional:
 *                                                        묶인 토큰은 증명을 보고, 묶이지 않은 토큰도 받는다)
 *
 * 받는 토큰
 *   - alg 는 RS256 과 ES256 만. "none" 이나 HS256 은 받지 않는다. 특히 HS256 을 받으면
 *     공개키를 HMAC 키로 쓴 위조 토큰이 통과하는 고전적인 구멍이 생긴다.
 *   - kid 로 키를 고르고, 그 키의 종류가 alg 와 맞아야 한다 (RSA 키로 ES256 검증 없음).
 *   - iss, aud, exp 는 반드시 있어야 하고, nbf 는 있으면 본다.
 *   - crit 헤더가 있으면 받지 않는다. 모르는 확장을 무시하라는 뜻이 아니라 반드시
 *     이해하라는 뜻이다. */

#include <stddef.h>
#include <stdint.h>

#include "policy.h"

/* 설정과 JWKS 를 읽는다. 읽은 키의 수를 돌려주고, 실패하면 -1 이며 그때는 이전에 읽은
 * 설정과 키가 그대로 남는다. */
int idp_load(const char *path);

/* idp_load 가 한 번이라도 성공했으면 1. */
int idp_enabled(void);

/* 토큰을 확인하고 사용자를 꺼낸다. proof 는 DPoP 증명 (없으면 NULL, proto.h 의 "DPoP"). now 는
 * 벽시계 초. login_status_t 를 돌려준다. */
int idp_verify(const char *token, size_t len, const char *proof, size_t proof_len, int64_t now,
		user_identity_t *out);

/* 사람이 읽을 이름 (로그, 감사 로그). */
const char *idp_status_name(int status);

void idp_dump(void);

#endif
