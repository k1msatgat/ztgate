#ifndef SERVERKEY_H
#define SERVERKEY_H

/* 서버의 고정 키 쌍 (P-256). 공개키 기기(devices.conf 의 p256:...)의 키를 뽑는 데 쓴다
 * (proto.h 의 "기기 등록", secure.h 의 secure_static_key).
 *
 *   vpn_server genkey /etc/ztgate/server.key      처음 한 번. 공개키를 찍는다
 *   vpn_server -k /etc/ztgate/server.key ...
 *
 *   파일: <비밀 스칼라 64 hex> <공개키 128 hex>
 *
 * 서버가 지키는 비밀은 이 파일 하나다. 이 키를 바꾸면 공개키 기기의 키가 모두 바뀌므로 그
 * 기기들은 다시 등록해야 한다 — 서버의 오래 가는 신원이다. 권한이 600 보다 넓으면 읽지 않는다. */

#include <stdint.h>

#include "crypt.h"

/* 새 키를 만들어 path 에 쓴다. 이미 있으면 덮지 않고 -1. 공개키를 stdout 에 찍는다. */
int serverkey_generate(const char *path);

/* 읽는다. 성공 0, 실패 -1 (이전에 읽은 것이 남는다). */
int serverkey_load(const char *path);

/* 읽어 둔 키. 없으면 NULL. */
crypt_ecdh_t *serverkey(void);
const uint8_t *serverkey_pub(void);

#endif
