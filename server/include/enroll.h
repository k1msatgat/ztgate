#ifndef ENROLL_H
#define ENROLL_H

/* 등록을 기다리는 자리의 목록.
 *
 * 관리자가 등록 코드를 만들면 그 코드에서 뽑은 임시 신원이 여기에 한 줄 생긴다. 줄마다
 * 그 기기가 받게 될 터널 주소와 포스처 조건, 이름, 만료 시각이 적혀 있다. 기기가 그
 * 코드로 붙어 자기 ID 와 키를 내면 서버가 기기 목록에 옮겨 적고 이 줄을 지운다.
 *
 *   # id(32 hex)  key(64 hex)  tunnel-ip  expires(unix)  [요구하는 포스처 ...]  # 이름
 *
 * id 와 key 는 코드 자체가 아니라 코드에서 뽑은 값이다 (secure.h). 이 파일이 새도 코드는
 * 나오지 않지만, 여기 적힌 키로 등록용 세션은 열 수 있다. 기기 목록과 같은 수준으로
 * 다뤄야 하는 파일이고, 권한이 600 이 아니면 읽지 않는다.
 *
 * 파일은 서버와 관리 도구가 함께 고친다. 관리 도구는 줄을 더하고 SIGHUP 을 보내고,
 * 서버는 쓰인 줄을 지운다. 둘 다 옆에 새 파일을 쓰고 이름을 바꾸는 식으로 고쳐서 반쯤
 * 쓰인 파일이 보이지 않는다. */

#include <stdint.h>

#include "device.h"

#define MAX_PENDING 256

void enroll_init(void);

/* 읽은 줄 수를 돌려준다. 파일이 없으면 기다리는 등록이 없는 것이다 (0). 형식이 틀리면
 * -1 이고 이전에 읽어 둔 목록이 그대로 남는다. 경로는 기억해 두었다가 줄을 지울 때 쓴다. */
int enroll_load(const char *path);

/* 그 ID 로 기다리는 자리. 없거나 만료됐으면 NULL.
 *
 * device_t 로 돌려준다. 핸드셰이크는 상대가 등록된 기기인지 등록하러 온 기기인지를
 * 구분하지 않고 같은 길로 돈다 — 필요한 것은 ID, 키, nonce 를 둘 자리이고 그건 같다. */
device_t *enroll_find(const uint8_t id[DEVICE_ID_LEN]);

/* 그 자리에 기기를 올린다: 기기 목록 파일에 한 줄을 더하고, 기다리던 줄을 지운다.
 * 성공 0, 실패 -1. 기기 목록을 다시 읽는 것은 부르는 쪽의 일이다. */
int enroll_complete(device_t *pending, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t key[AUTH_KEY_LEN], const char *device_path);

/* 감사 로그에 남길 이름. 없으면 빈 문자열. 글자, 숫자, 공백, _ . - 뿐이다. */
const char *enroll_label(const device_t *pending);

int enroll_count(void);

#endif
