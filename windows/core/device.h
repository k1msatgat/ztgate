#ifndef DEVICE_H
#define DEVICE_H

/* 기기 신원.
 *
 * 지금까지 서버는 "터널 IP 를 자칭한 누군가"만 알았다. 기기마다 고유한 ID 와
 * 비밀 키를 하나씩 주고 서버에 등록해 두면, 서버는 접속한 쪽이 등록된 그 기기인지
 * 확인할 수 있다. ID 는 이름표라 공개돼도 되고, 키는 이 기기와 서버만 안다.
 *
 * 등록(enroll)은 기기에서 한 번 한다. 여기서 만든 ID 와 키를 관리자가 서버의
 * 기기 목록에 옮겨 적는다. */

#include <stdint.h>

#include "proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct device {
	uint8_t id[DEVICE_ID_LEN];
	uint8_t key[AUTH_KEY_LEN];

	/* 등록 코드로 올라갈 때 받은 서버 공개키 (v9). 핸드셰이크에서 서버가 내미는 공개키가 이것과
	 * 다르면 답하지 않는다 — 사이에 낀 쪽이 바꿔 끼운 공개키로 감싼 기기 ID 를 보지 못하게.
	 * 손으로 올린 기기에는 없다. 비밀이 아니라서 DPAPI 로 감싸지 않는다. */
	uint8_t server_pub[VPN_PUB_LEN_WIRE];
	uint8_t has_server_pub;
} device_t;

#define DEVICE_OK		0
#define DEVICE_NOT_ENROLLED	1
#define DEVICE_ERROR		(-1)

/* 신원을 사용자 계정이 아니라 PC 에 둔다 (서비스용). 다른 함수를 부르기 전에 한 번 부른다. */
void device_use_machine_store(void);

/* 저장된 신원을 읽는다. */
int device_load(device_t *out);

/* 새 ID 와 키를 만들기만 한다. 저장하지 않는다. */
int device_generate(device_t *out);

/* 신원을 저장한다. 이미 있으면 덮어쓴다.
 *
 * 만드는 것과 저장하는 것을 나눈 것은 등록 코드 때문이다. 서버가 받아 준 뒤에 저장해야
 * 한다. 먼저 저장하면 서버에 닿지 못했을 때 예전 신원은 지워졌고 새 신원은 어디에도
 * 등록되지 않은 채로 남는다. */
int device_save(const device_t *dev);

/* 새 ID 와 키를 만들어 저장한다. 이미 있으면 덮어쓴다 — 서버에 등록된 예전 키는
 * 더 이상 맞지 않게 되므로 호출자가 사용자에게 확인받아야 한다. */
int device_enroll(device_t *out);

#ifdef __cplusplus
}
#endif

#endif
