#ifndef IDENTITY_H
#define IDENTITY_H

/* 기기 신원 (ID 와 키)을 파일에 둔다.
 *
 * ID 는 이름표라 공개돼도 되고, 키는 이 기기와 서버만 안다. Windows 클라이언트는 키를
 * DPAPI 로 감싸 레지스트리에 두는데, Linux 에는 같은 일을 하는 OS 기본 장치가 없다
 * (커널 키링은 재부팅하면 사라진다). 그래서 root 만 읽을 수 있는 파일에 둔다. 서버의
 * 기기 목록과 같은 방식이다 — 권한이 0600 보다 넓으면 읽지 않는다.
 *
 *   id(32 hex) key(64 hex) [server_pub(128 hex)]
 *
 * 한 줄이다. 서버의 기기 목록(devices.conf)의 앞 두 칸과 같은 모양이라 눈으로 맞춰 볼 수 있다.
 * 세 번째 칸은 등록 코드로 올라간 기기가 그때 받은 서버 공개키다 (v9). 핸드셰이크에서 서버가
 * 내미는 공개키가 이것과 다르면 그 답을 받지 않는다 — 사이에 낀 쪽이 공개키를 바꿔 끼워 감싼
 * 기기 ID 를 보는 것을 막는다. 손으로 올린 기기(enroll 만 한 기기)에는 없다. */

#include <stdint.h>

#include "proto.h"

#define IDENTITY_FILE_DEFAULT	"/var/lib/ztgate/device"

#define IDENTITY_OK		0
#define IDENTITY_NOT_ENROLLED	1	/* 파일이 없다 */
#define IDENTITY_ERROR		(-1)

typedef struct identity {
	uint8_t id[DEVICE_ID_LEN];
	uint8_t key[AUTH_KEY_LEN];
	uint8_t server_pub[VPN_PUB_LEN_WIRE];
	int has_server_pub;
} identity_t;

int identity_load(const char *path, identity_t *out);

/* 새 ID 와 키를 만들기만 한다. 저장하지 않는다.
 *
 * 만드는 것과 저장하는 것을 나눈 것은 등록 코드 때문이다. 서버가 받아 준 뒤에 저장해야
 * 한다. 먼저 저장하면 서버에 닿지 못했을 때 예전 신원은 지워졌고 새 신원은 어디에도
 * 등록되지 않은 채로 남는다. */
int identity_generate(identity_t *out);

/* 저장한다. 이미 있으면 바꾼다. 옆에 새 파일을 다 쓴 뒤 이름을 바꾸므로 반쯤 쓰인
 * 파일이 남지 않는다. */
int identity_save(const char *path, const identity_t *dev);

#endif
