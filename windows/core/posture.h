#ifndef POSTURE_H
#define POSTURE_H

/* 단말 보안 상태(posture) 수집.
 *
 * 터널은 "누가 접속했는가"만 안다. ZTNA 는 여기에 "그 단말이 지금 믿을 만한
 * 상태인가"를 더해 접근을 판단하므로, 클라이언트가 자기 상태를 읽어 서버에
 * 보고해야 한다. 이 모듈은 읽는 것까지만 하고 판단하지 않는다. 무엇이 통과인지는
 * 서버 정책이 정한다 — 클라이언트가 스스로 "합격"이라고 말하게 두면 정책을
 * 바꿀 때마다 클라이언트를 다시 배포해야 한다.
 *
 * tunnel.c 와 마찬가지로 UI 프레임워크에 의존하지 않는 순수 Win32/C 다. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 켜짐 / 꺼짐 두 값으로는 부족하다. 조회 자체가 실패한 경우를 "꺼짐"으로
 * 보고하면 서버는 멀쩡한 단말을 막고, "켜짐"으로 보고하면 확인하지 못한 것을
 * 통과시킨다. 모른다는 사실을 그대로 올려 서버 정책이 어떻게 다룰지 정하게 한다.
 * 0 이 UNKNOWN 이라 memset 으로 초기화한 구조체는 전부 "모름"에서 시작한다. */
typedef enum posture_state {
	POSTURE_UNKNOWN = 0,
	POSTURE_OFF,
	POSTURE_ON
} posture_state_t;

typedef struct posture {
	/* OS 버전. 읽지 못하면 셋 다 0 이다. */
	uint32_t os_major;
	uint32_t os_minor;
	uint32_t os_build;

	/* Windows 방화벽. 지금 적용 중인 프로필이 모두 켜져 있어야 ON 이다. */
	uint8_t firewall;		/* posture_state_t */

	/* 백신. Windows 보안 센터가 "정상"으로 보는 제품이 있어야 ON 이다. */
	uint8_t antivirus;		/* posture_state_t */

	/* 시스템 드라이브의 BitLocker. 보호가 켜져 있어야 ON 이다 (암호화만 돼 있고 보호가 일시
	 * 중지됐으면 OFF). 관리자가 아니면 WMI 로 읽지 못해 셸 속성으로 읽는다. */
	uint8_t disk;			/* posture_state_t */
} posture_t;

/* 현재 상태를 읽어 out 을 채운다. 항목별로 실패할 수 있고, 실패한 항목은
 * "모름" 값으로 남는다. 한 항목을 못 읽었다고 나머지를 버리지 않는다. */
void posture_collect(posture_t *out);

#ifdef __cplusplus
}
#endif

#endif
