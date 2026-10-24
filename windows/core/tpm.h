#ifndef TPM_H
#define TPM_H

/* 기기의 고정 키 쌍을 TPM 안에 둔다 (Microsoft Platform Crypto Provider).
 *
 * 등록 코드로 올라가는 기기는 고정 키 쌍을 만들어 공개키를 서버에 올리고, 기기 키를
 * ECDH(이 비밀키, 서버 공개키) 에서 뽑는다 (secure.h 의 secure_static_key). TPM 이 없을 때는 그
 * 비밀키를 한 번 쓰고 버린 뒤 뽑은 기기 키를 DPAPI 로 감싸 레지스트리에 둔다 — 그 값과 DPAPI 비밀을
 * 함께 빼 가면 다른 PC 에서도 이 기기가 될 수 있다.
 *
 * TPM 이 있으면 비밀키는 TPM 밖으로 나오지 않는다. 레지스트리에는 기기 키를 두지 않고, 터널을 열
 * 때마다 TPM 에 ECDH 를 시켜 기기 키를 다시 뽑아 메모리에서만 쓴다. 디스크를 통째로 떠 가도 이
 * PC 의 TPM 없이는 기기 키가 나오지 않는다.
 *
 * machine 이 0 이 아니면 PC 의 키(서비스, SYSTEM), 0 이면 지금 사용자의 키(콘솔). */

#include <stdint.h>

#include "crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TPM_KEY_NAME	L"ztgate-device"

/* TPM 공급자를 열 수 있으면 1. */
int tpm_available(void);

/* 키 쌍을 새로 만든다 (있던 것은 지운다). 공개키 X | Y 를 pub 에. 0 성공. */
int tpm_create(int machine, const wchar_t *name, uint8_t pub[VPN_PUB_LEN]);

/* 있는 키의 공개키. 0 성공. */
int tpm_public(int machine, const wchar_t *name, uint8_t pub[VPN_PUB_LEN]);

/* SHA-256(ECDH 공유점의 X) — crypt_ecdh_derive 와 같은 값. 0 성공. */
int tpm_ecdh(int machine, const wchar_t *name, const uint8_t peer_pub[VPN_PUB_LEN],
		uint8_t secret[VPN_SECRET_LEN]);

void tpm_delete(int machine, const wchar_t *name);

/* 임시 키로 TPM 의 ECDH 가 소프트웨어(crypt_ecdh_*)와 같은 값을 내는지 본다. 0 같다, 1 TPM 없음,
 * -1 다르거나 실패. */
int tpm_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
