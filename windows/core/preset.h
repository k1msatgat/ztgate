#ifndef PRESET_H
#define PRESET_H

/* 설치할 때 받은 설정: msiexec /i ztgate.msi SERVER=vpn.example.com PORT=9000 CODE=7K2QF-...
 *
 * MSI 는 vpn_service preset 을 시스템 계정으로 띄우고(ztgate.wxs), 그것이 아래 둘에 적는다.
 *
 *   HKLM\SOFTWARE\ztgate\install         누구나 읽는다
 *     servers  REG_SZ     GUI 의 서버 칸이 비어 있을 때 쓰는 값 (사용자가 적은 값과 정책이 앞선다)
 *     port     REG_DWORD
 *
 *   HKLM\SOFTWARE\ztgate\enroll          SYSTEM 과 Administrators 만 (PRESET_ENROLL_SDDL)
 *     servers  REG_SZ     이 서버에
 *     port     REG_DWORD
 *     code     REG_SZ     이 코드로 등록하라. 한 번 쓰이면 끝나는 비밀이라 사용자는 읽지 못하게 둔다
 *
 * 신원의 주인은 서비스다 (device_use_machine_store, TPM). 그래서 MSI 는 등록하지 않고 적어 두기만
 * 하고, 서비스가 뜰 때와 GUI 가 붙을 때 그 코드로 등록한다. 서버에 닿지 못하면 코드를 두고 다시
 * 해 보고, 서버가 받지 않으면(만료, 이미 쓰임) 지운다 (preset_after). */

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PRESET_REG_PATH		L"Software\\ztgate\\install"
#define PRESET_ENROLL_PATH	L"Software\\ztgate\\enroll"
/* 물려받지 않는다(P). HKLM\SOFTWARE 의 "Users 읽기"가 따라 내려오면 코드가 보인다. */
#define PRESET_ENROLL_SDDL	L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)"
#define PRESET_CODE_LEN		64	/* IPC_CODE_LEN 과 같다 */
#define PRESET_DEFAULT_PORT	9000

typedef struct preset {
	wchar_t servers[TUNNEL_SERVERS_LEN];	/* tunnel_check_servers 를 통과했다 */
	uint16_t port;
	char code[PRESET_CODE_LEN];		/* 비어 있으면 등록하지 않는다. 있으면 형식을 본 코드 */
} preset_t;

typedef enum preset_error {
	PRESET_OK = 0,
	PRESET_BAD_SERVER = 2,		/* vpn_service preset 의 종료 코드이기도 하다 (MSI 기록에 남는다) */
	PRESET_BAD_PORT,
	PRESET_BAD_CODE,
	PRESET_NO_SERVER,		/* 코드는 있는데 어느 서버인지 모른다 */
	PRESET_CANNOT_WRITE		/* 관리자가 아니다 */
} preset_error_t;

/* 서비스가 설치 때 받은 코드를 어디까지 했는가. GUI 가 보여 준다 (ipc_device). */
typedef enum preset_phase {
	PRESET_NONE = 0,	/* 받은 코드가 없다, 또는 다 썼다 */
	PRESET_WAITING,		/* 코드가 있다. 아직이거나, 서버에 닿지 못해 다시 해 본다 */
	PRESET_FAILED		/* 서버가 받지 않아 코드를 지웠다. 새 코드가 있어야 한다 */
} preset_phase_t;

typedef struct preset_step {
	preset_phase_t phase;
	int drop;		/* 코드를 지운다 */
} preset_step_t;

/* 경계: 사람이 적은 글자를 preset 으로. port 가 비어 있으면 9000, code 가 비어 있으면 서버만.
 * preset_error_t. */
int preset_parse(const wchar_t *servers, const wchar_t *port, const wchar_t *code, preset_t *out);

/* 한 번 해 본 뒤에 할 일. enrolled 는 해 보기 전에 이미 등록된 기기였는가 (그러면 코드를 쓰지 않고
 * 지운다 — 있는 신원을 설치 명령이 덮지 않는다), result 는 tunnel_enroll_result_t. */
preset_step_t preset_after(int enrolled, int result);

/* 서버에 닿지 못한 tries 번째 뒤에 다시 해 볼 때까지 (ms). 30초에서 두 배씩, 30분까지. */
ULONGLONG preset_retry_ms(unsigned tries);

/* 레지스트리. 0 성공, -1 실패. */
int preset_defaults_save(const preset_t *p);
int preset_enroll_save(const preset_t *p);	/* p->code 가 있어야 한다 */
/* 1 기다리는 코드가 있다, 0 없다, -1 있지만 읽을 수 없거나 형식이 틀렸다 (지워야 한다). */
int preset_enroll_load(preset_t *out);
void preset_enroll_drop(void);

int preset_selftest(void);

/* 설치 때 받은 서버 (GUI 가 서버 칸의 기본값으로). 없으면 0. */
static __inline int preset_defaults_load(wchar_t servers[TUNNEL_SERVERS_LEN], uint16_t *port)
{
	DWORD len = TUNNEL_SERVERS_LEN * sizeof(wchar_t), v = 0, vlen = sizeof(v);

	servers[0] = L'\0';
	if (RegGetValueW(HKEY_LOCAL_MACHINE, PRESET_REG_PATH, L"servers", RRF_RT_REG_SZ, NULL, servers, &len) !=
			ERROR_SUCCESS || tunnel_check_servers(servers) < 0) {
		servers[0] = L'\0';
		return 0;
	}
	*port = RegGetValueW(HKEY_LOCAL_MACHINE, PRESET_REG_PATH, L"port", RRF_RT_REG_DWORD, NULL, &v, &vlen) ==
		ERROR_SUCCESS && v > 0 && v <= 65535 ? (uint16_t)v : PRESET_DEFAULT_PORT;
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
