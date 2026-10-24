#ifndef VPN_REMOTE_H
#define VPN_REMOTE_H

/* 서비스에 붙어 터널을 조종하는 쪽 (GUI 용).
 *
 * vpn_session.h 의 함수들을 그대로 채운다. 차이는 그 뒤에 무엇이 있는가다.
 *
 *   vpn_session.c   이 프로세스 안의 워커 스레드가 tunnel_run() 을 돈다
 *   vpn_remote.c    터널은 서비스(vpn_service.exe)에 있고, 여기서는 파이프로 명령을
 *                   보내고 사건을 받는다
 *
 * 같은 이름으로 채운 것은 GUI 를 거의 그대로 두기 위해서다. 화면은 전과 같이 start /
 * stop 을 부르고 WM_VPN_* 메시지를 받는다. 둘 중 하나만 링크한다.
 *
 * 달라지는 것
 *   - 이 프로그램을 닫아도 터널은 그대로다. destroy 는 서비스에서 떨어질 뿐이다.
 *   - 이 프로그램에는 관리자 권한이 필요 없다.
 *   - 기기의 키를 이 프로그램이 읽지 않는다. 신원은 서비스가 만들고 서비스만 읽을 수 있는
 *     곳에 둔다. 여기서는 기기 ID 만 안다. */

#include "vpn_session.h"
#include "device.h"
#include "ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* vpn_session.h 의 WM_VPN_* 에 더해 오는 메시지. */
#define WM_VPN_SERVICE	(WM_APP + 5)	/* wParam = vpn_remote_link_t. 서비스와의 연결이 바뀌었다 */
#define WM_VPN_DEVICE	(WM_APP + 6)	/* 기기의 등록 상태가 바뀌었다. vpn_remote_device 로 읽는다 */
#define WM_VPN_ERROR	(WM_APP + 7)	/* wParam = ipc_error_code_t. 서비스가 명령을 받지 않았다 */
#define WM_VPN_LOGIN	(WM_APP + 8)	/* 사용자 로그인 상태가 바뀌었다. vpn_remote_login_info 로 읽는다 */

typedef enum vpn_remote_link {
	VPN_REMOTE_DOWN = 0,		/* 서비스에 닿지 못한다 (설치되지 않았거나 멈춰 있다) */
	VPN_REMOTE_UP,			/* 붙었다 */
	VPN_REMOTE_MISMATCH,		/* 서비스가 이 프로그램과 다른 빌드다 */
	VPN_REMOTE_BUSY			/* 다른 프로그램이 이미 서비스에 붙어 있다 */
} vpn_remote_link_t;

/* 지금 서비스와의 연결 (vpn_remote_link_t). */
int vpn_remote_link(const vpn_session_t *s);

/* 서비스가 알려 준, 터널이 연결된 때 (GetTickCount64 기준). 연결되지 않았거나 서비스에
 * 붙어 있지 않으면 0. 이 프로그램을 나중에 켜도 터널이 연결된 때부터 셀 수 있다. */
ULONGLONG vpn_remote_connected_since(vpn_session_t *s);

/* 등록된 기기면 1 을 돌려주고 id 를 채운다. 아니면 (또는 서비스에 붙지 못했으면) 0. */
int vpn_remote_device(vpn_session_t *s, uint8_t id[DEVICE_ID_LEN]);

/* 등록 코드로 서버에 이 PC 를 올리라고 서비스에 시킨다. tunnel_enroll_result_t 를 돌려준다.
 * 답이 올 때까지 블로킹한다 (길어야 수십 초). server_ip 는 IPv4 또는 IPv6. */
int vpn_remote_enroll(vpn_session_t *s, const tunnel_addr_t *server_ip, uint16_t server_port, const char *code);

/* 코드 없이: 서비스가 새 신원을 만들어 저장하고 ID 와 키를 돌려준다. 관리자가 서버에
 * 손으로 옮겨 적는다. 키를 볼 수 있는 것은 이 한 번뿐이다. DEVICE_OK / DEVICE_ERROR. */
int vpn_remote_enroll_manual(vpn_session_t *s, device_t *out);

/* IdP 의 토큰 엔드포인트 htu 에 보낼 DPoP 증명 (서비스가 이 PC 의 키로 만든다). 블로킹 (길어야 5초).
 * 0 성공. */
int vpn_remote_dpop(vpn_session_t *s, const char *htu, char *out, size_t cap);

/* 사용자의 토큰(JWT)을 서비스에 건넨다. 서비스가 세션 안으로 서버에 보내고, 서버의 답은
 * WM_VPN_LOGIN 으로 알게 된다. 토큰은 이 프로그램이 서비스에 붙어 있는 동안만 쓰인다 —
 * 서비스에 다시 붙으면(서비스 재시작) 다시 건네야 한다. 0 성공, -1 실패. */
int vpn_remote_login(vpn_session_t *s, const char *token, size_t len);

void vpn_remote_logout(vpn_session_t *s);

/* 서비스가 마지막으로 알려 준 로그인 상태. 붙어 있지 않으면 IPC_LOGIN_NONE. */
void vpn_remote_login_info(vpn_session_t *s, ipc_login_t *out);

#ifdef __cplusplus
}
#endif

#endif
