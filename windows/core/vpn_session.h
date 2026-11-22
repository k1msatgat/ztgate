#ifndef VPN_SESSION_H
#define VPN_SESSION_H

/* GUI 가 터널을 조종하는 인터페이스. 채우는 것은 vpn_remote.c 다 (서비스에 파이프로 붙는다).
 * 로그와 상태 변화는 PostMessage 로 UI 스레드에 넘긴다.
 *
 * UI 프레임워크(MFC / 순수 Win32)에 의존하지 않도록 HWND만 알고 있다. */

#include <winsock2.h>
#include <windows.h>

#include "tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

/* WM_APP 이상은 애플리케이션이 자유롭게 쓸 수 있는 범위다. */
#define WM_VPN_LOG	(WM_APP + 1)	/* lParam = char*, 받는 쪽이 vpn_session_free_log()로 해제 */
#define WM_VPN_STATE	(WM_APP + 2)	/* wParam = tunnel_state_t */
#define WM_VPN_DONE	(WM_APP + 3)	/* wParam = tunnel_run() 반환값 (0 정상 종료) */
#define WM_VPN_PACKETS	(WM_APP + 4)	/* 링버퍼에 패킷이 쌓였다. drain_packets 로 꺼낸다 */

/* 패킷 링버퍼 크기. UI가 못 따라오면 가장 오래된 것부터 버린다. */
#define VPN_PACKET_RING 4096

/* 종료 요청 후 워커를 기다리는 한도. 어댑터 정리에 보통 1초 안 걸린다. */
#define VPN_STOP_TIMEOUT_MS 10000

typedef struct vpn_session vpn_session_t;

/* notify는 메시지를 받을 창. 창보다 세션이 먼저 끝나야 한다. */
vpn_session_t *vpn_session_create(HWND notify);

/* 워커가 돌고 있으면 종료를 요청하고 기다린 뒤 해제한다. */
void vpn_session_destroy(vpn_session_t *s);

/* cfg를 구조체째로 복사하므로 호출자는 스택 변수를 넘겨도 된다.
 * on_log / on_state / ctx는 이 계층이 덮어쓰므로 UI가 채우지 않는다.
 * 0 성공, -1 실패(이미 돌고 있거나 스레드 생성 실패). */
int vpn_session_start(vpn_session_t *s, const tunnel_config_t *cfg);

/* 종료 요청만 하고 바로 돌아온다. UI는 멈추지 않고 WM_VPN_DONE을 기다리면 된다. */
void vpn_session_stop(vpn_session_t *s);

/* 워커가 끝나기를 기다리고 스레드 핸들을 정리한다. 0 성공, -1 타임아웃. */
int vpn_session_join(vpn_session_t *s, DWORD timeout_ms);

/* 워커를 띄운 뒤 아직 join하지 않았으면 0이 아니다. */
int vpn_session_active(const vpn_session_t *s);

/* 창을 없애기 전에 큐에 남은 WM_VPN_LOG의 버퍼를 해제한다.
 * 창을 소유한 스레드에서 불러야 한다. */
void vpn_session_drain(HWND notify);

void vpn_session_free_log(char *line);

/* 링버퍼에서 최대 max개를 꺼내 out에 복사하고 꺼낸 개수를 돌려준다.
 * WM_VPN_PACKETS를 받은 UI 스레드에서 0이 나올 때까지 부른다. */
int vpn_session_drain_packets(vpn_session_t *s, tunnel_packet_t *out, int max);

/* 링버퍼가 꽉 차서 버린 패킷 수. 0이 아니면 UI가 유실을 표시해야 한다. */
uint64_t vpn_session_lost_packets(vpn_session_t *s);

#ifdef __cplusplus
}
#endif

#endif
