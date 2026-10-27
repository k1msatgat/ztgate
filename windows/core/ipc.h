#ifndef IPC_H
#define IPC_H

/* 서비스(vpn_service.exe)와 그것을 조종하는 프로그램(GUI) 사이의 약속.
 *
 * 지금까지는 GUI 가 터널을 품고 있었다. 창을 닫으면 터널이 끊겼고, 어댑터를 만들려면
 * 관리자 권한이 필요해서 화면을 그리는 코드 전체가 관리자 권한으로 돌았으며, 로그인하기
 * 전에는 연결할 수 없었다. 터널은 서비스가 맡고, GUI 는 권한 없이 떠서 상태를 보고
 * 연결 / 해제를 시키기만 한다.
 *
 * 둘은 이름 있는 파이프로 말한다. 메시지 하나가 WriteFile 한 번이다 (메시지 모드).
 *
 *   ipc_header(8) | 내용
 *
 * 같은 PC 안의 같은 빌드끼리만 말하므로 구조체를 그대로 싣는다. 대신 처음에 서로의 버전과
 * 구조체 크기를 대 보고, 다르면 말을 섞지 않는다 (HELLO). 서비스만 새로 설치하고 GUI 는
 * 예전 것을 띄운 경우에, 어긋난 구조체를 읽어 엉뚱한 화면을 보여 주지 않으려는 것이다.
 *
 * 명령에는 답이 따로 없다. 서비스는 일어난 일을 사건으로 내보내고, 명령의 결과도 그
 * 사건으로 알게 된다 (CONNECT 를 보내면 STATE 가 온다). 답을 기다리는 구조로 만들면
 * 그동안 밀려드는 패킷 사건과 순서를 맞춰야 한다. */

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_PIPE_NAME	L"\\\\.\\pipe\\ztgate"
#define IPC_VERSION	8	/* 2: 사용자 로그인 (LOGIN / LOGOUT), 3: 상태에 연결된 뒤 지난 시간, 4: 서버 여럿, 5: DPoP 증명, 6: IPv6 서버, 7: 서버를 글자(DNS 이름)로, 8: 상태에 터널이 도는지 */

/* 한 메시지의 최대 크기. 패킷 사건을 묶어 보내는 것이 가장 크다. */
#define IPC_MAX_MSG	16384

#define IPC_LOG_LEN	256
#define IPC_CODE_LEN	64	/* 등록 코드를 사람이 적은 그대로 (줄표, 공백 포함) */

typedef enum ipc_type {
	/* GUI -> 서비스 */
	IPC_CMD_HELLO = 1,		/* ipc_hello */
	IPC_CMD_CONNECT,		/* ipc_connect */
	IPC_CMD_DISCONNECT,		/* 내용 없음 */
	IPC_CMD_ENROLL,			/* ipc_enroll */
	IPC_CMD_ENROLL_MANUAL,		/* 내용 없음. 서비스가 ID 와 키를 만들어 돌려준다 */
	IPC_CMD_LOGIN,			/* 사용자의 토큰 (JWT 글자들, 끝의 0 없이) */
	IPC_CMD_LOGOUT,			/* 내용 없음 */
	IPC_CMD_DPOP,			/* ipc_dpop_req. 서비스가 이 PC 의 키로 IdP 에 보낼 DPoP 증명을 만든다 */

	/* 서비스 -> GUI */
	IPC_EVT_HELLO = 100,		/* ipc_hello. 이 뒤로 지금의 상태와 밀린 기록이 온다 */
	IPC_EVT_STATE,			/* ipc_state */
	IPC_EVT_DEVICE,			/* ipc_device */
	IPC_EVT_LOG,			/* 글자들 (끝의 0 없이) */
	IPC_EVT_PACKETS,		/* ipc_packets 뒤에 tunnel_packet_t 가 count 개 */
	IPC_EVT_ENROLL_RESULT,		/* ipc_enroll_result */
	IPC_EVT_ERROR,			/* ipc_error. 명령을 받아 줄 수 없다 */
	IPC_EVT_LOGIN,			/* ipc_login. 로그인 상태가 바뀌었다 */
	IPC_EVT_DPOP			/* ipc_dpop. IPC_CMD_DPOP 의 답 */
} ipc_type_t;

typedef struct ipc_header {
	uint32_t type;		/* ipc_type_t */
	uint32_t len;		/* 뒤따르는 내용의 길이 */
} ipc_header_t;

typedef struct ipc_hello {
	uint32_t version;	/* IPC_VERSION */
	uint32_t packet_size;	/* sizeof(tunnel_packet_t). 빌드가 어긋났는지 본다 */
} ipc_hello_t;

typedef struct ipc_connect {
	wchar_t adapter_name[TUNNEL_ADAPTER_NAME_LEN];
	wchar_t servers[TUNNEL_SERVERS_LEN];	/* tunnel_config_t.servers 그대로 (v7) */
	uint16_t server_port;	/* host byte order */
} ipc_connect_t;

/* GUI 가 IdP 의 토큰 엔드포인트에 보낼 증명 (htm POST). 키는 서비스에만 있다 (dpop.h). */
typedef struct ipc_dpop_req {
	char htu[512];
} ipc_dpop_req_t;

typedef struct ipc_dpop {
	char proof[1024];	/* 비어 있으면 만들지 못했다 */
} ipc_dpop_t;

typedef struct ipc_enroll {
	wchar_t servers[TUNNEL_SERVERS_LEN];	/* 받아 주는 주소에 차례로 올린다 (tunnel_enroll) */
	uint16_t server_port;
	char code[IPC_CODE_LEN];
} ipc_enroll_t;

/* connected_ms 는 터널이 연결된 뒤 지난 시간이다. 연결된 때를 아는 것은 서비스뿐이라,
 * 이것이 없으면 GUI 는 자기가 "연결됨"을 처음 본 때부터 센다 — GUI 를 다시 켜면 몇 시간째
 * 붙어 있는 터널이 00:00:00 으로 보였다. 시각이 아니라 지난 양으로 보내 두 프로세스의
 * 시계를 맞출 필요가 없게 한다. */
typedef struct ipc_state {
	uint32_t state;		/* tunnel_state_t */
	uint32_t wanted;	/* 사용자가 연결을 원한 상태인가. 끊겨도 서비스가 다시 시도한다 */
	uint32_t running;	/* 서비스 안에서 터널이 돌고 있다. wanted 여도 다시 올리기를 기다리는 동안
				 * (등록되지 않았다, 지난번이 끝났다)은 0 이다 — 그때는 등록을 받는다 */
	uint32_t reserved;
	uint64_t connected_ms;	/* 연결된 뒤 지난 ms. 재연결 동안은 이어서 세고, 끊기거나 거부되면 0 */
} ipc_state_t;

typedef struct ipc_device {
	uint32_t enrolled;
	uint8_t id[DEVICE_ID_LEN];
} ipc_device_t;

typedef struct ipc_packets {
	uint64_t lost;		/* 이 GUI 가 받기 전에 밀려나 버려진 패킷의 누계 */
	uint32_t count;
	uint32_t reserved;
} ipc_packets_t;

typedef struct ipc_enroll_result {
	uint32_t result;	/* tunnel_enroll_result_t */
	uint32_t has_key;	/* ENROLL_MANUAL 의 답일 때만 1: key 를 화면에 한 번 보여 준다 */
	uint8_t id[DEVICE_ID_LEN];
	uint8_t key[AUTH_KEY_LEN];
} ipc_enroll_result_t;

/* 사용자 로그인.
 *
 * 토큰을 IdP 에서 받아 오는 것은 GUI 다. 로그인은 그 사람의 일이라 그 사람의 계정으로 도는
 * 프로그램이 브라우저를 띄우고, 갱신에 쓰는 refresh token 도 그쪽에 둔다. 서비스는 받은
 * 토큰을 터널에 넘겨 서버로 보내기만 한다.
 *
 * 토큰은 그것을 준 GUI 가 붙어 있는 동안만 쓴다. GUI 가 떨어지면(로그오프, 종료) 서비스는
 * 로그아웃한다. 터널은 PC 의 것이라 그대로 두지만, 다음에 앉는 사람이 앞사람의 신원으로
 * 쓰면 안 된다. */
typedef enum ipc_login_state {
	IPC_LOGIN_NONE = 0,		/* 토큰이 없다 */
	IPC_LOGIN_PENDING,		/* 토큰을 받았고 서버의 답을 기다린다 (터널이 닫혀 있으면 열릴 때까지) */
	IPC_LOGIN_DONE			/* 서버가 답했다. status 를 본다 */
} ipc_login_state_t;

typedef struct ipc_login {
	uint32_t state;		/* ipc_login_state_t */
	uint32_t status;	/* login_status_t. DONE 일 때만 */
	int64_t expires;	/* 토큰의 exp (Unix time). 실패면 0 */
	char user[LOGIN_USER_MAX + 1];	/* 성공했을 때의 사용자 이름 */
} ipc_login_t;

typedef enum ipc_error_code {
	IPC_ERR_BUSY = 1,		/* 터널이 열려 있다. 먼저 해제해야 한다 */
	IPC_ERR_NOT_ENROLLED,		/* 등록되지 않은 기기다 */
	IPC_ERR_BAD_REQUEST,		/* 내용의 길이나 값이 맞지 않는다 */
	IPC_ERR_INTERNAL,
	IPC_ERR_POLICY			/* 관리 정책이 막는다 (AlwaysOn 인데 해제하라고 했다) */
} ipc_error_code_t;

typedef struct ipc_error {
	uint32_t code;
} ipc_error_t;

/* 한 메시지에 묶을 수 있는 패킷 사건의 수. */
#define IPC_PACKETS_PER_MSG \
	((IPC_MAX_MSG - sizeof(ipc_header_t) - sizeof(ipc_packets_t)) / sizeof(tunnel_packet_t))

/* 메시지 하나를 보낸다. 파이프는 FILE_FLAG_OVERLAPPED 로 연 것이어야 한다.
 * 상대가 읽지 않아 timeout_ms 안에 나가지 못하면 실패다 — 멈춘 상대를 기다리느라 이쪽이
 * 멈추지 않는다. cancel 이 signaled 되어도 그만둔다 (NULL 이면 보지 않는다).
 * 성공 0, 실패 -1. */
int ipc_send(HANDLE pipe, uint32_t type, const void *body, uint32_t len,
		DWORD timeout_ms, HANDLE cancel);

#ifdef __cplusplus
}
#endif

#endif
