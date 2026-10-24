/* vpn_service.exe — 터널을 맡는 Windows 서비스.
 *
 *   vpn_service install      Program Files 에 복사하고 서비스로 등록해 시작한다 (관리자)
 *   vpn_service uninstall    멈추고 지운다 (관리자)
 *   vpn_service run          서비스로 등록하지 않고 이 콘솔에서 돈다 (관리자, 디버깅용)
 *   vpn_service ctl ...      돌고 있는 서비스에 말을 건다 (권한 필요 없음, 확인용)
 *
 * 인자 없이 뜨는 것은 서비스 관리자가 띄웠을 때뿐이다.
 *
 * 스레드는 둘이다.
 *   서비스 스레드   파이프(GUI 의 명령)와 워커의 끝남을 한 곳에서 기다린다
 *   워커           tunnel_run() 을 돈다. 올라오는 로그 / 상태 / 패킷을 기록에 쌓기만 한다
 *
 * 워커는 파이프에 직접 쓰지 않는다. GUI 가 읽지 않고 멈춰 있으면 파이프에 쓰는 쪽이
 * 멈추는데, 그게 터널을 나르는 스레드여서는 안 된다. */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#include "tunnel.h"
#include "device.h"
#include "crypt.h"
#include "ipc.h"
#include "filelog.h"

#define SERVICE_NAME	L"ztgate"
#define SERVICE_DISPLAY	L"ztgate tunnel"
#define INSTALL_DIR	L"%ProgramFiles%\\ztgate"
#define STATE_REG_PATH	L"Software\\ztgate\\service"

/* 연결을 원하는데 터널이 내려갔을 때 다시 올리기까지의 시간. 부팅 직후에는 네트워크가
 * 아직 없어 첫 시도가 실패하는 것이 보통이다. */
#define RETRY_MSEC	15000

#define SEND_TIMEOUT_MSEC	3000
#define WORKER_STOP_MSEC	10000

#define LOG_RING	256
#define PACKET_RING	4096

/* 한 번 깨어났을 때 GUI 로 보내는 패킷 묶음의 한도. 패킷이 계속 밀려들어도 명령을
 * 읽으러 돌아갈 수 있어야 한다. */
#define FLUSH_BATCHES	32

/* ---- 서비스의 상태 --------------------------------------------------------- */
static HANDLE stop_all;		/* manual-reset. 서비스를 내린다 */
static HANDLE notify;		/* auto-reset. 워커가 기록에 무언가를 쌓았다 */
static CRITICAL_SECTION lock;	/* 아래의 기록과 state 를 지킨다 */
static int interactive;		/* run 으로 떴다: 로그를 콘솔에도 찍는다 */

/* 워커 */
static HANDLE worker;
static HANDLE tunnel_stop;	/* manual-reset. 터널만 내린다 */
static tunnel_config_t run_cfg;
static int wanted;		/* 사용자가 연결을 원한다. 터널이 내려가도 다시 올린다 */
static ULONGLONG retry_at;	/* 0 이 아니면 그때 다시 올린다 */
static uint32_t state = TUNNEL_STATE_STOPPED;
static ULONGLONG connected_at;	/* 처음 연결된 때 (GetTickCount64). 0 이면 연결되지 않았다 */
static int state_dirty;

/* 기록. GUI 가 붙어 있지 않을 때에도 쌓인다 — 나중에 붙은 GUI 가 그동안의 일을 본다.
 * seq 는 지금까지 쌓은 개수이고, 항목 i 는 [i % RING] 자리에 있다. */
static char logs[LOG_RING][IPC_LOG_LEN];
static uint64_t log_seq;
static tunnel_packet_t packets[PACKET_RING];
static uint64_t pkt_seq;

/* 사용자 로그인. 토큰은 터널과 함께 쓰는 자리에 두고, 화면에 보일 상태는 따로 둔다. */
static tunnel_login_t login;
static ipc_login_t login_info;	/* lock 이 지킨다 */
static int login_dirty;

/* 붙어 있는 GUI. 한 번에 하나다. */
static HANDLE pipe = INVALID_HANDLE_VALUE;
static OVERLAPPED pipe_ov;	/* 접속을 기다리는 중이거나, 붙은 뒤에는 읽기를 기다리는 중 */
static int client_on;		/* 접속했다 */
static int client_ready;	/* HELLO 까지 주고받았다 */
static uint8_t rbuf[IPC_MAX_MSG];
static uint64_t c_log_seq;	/* 이 GUI 에게 여기까지 보냈다 */
static uint64_t c_pkt_seq;
static uint64_t c_lost;

/* ---- 기록 ------------------------------------------------------------------ */
static void push_log(const char *line)
{
	EnterCriticalSection(&lock);
	strncpy(logs[log_seq % LOG_RING], line, IPC_LOG_LEN - 1);
	logs[log_seq % LOG_RING][IPC_LOG_LEN - 1] = '\0';
	log_seq++;
	LeaveCriticalSection(&lock);

	filelog_write(line);
	if (interactive) {
		printf("%s\n", line);
		fflush(stdout);
	}
	SetEvent(notify);
}

static void slog(const char *fmt, ...)
{
	char line[IPC_LOG_LEN];
	va_list ap;
	int n;

	n = snprintf(line, sizeof(line), "[svc] ");
	va_start(ap, fmt);
	vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
	va_end(ap);

	push_log(line);
}

static void set_state(uint32_t s)
{
	EnterCriticalSection(&lock);
	state = s;
	/* 서버 무응답으로 다시 맺는 동안(RECONNECTING)은 같은 연결로 친다. 거부되면 그때부터는
	 * 통하지 않으므로, 다시 받아들여지면 새로 센다. */
	if (s == TUNNEL_STATE_CONNECTED) {
		if (connected_at == 0) {
			connected_at = GetTickCount64();
		}
	}
	else if (s == TUNNEL_STATE_STOPPED || s == TUNNEL_STATE_DENIED) {
		connected_at = 0;
	}
	state_dirty = 1;
	LeaveCriticalSection(&lock);
	SetEvent(notify);
}

/* 아래 셋은 워커 스레드에서 불린다. */
static void on_log(void *ctx, const char *line)
{
	(void)ctx;
	push_log(line);
}

static void on_state(void *ctx, tunnel_state_t s)
{
	(void)ctx;
	set_state((uint32_t)s);
}

static void on_login(void *ctx, int status, int64_t expires, const char *user)
{
	(void)ctx;

	EnterCriticalSection(&lock);
	login_info.state = IPC_LOGIN_DONE;
	login_info.status = (uint32_t)status;
	login_info.expires = expires;
	strncpy(login_info.user, user, sizeof(login_info.user) - 1);
	login_info.user[sizeof(login_info.user) - 1] = '\0';
	login_dirty = 1;
	LeaveCriticalSection(&lock);
	SetEvent(notify);
}

static void on_packet(void *ctx, const tunnel_packet_t *p)
{
	(void)ctx;

	EnterCriticalSection(&lock);
	packets[pkt_seq % PACKET_RING] = *p;
	pkt_seq++;
	LeaveCriticalSection(&lock);
	SetEvent(notify);
}

/* ---- 기억해 둘 것 ----------------------------------------------------------
 * 마지막으로 연결하라고 한 곳과, 지금도 연결을 원하는지. 서비스가 다시 뜨면(재부팅)
 * 이어서 연결한다. 로그온한 사람이 없어도 터널이 열려 있게 하려는 것이다. */
static void remember(void)
{
	DWORD ip = run_cfg.server_ip.s_addr;
	DWORD port = run_cfg.server_port;
	DWORD want = (DWORD)wanted;
	HKEY key;

	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, 0, NULL, 0, KEY_SET_VALUE,
				NULL, &key, NULL) != ERROR_SUCCESS) {
		return;
	}

	RegSetValueExW(key, L"adapter", 0, REG_SZ, (const BYTE *)run_cfg.adapter_name,
			(DWORD)((wcslen(run_cfg.adapter_name) + 1) * sizeof(wchar_t)));
	RegSetValueExW(key, L"server", 0, REG_DWORD, (const BYTE *)&ip, sizeof(ip));
	RegSetValueExW(key, L"port", 0, REG_DWORD, (const BYTE *)&port, sizeof(port));
	RegSetValueExW(key, L"wanted", 0, REG_DWORD, (const BYTE *)&want, sizeof(want));
	RegCloseKey(key);
}

static int recall(void)
{
	DWORD ip = 0, port = 0, want = 0;
	DWORD len;

	len = sizeof(run_cfg.adapter_name);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, L"adapter", RRF_RT_REG_SZ, NULL,
				run_cfg.adapter_name, &len) != ERROR_SUCCESS) {
		return 0;
	}
	len = sizeof(ip);
	RegGetValueW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, L"server", RRF_RT_REG_DWORD, NULL, &ip, &len);
	len = sizeof(port);
	RegGetValueW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, L"port", RRF_RT_REG_DWORD, NULL, &port, &len);
	len = sizeof(want);
	RegGetValueW(HKEY_LOCAL_MACHINE, STATE_REG_PATH, L"wanted", RRF_RT_REG_DWORD, NULL, &want, &len);

	run_cfg.server_ip.s_addr = ip;
	run_cfg.server_port = (uint16_t)port;

	return want != 0 && ip != 0 && port != 0 && port <= 65535;
}

/* ---- 워커 ------------------------------------------------------------------ */
static DWORD WINAPI worker_main(LPVOID arg)
{
	(void)arg;

	return (DWORD)tunnel_run(&run_cfg, tunnel_stop);
}

/* run_cfg 에 적힌 곳으로 터널을 올린다. 0 성공, 아니면 ipc_error_code_t. */
static int tunnel_start(void)
{
	device_t dev;
	int enrolled;

	enrolled = device_load(&dev);
	if (enrolled != DEVICE_OK) {
		SecureZeroMemory(&dev, sizeof(dev));
		return enrolled == DEVICE_NOT_ENROLLED ? IPC_ERR_NOT_ENROLLED : IPC_ERR_INTERNAL;
	}

	memcpy(run_cfg.device_id, dev.id, sizeof(run_cfg.device_id));
	memcpy(run_cfg.device_key, dev.key, sizeof(run_cfg.device_key));
	memcpy(run_cfg.server_pub, dev.server_pub, sizeof(run_cfg.server_pub));
	run_cfg.has_server_pub = dev.has_server_pub;
	SecureZeroMemory(&dev, sizeof(dev));

	run_cfg.log_packets = 0;
	run_cfg.on_log = on_log;
	run_cfg.on_state = on_state;
	run_cfg.on_packet = on_packet;
	run_cfg.login = &login;
	run_cfg.on_login = on_login;
	run_cfg.ctx = NULL;

	ResetEvent(tunnel_stop);
	retry_at = 0;

	worker = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
	if (!worker) {
		slog("CreateThread failed: %lu", GetLastError());
		SecureZeroMemory(run_cfg.device_key, sizeof(run_cfg.device_key));
		return IPC_ERR_INTERNAL;
	}

	return 0;
}

/* 워커가 끝났다. 사용자가 해제한 것이 아니면 잠시 뒤에 다시 올린다. */
static void worker_exited(void)
{
	DWORD code = 1;

	GetExitCodeThread(worker, &code);
	CloseHandle(worker);
	worker = NULL;
	SecureZeroMemory(run_cfg.device_key, sizeof(run_cfg.device_key));

	if (wanted) {
		slog("tunnel ended (%lu), trying again in %d s", code, RETRY_MSEC / 1000);
		retry_at = GetTickCount64() + RETRY_MSEC;
		/* tunnel_run 은 끝나면서 STOPPED 를 올린다. 하지만 사용자가 보기에는 끊긴 것이
		 * 아니라 다시 붙는 중이다. 그렇게 보여야 [연결 해제]로 그만두게 할 수 있다. */
		set_state(TUNNEL_STATE_RECONNECTING);
	}
	else {
		slog("tunnel ended (%lu)", code);
		set_state(TUNNEL_STATE_STOPPED);
	}
}

static void worker_stop_and_wait(void)
{
	if (!worker) {
		return;
	}

	SetEvent(tunnel_stop);
	if (WaitForSingleObject(worker, WORKER_STOP_MSEC) != WAIT_OBJECT_0) {
		/* 강제로 끝내지 않는다. 정리 구간이 돌지 못하면 어댑터와 터널 주소가 남는다. */
		slog("the tunnel did not stop in %d s", WORKER_STOP_MSEC / 1000);
		return;
	}
	CloseHandle(worker);
	worker = NULL;
}

/* ---- 파이프 ---------------------------------------------------------------- */
/* 누가 서비스에 말을 걸 수 있는가.
 *
 *   SYSTEM, 관리자          전부
 *   이 PC 에 앉아 로그온한 사람  읽고 쓰기 (연결 / 해제 / 등록)
 *   그 밖 (네트워크 너머, 서비스 계정, 익명)  접근 없음
 *
 * 이름 있는 파이프는 기본으로 다른 PC 에서도 열 수 있다. PIPE_REJECT_REMOTE_CLIENTS 로
 * 그 길을 닫고, 접근 목록에서도 대화형 로그온(IU)만 들인다. */
static HANDLE pipe_create(void)
{
	SECURITY_ATTRIBUTES sa;
	HANDLE h;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
				L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1,
				&sa.lpSecurityDescriptor, NULL)) {
		return INVALID_HANDLE_VALUE;
	}

	/* FILE_FLAG_FIRST_PIPE_INSTANCE: 같은 이름의 파이프가 이미 있으면 만들지 않는다.
	 * 다른 프로그램이 먼저 그 이름으로 파이프를 열어 두고 서비스인 척하는 것을, 적어도
	 * 서비스가 모른 채 그 옆에 끼어드는 일은 없게 한다. */
	h = CreateNamedPipeW(IPC_PIPE_NAME,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			1, IPC_MAX_MSG * 8, IPC_MAX_MSG, 0, &sa);

	LocalFree(sa.lpSecurityDescriptor);

	return h;
}

static void login_set(const char *token, uint32_t len);

static void client_drop(void)
{
	int had_login;

	if (client_on) {
		slog("the control program disconnected");
	}

	/* 토큰은 그것을 준 GUI 가 붙어 있는 동안만 쓴다 (ipc.h). */
	EnterCriticalSection(&lock);
	had_login = login_info.state != IPC_LOGIN_NONE;
	LeaveCriticalSection(&lock);
	if (had_login) {
		login_set(NULL, 0);
		slog("user logged out with the control program");
	}

	CancelIo(pipe);
	DisconnectNamedPipe(pipe);
	client_on = 0;
	client_ready = 0;
	SecureZeroMemory(rbuf, sizeof(rbuf));
}

/* 접속을 기다리기 시작한다. */
static void client_listen(void)
{
	ResetEvent(pipe_ov.hEvent);

	if (ConnectNamedPipe(pipe, &pipe_ov)) {
		SetEvent(pipe_ov.hEvent);
		return;
	}

	switch (GetLastError()) {
	case ERROR_IO_PENDING:
		break;
	case ERROR_PIPE_CONNECTED:
		/* 기다리기 시작하기 전에 이미 붙었다. */
		SetEvent(pipe_ov.hEvent);
		break;
	default:
		slog("ConnectNamedPipe failed: %lu", GetLastError());
		break;
	}
}

/* 다음 명령을 읽기 시작한다. 실패하면 상대가 떠난 것이다. */
static int client_read(void)
{
	DWORD n;

	if (ReadFile(pipe, rbuf, sizeof(rbuf), &n, &pipe_ov) || GetLastError() == ERROR_IO_PENDING) {
		return 0;
	}

	return -1;
}

static int send_msg(uint32_t type, const void *body, uint32_t len)
{
	if (ipc_send(pipe, type, body, len, SEND_TIMEOUT_MSEC, stop_all) < 0) {
		return -1;
	}

	return 0;
}

static int send_state(void)
{
	ipc_state_t s;

	EnterCriticalSection(&lock);
	s.state = state;
	s.connected_ms = connected_at ? GetTickCount64() - connected_at : 0;
	state_dirty = 0;
	LeaveCriticalSection(&lock);
	s.wanted = (uint32_t)wanted;

	return send_msg(IPC_EVT_STATE, &s, sizeof(s));
}

static int send_device(void)
{
	ipc_device_t d;
	device_t dev;

	memset(&d, 0, sizeof(d));
	if (device_load(&dev) == DEVICE_OK) {
		d.enrolled = 1;
		memcpy(d.id, dev.id, sizeof(d.id));
	}
	SecureZeroMemory(&dev, sizeof(dev));

	return send_msg(IPC_EVT_DEVICE, &d, sizeof(d));
}

static int send_login(void)
{
	ipc_login_t l;

	EnterCriticalSection(&lock);
	l = login_info;
	login_dirty = 0;
	LeaveCriticalSection(&lock);

	return send_msg(IPC_EVT_LOGIN, &l, sizeof(l));
}

/* 토큰을 바꾸고 화면에 보일 상태를 처음으로 되돌린다. len 0 이면 로그아웃. */
static void login_set(const char *token, uint32_t len)
{
	tunnel_login_set(&login, token, len);

	EnterCriticalSection(&lock);
	memset(&login_info, 0, sizeof(login_info));
	login_info.state = len > 0 ? IPC_LOGIN_PENDING : IPC_LOGIN_NONE;
	login_dirty = 1;
	LeaveCriticalSection(&lock);
}

static int send_error(uint32_t code)
{
	ipc_error_t e;

	e.code = code;

	return send_msg(IPC_EVT_ERROR, &e, sizeof(e));
}

/* 쌓인 기록 중 이 GUI 가 아직 받지 않은 것을 보낸다. 0 이면 계속, -1 이면 상대가 떠났다. */
static int client_flush(void)
{
	static uint8_t msg[IPC_MAX_MSG];
	char line[IPC_LOG_LEN];
	ipc_packets_t head;
	uint64_t have;
	uint32_t n, i;
	int dirty;
	int batch;

	EnterCriticalSection(&lock);
	dirty = state_dirty;
	LeaveCriticalSection(&lock);
	if (dirty && send_state() < 0) {
		return -1;
	}

	EnterCriticalSection(&lock);
	dirty = login_dirty;
	LeaveCriticalSection(&lock);
	if (dirty && send_login() < 0) {
		return -1;
	}

	for (;;) {
		EnterCriticalSection(&lock);
		have = log_seq;
		if (c_log_seq + LOG_RING < have) {
			c_log_seq = have - LOG_RING;	/* 그 앞의 것은 이미 덮였다 */
		}
		if (c_log_seq < have) {
			memcpy(line, logs[c_log_seq % LOG_RING], sizeof(line));
		}
		LeaveCriticalSection(&lock);

		if (c_log_seq >= have) {
			break;
		}
		if (send_msg(IPC_EVT_LOG, line, (uint32_t)strlen(line)) < 0) {
			return -1;
		}
		c_log_seq++;
	}

	for (batch = 0; batch < FLUSH_BATCHES; batch++) {
		EnterCriticalSection(&lock);
		have = pkt_seq;
		if (c_pkt_seq + PACKET_RING < have) {
			/* GUI 가 따라오지 못해 덮인 만큼은 버려졌다. 세어서 알려 준다. */
			c_lost += have - PACKET_RING - c_pkt_seq;
			c_pkt_seq = have - PACKET_RING;
		}
		n = (uint32_t)(have - c_pkt_seq);
		if (n > IPC_PACKETS_PER_MSG) {
			n = (uint32_t)IPC_PACKETS_PER_MSG;
		}
		for (i = 0; i < n; i++) {
			memcpy(msg + sizeof(head) + i * sizeof(tunnel_packet_t),
					&packets[(c_pkt_seq + i) % PACKET_RING], sizeof(tunnel_packet_t));
		}
		LeaveCriticalSection(&lock);

		if (n == 0) {
			return 0;
		}

		head.lost = c_lost;
		head.count = n;
		head.reserved = 0;
		memcpy(msg, &head, sizeof(head));

		if (send_msg(IPC_EVT_PACKETS, msg, (uint32_t)(sizeof(head) + n * sizeof(tunnel_packet_t))) < 0) {
			return -1;
		}
		c_pkt_seq += n;
	}

	/* 아직 남았다. 명령을 한 번 보고 돌아온다. */
	SetEvent(notify);

	return 0;
}

/* ---- 명령 ------------------------------------------------------------------ */
static int cmd_hello(const uint8_t *body, uint32_t len)
{
	ipc_hello_t theirs, ours;

	ours.version = IPC_VERSION;
	ours.packet_size = (uint32_t)sizeof(tunnel_packet_t);

	if (len != sizeof(theirs)) {
		return -1;
	}
	memcpy(&theirs, body, sizeof(theirs));

	/* 우리 것을 먼저 알려 준다. 어긋났으면 상대가 "서비스와 버전이 다르다"고 말할 수 있다. */
	if (send_msg(IPC_EVT_HELLO, &ours, sizeof(ours)) < 0) {
		return -1;
	}
	if (theirs.version != ours.version || theirs.packet_size != ours.packet_size) {
		slog("the control program is a different build (version %u, packet %u bytes)",
				theirs.version, theirs.packet_size);
		return -1;
	}

	/* 남아 있는 기록의 맨 앞부터 보낸다. */
	EnterCriticalSection(&lock);
	c_log_seq = log_seq > LOG_RING ? log_seq - LOG_RING : 0;
	c_pkt_seq = pkt_seq > PACKET_RING ? pkt_seq - PACKET_RING : 0;
	LeaveCriticalSection(&lock);
	c_lost = 0;
	client_ready = 1;

	if (send_state() < 0 || send_device() < 0 || send_login() < 0) {
		return -1;
	}

	return client_flush();
}

static int cmd_connect(const uint8_t *body, uint32_t len)
{
	ipc_connect_t c;
	int err;

	if (len != sizeof(c)) {
		return send_error(IPC_ERR_BAD_REQUEST);
	}
	memcpy(&c, body, sizeof(c));
	c.adapter_name[TUNNEL_ADAPTER_NAME_LEN - 1] = L'\0';

	if (c.adapter_name[0] == L'\0' || c.server_ip == 0 || c.server_port == 0) {
		return send_error(IPC_ERR_BAD_REQUEST);
	}
	if (worker || wanted) {
		return send_error(IPC_ERR_BUSY);
	}

	memset(&run_cfg, 0, sizeof(run_cfg));
	wcscpy(run_cfg.adapter_name, c.adapter_name);
	run_cfg.server_ip.s_addr = c.server_ip;
	run_cfg.server_port = c.server_port;

	err = tunnel_start();
	if (err != 0) {
		return send_error((uint32_t)err);
	}

	wanted = 1;
	remember();
	slog("connect requested");

	return 0;
}

static int cmd_disconnect(void)
{
	wanted = 0;
	retry_at = 0;
	remember();
	slog("disconnect requested");

	if (worker) {
		SetEvent(tunnel_stop);	/* 끝나면 worker_exited 가 STOPPED 를 올린다 */
	}
	else {
		set_state(TUNNEL_STATE_STOPPED);
	}

	return 0;
}

static int send_enroll_result(int result, const device_t *dev, int with_key)
{
	ipc_enroll_result_t r;
	int ret;

	memset(&r, 0, sizeof(r));
	r.result = (uint32_t)result;
	if (result == TUNNEL_ENROLL_OK && dev != NULL) {
		memcpy(r.id, dev->id, sizeof(r.id));
		if (with_key) {
			r.has_key = 1;
			memcpy(r.key, dev->key, sizeof(r.key));
		}
	}

	ret = send_msg(IPC_EVT_ENROLL_RESULT, &r, sizeof(r));
	SecureZeroMemory(&r, sizeof(r));

	return ret;
}

/* 등록 코드로 서버에 이 PC 를 올린다. 신원은 서비스가 만들고 서비스만 읽을 수 있는 곳에
 * 둔다. GUI 로는 기기 ID 만 돌아간다. 답을 기다리는 동안(길어야 십여 초) 서비스 스레드가
 * 멈추지만, 터널이 열려 있을 때에는 받지 않으므로 그 사이에 놓치는 것이 없다. */
static int cmd_enroll(const uint8_t *body, uint32_t len)
{
	tunnel_config_t cfg;
	ipc_enroll_t e;
	device_t dev;
	int result;
	int ret;

	if (len != sizeof(e)) {
		return send_error(IPC_ERR_BAD_REQUEST);
	}
	memcpy(&e, body, sizeof(e));
	e.code[IPC_CODE_LEN - 1] = '\0';

	if (worker || wanted) {
		SecureZeroMemory(&e, sizeof(e));
		return send_error(IPC_ERR_BUSY);
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.server_ip.s_addr = e.server_ip;
	cfg.server_port = e.server_port;
	cfg.on_log = on_log;

	result = TUNNEL_ENROLL_ERROR;
	if (device_generate(&dev) == DEVICE_OK) {
		result = tunnel_enroll(&cfg, e.code, dev.id, dev.key, dev.server_pub, stop_all);
		dev.has_server_pub = result == TUNNEL_ENROLL_OK;

		/* 서버가 받아 준 뒤에 저장한다. 먼저 저장하면 서버에 닿지 못했을 때 예전 신원만 잃는다. */
		if (result == TUNNEL_ENROLL_OK && device_save(&dev) != DEVICE_OK) {
			slog("the server accepted the device but it could not be stored here");
			result = TUNNEL_ENROLL_ERROR;
		}
	}
	SecureZeroMemory(&e, sizeof(e));

	slog("enroll: result %d", result);
	ret = send_enroll_result(result, &dev, 0);
	SecureZeroMemory(&dev, sizeof(dev));

	return ret < 0 ? -1 : send_device();
}

/* 코드 없이: 신원을 만들어 저장하고 ID 와 키를 돌려준다. 관리자가 서버에 손으로 옮긴다.
 * 키가 서비스 밖으로 나가는 것은 이때 한 번뿐이다. */
static int cmd_enroll_manual(void)
{
	device_t dev;
	int ret;

	if (worker || wanted) {
		return send_error(IPC_ERR_BUSY);
	}

	if (device_enroll(&dev) != DEVICE_OK) {
		return send_enroll_result(TUNNEL_ENROLL_ERROR, NULL, 0);
	}

	slog("a new identity was created for manual registration");
	ret = send_enroll_result(TUNNEL_ENROLL_OK, &dev, 1);
	SecureZeroMemory(&dev, sizeof(dev));

	return ret < 0 ? -1 : send_device();
}

/* 토큰을 받았다. 서버가 서명을 보므로 여기서는 크기만 본다. */
static int cmd_login(const uint8_t *body, uint32_t len)
{
	if (len == 0 || len > LOGIN_TOKEN_MAX) {
		return send_error(IPC_ERR_BAD_REQUEST);
	}

	login_set((const char *)body, len);
	SecureZeroMemory((void *)body, len);
	slog("user token received (%u bytes)", len);

	return send_login();
}

static int cmd_logout(void)
{
	login_set(NULL, 0);
	slog("user logged out");

	return send_login();
}

/* 0 이면 계속, -1 이면 이 GUI 와는 끝이다. */
static int client_message(uint32_t n)
{
	ipc_header_t h;
	const uint8_t *body = rbuf + sizeof(h);

	if (n < sizeof(h)) {
		return -1;
	}
	memcpy(&h, rbuf, sizeof(h));
	if (h.len != n - sizeof(h)) {
		return -1;
	}

	if (!client_ready) {
		return h.type == IPC_CMD_HELLO ? cmd_hello(body, h.len) : -1;
	}

	switch (h.type) {
	case IPC_CMD_CONNECT:		return cmd_connect(body, h.len);
	case IPC_CMD_DISCONNECT:	return cmd_disconnect();
	case IPC_CMD_ENROLL:		return cmd_enroll(body, h.len);
	case IPC_CMD_ENROLL_MANUAL:	return cmd_enroll_manual();
	case IPC_CMD_LOGIN:		return cmd_login(body, h.len);
	case IPC_CMD_LOGOUT:		return cmd_logout();
	default:			return send_error(IPC_ERR_BAD_REQUEST);
	}
}

/* ---- 서비스 스레드 ---------------------------------------------------------- */
static int service_init(void)
{
	WSADATA wsa;

	InitializeCriticalSection(&lock);
	tunnel_login_init(&login);
	stop_all = CreateEventW(NULL, TRUE, FALSE, NULL);
	tunnel_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	notify = CreateEventW(NULL, FALSE, FALSE, NULL);
	pipe_ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

	if (!stop_all || !tunnel_stop || !notify || !pipe_ov.hEvent) {
		return -1;
	}
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return -1;
	}

	/* 신원은 사용자 계정이 아니라 PC 에 둔다. 로그온한 사람이 없어도 읽을 수 있어야 한다. */
	device_use_machine_store();

	return 0;
}

static void service_run(void)
{
	HANDLE waits[4];
	ULONGLONG now;
	DWORD nwaits, timeout, w, n;
	int err;

	slog("started");

	pipe = pipe_create();
	if (pipe == INVALID_HANDLE_VALUE) {
		slog("cannot create the control pipe: %lu", GetLastError());
		return;
	}
	client_listen();

	/* 지난번에 연결해 둔 채였으면 이어서 연결한다. */
	if (recall()) {
		wanted = 1;
		err = tunnel_start();
		if (err != 0) {
			slog("cannot resume the tunnel (%d)", err);
			retry_at = GetTickCount64() + RETRY_MSEC;
			set_state(TUNNEL_STATE_RECONNECTING);
		}
	}

	for (;;) {
		nwaits = 0;
		waits[nwaits++] = stop_all;
		waits[nwaits++] = pipe_ov.hEvent;
		if (client_ready) {
			waits[nwaits++] = notify;
		}
		if (worker) {
			waits[nwaits++] = worker;
		}

		timeout = INFINITE;
		if (retry_at != 0) {
			now = GetTickCount64();
			timeout = retry_at > now ? (DWORD)(retry_at - now) : 0;
		}

		w = WaitForMultipleObjects(nwaits, waits, FALSE, timeout);
		if (w == WAIT_FAILED) {
			slog("WaitForMultipleObjects failed: %lu", GetLastError());
			break;
		}

		if (w == WAIT_TIMEOUT) {
			retry_at = 0;
			err = tunnel_start();
			if (err != 0) {
				slog("cannot start the tunnel (%d)", err);
				retry_at = GetTickCount64() + RETRY_MSEC;
			}
			continue;
		}

		if (waits[w - WAIT_OBJECT_0] == stop_all) {
			break;
		}

		if (worker && waits[w - WAIT_OBJECT_0] == worker) {
			worker_exited();
		}
		else if (waits[w - WAIT_OBJECT_0] == pipe_ov.hEvent) {
			if (!client_on) {
				/* 누가 붙었다. HELLO 를 기다린다. */
				client_on = 1;
				slog("a control program connected");
				if (client_read() < 0) {
					client_drop();
					client_listen();
				}
				continue;
			}

			if (!GetOverlappedResult(pipe, &pipe_ov, &n, FALSE) ||
					client_message(n) < 0 || client_read() < 0) {
				client_drop();
				client_listen();
				continue;
			}
		}

		/* 무엇 때문에 깨어났든, 붙어 있는 GUI 에게 밀린 것을 보낸다. */
		if (client_ready && client_flush() < 0) {
			client_drop();
			client_listen();
		}
	}

	slog("stopping");
	worker_stop_and_wait();

	if (client_on) {
		client_drop();
	}
	CloseHandle(pipe);
	pipe = INVALID_HANDLE_VALUE;
}

/* ---- 서비스 관리자와의 약속 -------------------------------------------------- */
static SERVICE_STATUS_HANDLE scm;

static void scm_report(DWORD current)
{
	SERVICE_STATUS st;

	memset(&st, 0, sizeof(st));
	st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	st.dwCurrentState = current;
	st.dwControlsAccepted = current == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
	/* 내려갈 때 어댑터와 터널 주소를 정리한다. 그 시간을 달라고 한다. */
	st.dwWaitHint = current == SERVICE_STOP_PENDING ? WORKER_STOP_MSEC + 2000 : 3000;

	SetServiceStatus(scm, &st);
}

static DWORD WINAPI scm_control(DWORD control, DWORD type, LPVOID data, LPVOID ctx)
{
	(void)type;
	(void)data;
	(void)ctx;

	switch (control) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		scm_report(SERVICE_STOP_PENDING);
		SetEvent(stop_all);
		return NO_ERROR;
	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
	(void)argc;
	(void)argv;

	scm = RegisterServiceCtrlHandlerExW(SERVICE_NAME, scm_control, NULL);
	if (!scm) {
		return;
	}
	filelog_open();
	filelog_install_crash_handler();

	scm_report(SERVICE_START_PENDING);
	if (service_init() < 0) {
		scm_report(SERVICE_STOPPED);
		return;
	}

	scm_report(SERVICE_RUNNING);
	service_run();
	filelog_close();
	scm_report(SERVICE_STOPPED);
}

/* ---- 설치 / 제거 ------------------------------------------------------------ */
static int service_wait(SC_HANDLE svc, DWORD want, DWORD timeout_ms)
{
	ULONGLONG deadline = GetTickCount64() + timeout_ms;
	SERVICE_STATUS st;

	for (;;) {
		if (!QueryServiceStatus(svc, &st)) {
			return -1;
		}
		if (st.dwCurrentState == want) {
			return 0;
		}
		if (GetTickCount64() >= deadline) {
			return -1;
		}
		Sleep(200);
	}
}

static void service_stop(SC_HANDLE svc)
{
	SERVICE_STATUS st;

	if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
		service_wait(svc, SERVICE_STOPPED, WORKER_STOP_MSEC + 5000);
	}
}

/* 서비스는 시스템 권한으로 돈다. 일반 사용자가 고칠 수 있는 곳의 실행 파일을 서비스로
 * 등록하면 그 파일을 바꿔치기한 사람이 곧 시스템 권한을 얻는다. 그래서 빌드한 자리의
 * 파일을 그대로 가리키지 않고, 관리자만 쓸 수 있는 Program Files 로 복사해 그것을
 * 등록한다. */
static int install(void)
{
	wchar_t self[MAX_PATH], dir[MAX_PATH], src[MAX_PATH], dst[MAX_PATH], cmd[MAX_PATH + 4];
	SERVICE_DESCRIPTIONW desc;
	SC_HANDLE mgr, svc;
	wchar_t *slash;
	int ret = 1;

	if (!GetModuleFileNameW(NULL, self, MAX_PATH) ||
			!ExpandEnvironmentStringsW(INSTALL_DIR, dir, MAX_PATH)) {
		return 1;
	}

	mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!mgr) {
		fprintf(stderr, "cannot open the service manager (%lu). run as Administrator.\n", GetLastError());
		return 1;
	}

	/* 이미 설치돼 있으면 멈춘 뒤에 덮어쓴다. 돌고 있는 실행 파일은 바꿀 수 없다. */
	svc = OpenServiceW(mgr, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (svc) {
		service_stop(svc);
	}

	CreateDirectoryW(dir, NULL);

	swprintf(dst, MAX_PATH, L"%ls\\vpn_service.exe", dir);
	if (_wcsicmp(self, dst) != 0 && !CopyFileW(self, dst, FALSE)) {
		fprintf(stderr, "cannot copy the service to %ls (%lu)\n", dst, GetLastError());
		goto out;
	}

	/* wintun.dll 은 이 실행 파일 옆에 있다 (빌드가 복사해 둔다). */
	wcscpy(src, self);
	slash = wcsrchr(src, L'\\');
	if (slash) {
		wcscpy(slash + 1, L"wintun.dll");
		swprintf(dst, MAX_PATH, L"%ls\\wintun.dll", dir);
		if (_wcsicmp(src, dst) != 0 && !CopyFileW(src, dst, FALSE)) {
			fprintf(stderr, "cannot copy wintun.dll to %ls (%lu)\n", dst, GetLastError());
			goto out;
		}
	}

	/* 경로에 공백이 있다 (Program Files). 따옴표로 싸지 않으면 Windows 가 앞에서부터
	 * 끊어 가며 실행 파일을 찾는다 — C:\Program.exe 가 있으면 그것이 뜬다. */
	swprintf(cmd, MAX_PATH + 4, L"\"%ls\\vpn_service.exe\"", dir);

	if (svc) {
		if (!ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
					SERVICE_ERROR_NORMAL, cmd, NULL, NULL, NULL, NULL, NULL, SERVICE_DISPLAY)) {
			fprintf(stderr, "cannot update the service (%lu)\n", GetLastError());
			goto out;
		}
	}
	else {
		svc = CreateServiceW(mgr, SERVICE_NAME, SERVICE_DISPLAY, SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
				cmd, NULL, NULL, NULL, NULL, NULL);
		if (!svc) {
			fprintf(stderr, "cannot create the service (%lu)\n", GetLastError());
			goto out;
		}
	}

	desc.lpDescription = L"Keeps the ztgate tunnel up. The GUI talks to this service; it does not hold the tunnel itself.";
	ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

	if (!StartServiceW(svc, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
		fprintf(stderr, "installed, but the service did not start (%lu)\n", GetLastError());
		goto out;
	}
	if (service_wait(svc, SERVICE_RUNNING, 10000) < 0) {
		fprintf(stderr, "installed, but the service is not running\n");
		goto out;
	}

	printf("installed and running: %ls\n", cmd);
	ret = 0;

out:
	if (svc) {
		CloseServiceHandle(svc);
	}
	CloseServiceHandle(mgr);

	return ret;
}

static int uninstall(void)
{
	wchar_t dir[MAX_PATH], path[MAX_PATH];
	SC_HANDLE mgr, svc;

	mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!mgr) {
		fprintf(stderr, "cannot open the service manager (%lu). run as Administrator.\n", GetLastError());
		return 1;
	}

	svc = OpenServiceW(mgr, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (!svc) {
		fprintf(stderr, "the service is not installed, or this is not an Administrator (%lu)\n", GetLastError());
		CloseServiceHandle(mgr);
		return 1;
	}

	service_stop(svc);
	if (!DeleteService(svc)) {
		fprintf(stderr, "cannot delete the service (%lu)\n", GetLastError());
	}
	CloseServiceHandle(svc);
	CloseServiceHandle(mgr);

	/* 기기 신원(레지스트리)은 남긴다. 다시 설치하면 같은 기기다. */
	if (ExpandEnvironmentStringsW(INSTALL_DIR, dir, MAX_PATH)) {
		swprintf(path, MAX_PATH, L"%ls\\vpn_service.exe", dir);
		DeleteFileW(path);
		swprintf(path, MAX_PATH, L"%ls\\wintun.dll", dir);
		DeleteFileW(path);
		RemoveDirectoryW(dir);
	}

	printf("removed. the device identity is kept.\n");

	return 0;
}

/* ---- run: 콘솔에서 ---------------------------------------------------------- */
static BOOL WINAPI on_console_ctrl(DWORD type)
{
	(void)type;
	SetEvent(stop_all);

	return TRUE;
}

static int run_in_console(void)
{
	interactive = 1;

	if (service_init() < 0) {
		fprintf(stderr, "initialization failed\n");
		return 1;
	}
	SetConsoleCtrlHandler(on_console_ctrl, TRUE);
	service_run();

	return 0;
}

/* ---- ctl: 돌고 있는 서비스에 말을 건다 ----------------------------------------
 * GUI 없이 서비스를 확인하는 데 쓴다. 명령 하나를 보내고 몇 초 동안 온 사건을 찍는다. */
static const char *state_name(uint32_t s)
{
	switch (s) {
	case TUNNEL_STATE_STOPPED:	return "stopped";
	case TUNNEL_STATE_CONNECTING:	return "connecting";
	case TUNNEL_STATE_CONNECTED:	return "connected";
	case TUNNEL_STATE_RECONNECTING:	return "reconnecting";
	case TUNNEL_STATE_DENIED:	return "denied";
	default:			return "?";
	}
}

static void ctl_print(const uint8_t *msg, DWORD n, int verbose)
{
	ipc_header_t h;
	const uint8_t *body = msg + sizeof(h);
	uint32_t i;

	if (n < sizeof(h)) {
		return;
	}
	memcpy(&h, msg, sizeof(h));

	switch (h.type) {
	case IPC_EVT_HELLO: {
		ipc_hello_t v;

		memcpy(&v, body, sizeof(v));
		printf("service: ipc version %u, packet %u bytes%s\n", v.version, v.packet_size,
				v.version == IPC_VERSION && v.packet_size == sizeof(tunnel_packet_t) ?
				"" : "   (this program is a different build)");
		break;
	}
	case IPC_EVT_STATE: {
		ipc_state_t s;

		memcpy(&s, body, sizeof(s));
		printf("state: %s%s", state_name(s.state), s.wanted ? " (wanted)" : "");
		if (s.connected_ms) {
			ULONGLONG sec = s.connected_ms / 1000;

			printf(", connected for %llu:%02llu:%02llu", sec / 3600, (sec / 60) % 60, sec % 60);
		}
		printf("\n");
		break;
	}
	case IPC_EVT_DEVICE: {
		ipc_device_t d;

		memcpy(&d, body, sizeof(d));
		if (!d.enrolled) {
			printf("device: not enrolled\n");
			break;
		}
		printf("device: ");
		for (i = 0; i < DEVICE_ID_LEN; i++) {
			printf("%02x", d.id[i]);
		}
		printf("\n");
		break;
	}
	case IPC_EVT_LOG:
		if (verbose) {
			printf("log: %.*s\n", (int)h.len, (const char *)body);
		}
		break;
	case IPC_EVT_PACKETS: {
		ipc_packets_t p;

		memcpy(&p, body, sizeof(p));
		printf("packets: %u (lost %llu)\n", p.count, (unsigned long long)p.lost);
		break;
	}
	case IPC_EVT_ENROLL_RESULT: {
		ipc_enroll_result_t r;

		memcpy(&r, body, sizeof(r));
		printf("enroll: result %u%s\n", r.result, r.result == TUNNEL_ENROLL_OK ? " (ok)" : "");
		SecureZeroMemory(&r, sizeof(r));
		break;
	}
	case IPC_EVT_LOGIN: {
		ipc_login_t l;

		memcpy(&l, body, sizeof(l));
		l.user[sizeof(l.user) - 1] = '\0';
		if (l.state == IPC_LOGIN_NONE) {
			printf("login: none\n");
		}
		else if (l.state == IPC_LOGIN_PENDING) {
			printf("login: waiting for the server\n");
		}
		else if (l.status == LOGIN_OK) {
			printf("login: %s (expires in %llds)\n", l.user, (long long)(l.expires - (int64_t)time(NULL)));
		}
		else {
			printf("login: rejected (status %u)\n", l.status);
		}
		break;
	}
	case IPC_EVT_ERROR: {
		ipc_error_t e;

		memcpy(&e, body, sizeof(e));
		printf("error: %u (%s)\n", e.code,
				e.code == IPC_ERR_BUSY ? "the tunnel is up, disconnect first" :
				e.code == IPC_ERR_NOT_ENROLLED ? "this device is not enrolled" :
				e.code == IPC_ERR_BAD_REQUEST ? "bad request" : "internal");
		break;
	}
	default:
		printf("message type %u\n", h.type);
		break;
	}
}

static int ctl(int argc, wchar_t **argv)
{
	static uint8_t msg[IPC_MAX_MSG];
	ipc_hello_t hello;
	ipc_connect_t c;
	ipc_enroll_t e;
	OVERLAPPED ov;
	HANDLE h;
	ULONGLONG deadline;
	DWORD mode = PIPE_READMODE_MESSAGE;
	DWORD n;
	DWORD seconds = 3;
	int verbose = 0;
	int sent = -1;

	if (argc < 1) {
		goto usage;
	}

	h = CreateFileW(IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "cannot reach the service (%lu)%s\n", GetLastError(),
				GetLastError() == ERROR_FILE_NOT_FOUND ? ": it is not running" :
				GetLastError() == ERROR_PIPE_BUSY ? ": another control program (the GUI?) is connected" : "");
		return 1;
	}
	SetNamedPipeHandleState(h, &mode, NULL, NULL);

	hello.version = IPC_VERSION;
	hello.packet_size = (uint32_t)sizeof(tunnel_packet_t);
	if (ipc_send(h, IPC_CMD_HELLO, &hello, sizeof(hello), 3000, NULL) < 0) {
		fprintf(stderr, "the service does not answer\n");
		CloseHandle(h);
		return 1;
	}

	if (wcscmp(argv[0], L"status") == 0 || wcscmp(argv[0], L"watch") == 0) {
		verbose = wcscmp(argv[0], L"watch") == 0;
		if (argc >= 2) {
			seconds = (DWORD)wcstoul(argv[1], NULL, 10);
		}
		sent = 0;
	}
	else if (wcscmp(argv[0], L"connect") == 0 && argc >= 4) {
		memset(&c, 0, sizeof(c));
		wcsncpy(c.adapter_name, argv[1], TUNNEL_ADAPTER_NAME_LEN - 1);
		if (InetPtonW(AF_INET, argv[2], &c.server_ip) != 1) {
			goto usage;
		}
		c.server_port = (uint16_t)wcstoul(argv[3], NULL, 10);
		verbose = 1;
		seconds = 6;
		sent = ipc_send(h, IPC_CMD_CONNECT, &c, sizeof(c), 3000, NULL);
	}
	else if (wcscmp(argv[0], L"login") == 0 && argc >= 2) {
		/* 토큰은 GUI 가 붙어 있는 동안만 쓰이므로, 이 명령이 떠 있는 동안만 로그인해 있다. */
		static char token[LOGIN_TOKEN_MAX + 2];
		FILE *f = _wfopen(argv[1], L"rb");
		size_t len;

		if (!f) {
			fprintf(stderr, "cannot read %ls\n", argv[1]);
			CloseHandle(h);
			return 1;
		}
		len = fread(token, 1, sizeof(token), f);
		fclose(f);
		while (len > 0 && (token[len - 1] == '\n' || token[len - 1] == '\r' || token[len - 1] == ' ')) {
			len--;
		}
		verbose = 1;
		seconds = argc >= 3 ? (DWORD)wcstoul(argv[2], NULL, 10) : 20;
		sent = ipc_send(h, IPC_CMD_LOGIN, token, (uint32_t)len, 3000, NULL);
		SecureZeroMemory(token, sizeof(token));
	}
	else if (wcscmp(argv[0], L"disconnect") == 0) {
		verbose = 1;
		sent = ipc_send(h, IPC_CMD_DISCONNECT, NULL, 0, 3000, NULL);
	}
	else if (wcscmp(argv[0], L"enroll") == 0 && argc >= 4) {
		memset(&e, 0, sizeof(e));
		if (InetPtonW(AF_INET, argv[1], &e.server_ip) != 1) {
			goto usage;
		}
		e.server_port = (uint16_t)wcstoul(argv[2], NULL, 10);
		WideCharToMultiByte(CP_ACP, 0, argv[3], -1, e.code, IPC_CODE_LEN - 1, NULL, NULL);
		verbose = 1;
		seconds = 20;
		sent = ipc_send(h, IPC_CMD_ENROLL, &e, sizeof(e), 3000, NULL);
		SecureZeroMemory(&e, sizeof(e));
	}
	else {
		CloseHandle(h);
		goto usage;
	}

	if (sent < 0) {
		fprintf(stderr, "could not send the command\n");
		CloseHandle(h);
		return 1;
	}

	memset(&ov, 0, sizeof(ov));
	ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	deadline = GetTickCount64() + seconds * 1000ULL;

	for (;;) {
		ULONGLONG now = GetTickCount64();

		if (now >= deadline) {
			break;
		}
		if (!ReadFile(h, msg, sizeof(msg), &n, &ov)) {
			if (GetLastError() != ERROR_IO_PENDING) {
				printf("the service closed the connection (%lu)\n", GetLastError());
				break;
			}
			if (WaitForSingleObject(ov.hEvent, (DWORD)(deadline - now)) != WAIT_OBJECT_0) {
				CancelIoEx(h, &ov);
				GetOverlappedResult(h, &ov, &n, TRUE);
				break;
			}
			if (!GetOverlappedResult(h, &ov, &n, FALSE)) {
				printf("the service closed the connection (%lu)\n", GetLastError());
				break;
			}
		}
		ctl_print(msg, n, verbose);
	}

	CloseHandle(ov.hEvent);
	CloseHandle(h);

	return 0;

usage:
	fprintf(stderr, "usage: vpn_service ctl status [seconds]\n");
	fprintf(stderr, "       vpn_service ctl watch [seconds]                       status and the log\n");
	fprintf(stderr, "       vpn_service ctl connect <adapter-name> <server-ip> <port>\n");
	fprintf(stderr, "       vpn_service ctl disconnect\n");
	fprintf(stderr, "       vpn_service ctl enroll <server-ip> <port> <code>\n");
	fprintf(stderr, "       vpn_service ctl login <token-file> [seconds]          logged in while this runs\n");

	return 1;
}

int wmain(int argc, wchar_t **argv)
{
	static const SERVICE_TABLE_ENTRYW table[] = {
		{ (LPWSTR)SERVICE_NAME, service_main },
		{ NULL, NULL },
	};

	if (argc >= 2 && wcscmp(argv[1], L"install") == 0) {
		return install();
	}
	if (argc >= 2 && wcscmp(argv[1], L"uninstall") == 0) {
		return uninstall();
	}
	if (argc >= 2 && wcscmp(argv[1], L"run") == 0) {
		return run_in_console();
	}
	if (argc >= 2 && wcscmp(argv[1], L"ctl") == 0) {
		return ctl(argc - 2, argv + 2);
	}

	/* 인자가 없다. 서비스 관리자가 띄운 것이면 여기서 서비스 스레드가 끝날 때까지 머문다.
	 * 사람이 콘솔에서 그냥 실행했으면 관리자에 붙지 못하고 곧바로 돌아온다. */
	if (!StartServiceCtrlDispatcherW(table)) {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			fprintf(stderr, "usage: vpn_service install | uninstall | run | ctl ...\n");
		}
		return 1;
	}

	return 0;
}
