#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "vpn_remote.h"
#include "ipc.h"

#define RETRY_MSEC		1000
#define SEND_TIMEOUT_MSEC	3000

/* 등록의 답을 기다리는 한도. 서비스 쪽의 핸드셰이크와 재시도를 다 합쳐도 이보다 짧다. */
#define ENROLL_WAIT_MSEC	30000

struct vpn_session {
	HWND notify;
	HANDLE thread;		/* 서비스에 붙어 사건을 읽는 스레드 */
	HANDLE quit;		/* manual-reset. 그 스레드를 끝낸다 */

	/* 아래는 읽는 스레드와 UI 스레드가 함께 본다. */
	CRITICAL_SECTION lock;
	HANDLE pipe;		/* 붙어 있지 않으면 INVALID_HANDLE_VALUE */
	int link;		/* vpn_remote_link_t */
	int active;		/* 터널이 열려 있거나 서비스가 열려고 하는 중이다 */
	ULONGLONG connected_since;	/* 터널이 연결된 때 (이 PC 의 GetTickCount64). 0 이면 연결되지 않았다 */
	int enrolled;
	uint8_t device_id[DEVICE_ID_LEN];

	/* 패킷 링버퍼. vpn_session.c 와 같은 방식이다. */
	tunnel_packet_t *ring;
	int ring_head;
	int ring_count;
	uint64_t ring_lost;	/* 화면이 따라오지 못해 여기서 버린 것 */
	uint64_t svc_lost;	/* 서비스가 우리에게 보내기 전에 버린 것 */
	volatile LONG notify_pending;

	/* 등록의 답을 기다리는 자리. */
	HANDLE enroll_done;	/* manual-reset */
	ipc_enroll_result_t enroll_result;
	HANDLE dpop_done;	/* manual-reset */
	ipc_dpop_t dpop;
	CRITICAL_SECTION dpop_lock;	/* 증명 요청은 한 번에 하나 */

	ipc_login_t login;	/* 서비스가 마지막으로 알려 준 로그인 상태 */
};

static void post(vpn_session_t *s, UINT msg, WPARAM w)
{
	PostMessageW(s->notify, msg, w, 0);
}

static void set_link(vpn_session_t *s, int link)
{
	int changed;

	EnterCriticalSection(&s->lock);
	changed = s->link != link;
	s->link = link;
	LeaveCriticalSection(&s->lock);

	if (changed) {
		post(s, WM_VPN_SERVICE, (WPARAM)link);
	}
}

/* 명령 하나를 보낸다. 붙어 있지 않으면 -1. */
static int command(vpn_session_t *s, uint32_t type, const void *body, uint32_t len)
{
	int ret = -1;

	EnterCriticalSection(&s->lock);
	if (s->pipe != INVALID_HANDLE_VALUE && s->link == VPN_REMOTE_UP) {
		ret = ipc_send(s->pipe, type, body, len, SEND_TIMEOUT_MSEC, s->quit);
	}
	LeaveCriticalSection(&s->lock);

	return ret;
}

/* ---- 사건 ------------------------------------------------------------------ */
static void on_log(vpn_session_t *s, const uint8_t *body, uint32_t len)
{
	char *copy;

	/* 받는 쪽(UI 스레드)이 vpn_session_free_log 로 해제한다. */
	copy = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)len + 1);
	if (!copy) {
		return;
	}
	memcpy(copy, body, len);
	copy[len] = '\0';

	if (!PostMessageW(s->notify, WM_VPN_LOG, 0, (LPARAM)copy)) {
		HeapFree(GetProcessHeap(), 0, copy);
	}
}

static void on_packets(vpn_session_t *s, const uint8_t *body, uint32_t len)
{
	ipc_packets_t head;
	uint32_t i;

	if (len < sizeof(head)) {
		return;
	}
	memcpy(&head, body, sizeof(head));
	if (head.count > IPC_PACKETS_PER_MSG ||
			len != sizeof(head) + (size_t)head.count * sizeof(tunnel_packet_t)) {
		return;
	}
	body += sizeof(head);

	EnterCriticalSection(&s->lock);
	s->svc_lost = head.lost;
	for (i = 0; i < head.count; i++) {
		if (s->ring_count == VPN_PACKET_RING) {
			/* 꽉 찼으면 가장 오래된 것을 버린다. 최신 패킷을 살리는 쪽이 분석에 쓸모 있다. */
			s->ring_head = (s->ring_head + 1) % VPN_PACKET_RING;
			s->ring_count--;
			s->ring_lost++;
		}
		memcpy(&s->ring[(s->ring_head + s->ring_count) % VPN_PACKET_RING],
				body + (size_t)i * sizeof(tunnel_packet_t), sizeof(tunnel_packet_t));
		s->ring_count++;
	}
	LeaveCriticalSection(&s->lock);

	/* 처리되지 않은 알림이 없을 때만 깨운다. 패킷 수와 무관하게 큐에 떠 있는 알림은
	 * 최대 하나다. */
	if (InterlockedExchange(&s->notify_pending, 1) == 0) {
		if (!PostMessageW(s->notify, WM_VPN_PACKETS, 0, 0)) {
			InterlockedExchange(&s->notify_pending, 0);
		}
	}
}

static void on_state(vpn_session_t *s, const uint8_t *body, uint32_t len)
{
	ipc_state_t st;
	int was_active;
	int active;

	if (len != sizeof(st)) {
		return;
	}
	memcpy(&st, body, sizeof(st));

	active = st.state != TUNNEL_STATE_STOPPED || st.wanted;

	EnterCriticalSection(&s->lock);
	was_active = s->active;
	s->active = active;
	/* 받은 지금에서 지난 양을 빼 연결된 때로 바꿔 둔다. 화면이 이것을 읽는 것은 아래의
	 * WM_VPN_STATE 를 받은 뒤다. */
	s->connected_since = st.connected_ms ? GetTickCount64() - st.connected_ms : 0;
	LeaveCriticalSection(&s->lock);

	post(s, WM_VPN_STATE, (WPARAM)st.state);

	/* 화면은 터널이 닫히면 WM_VPN_DONE 을 기다린다 (버튼을 풀고 "연결"로 되돌린다).
	 * 전에는 워커 스레드가 끝나며 보내던 것이다. */
	if (was_active && !active) {
		post(s, WM_VPN_DONE, 0);
	}
}

static void on_error(vpn_session_t *s, const uint8_t *body, uint32_t len)
{
	ipc_error_t e;

	if (len != sizeof(e)) {
		return;
	}
	memcpy(&e, body, sizeof(e));

	/* 등록을 기다리는 중이었으면 그 기다림도 끝낸다. 답이 따로 오지 않는다. */
	EnterCriticalSection(&s->lock);
	memset(&s->enroll_result, 0, sizeof(s->enroll_result));
	s->enroll_result.result = TUNNEL_ENROLL_ERROR;
	LeaveCriticalSection(&s->lock);
	SetEvent(s->enroll_done);

	post(s, WM_VPN_ERROR, (WPARAM)e.code);
}

/* 0 이면 계속 읽고, -1 이면 이 연결을 끊는다. */
static int on_message(vpn_session_t *s, const uint8_t *msg, DWORD n)
{
	ipc_header_t h;
	const uint8_t *body = msg + sizeof(h);

	if (n < sizeof(h)) {
		return -1;
	}
	memcpy(&h, msg, sizeof(h));
	if (h.len != n - sizeof(h)) {
		return -1;
	}

	switch (h.type) {
	case IPC_EVT_HELLO: {
		ipc_hello_t v;

		if (h.len != sizeof(v)) {
			return -1;
		}
		memcpy(&v, body, sizeof(v));

		/* 서비스만 새로 설치하고 이 프로그램은 예전 것인 경우(또는 그 반대). 구조체가
		 * 어긋나 있을 수 있으므로 더 읽지 않는다. */
		if (v.version != IPC_VERSION || v.packet_size != sizeof(tunnel_packet_t)) {
			set_link(s, VPN_REMOTE_MISMATCH);
			return -1;
		}
		set_link(s, VPN_REMOTE_UP);
		break;
	}
	case IPC_EVT_STATE:
		on_state(s, body, h.len);
		break;
	case IPC_EVT_DEVICE: {
		ipc_device_t d;

		if (h.len != sizeof(d)) {
			return -1;
		}
		memcpy(&d, body, sizeof(d));

		EnterCriticalSection(&s->lock);
		s->enrolled = d.enrolled != 0;
		memcpy(s->device_id, d.id, sizeof(s->device_id));
		LeaveCriticalSection(&s->lock);

		post(s, WM_VPN_DEVICE, 0);
		break;
	}
	case IPC_EVT_LOG:
		on_log(s, body, h.len);
		break;
	case IPC_EVT_PACKETS:
		on_packets(s, body, h.len);
		break;
	case IPC_EVT_ENROLL_RESULT:
		if (h.len != sizeof(s->enroll_result)) {
			return -1;
		}
		EnterCriticalSection(&s->lock);
		memcpy(&s->enroll_result, body, sizeof(s->enroll_result));
		LeaveCriticalSection(&s->lock);
		SetEvent(s->enroll_done);
		break;
	case IPC_EVT_DPOP:
		if (h.len != sizeof(s->dpop)) {
			return -1;
		}
		EnterCriticalSection(&s->lock);
		memcpy(&s->dpop, body, sizeof(s->dpop));
		s->dpop.proof[sizeof(s->dpop.proof) - 1] = '\0';
		LeaveCriticalSection(&s->lock);
		SetEvent(s->dpop_done);
		break;
	case IPC_EVT_ERROR:
		on_error(s, body, h.len);
		break;
	case IPC_EVT_LOGIN:
		if (h.len != sizeof(s->login)) {
			return -1;
		}
		EnterCriticalSection(&s->lock);
		memcpy(&s->login, body, sizeof(s->login));
		s->login.user[sizeof(s->login.user) - 1] = '\0';
		LeaveCriticalSection(&s->lock);
		post(s, WM_VPN_LOGIN, 0);
		break;
	default:
		break;	/* 모르는 사건은 넘긴다 */
	}

	return 0;
}

/* ---- 읽는 스레드 ------------------------------------------------------------ */
/* 서비스에 붙어 끊길 때까지 읽는다. 돌아오면 붙어 있지 않은 상태다. */
static void attach(vpn_session_t *s)
{
	static const DWORD message_mode = PIPE_READMODE_MESSAGE;
	uint8_t *msg;
	ipc_hello_t hello;
	OVERLAPPED ov;
	HANDLE waits[2];
	HANDLE h;
	DWORD mode = message_mode;
	DWORD n;
	DWORD err;

	h = CreateFileW(IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		/* 파이프가 없으면 서비스가 없는 것이고, 바쁘면 다른 프로그램이 붙어 있는 것이다. */
		set_link(s, GetLastError() == ERROR_PIPE_BUSY ? VPN_REMOTE_BUSY : VPN_REMOTE_DOWN);
		return;
	}
	SetNamedPipeHandleState(h, &mode, NULL, NULL);

	msg = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, IPC_MAX_MSG);
	memset(&ov, 0, sizeof(ov));
	ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!msg || !ov.hEvent) {
		goto out;
	}

	hello.version = IPC_VERSION;
	hello.packet_size = (uint32_t)sizeof(tunnel_packet_t);
	if (ipc_send(h, IPC_CMD_HELLO, &hello, sizeof(hello), SEND_TIMEOUT_MSEC, s->quit) < 0) {
		goto out;
	}

	EnterCriticalSection(&s->lock);
	s->pipe = h;
	LeaveCriticalSection(&s->lock);

	waits[0] = s->quit;
	waits[1] = ov.hEvent;

	for (;;) {
		if (!ReadFile(h, msg, IPC_MAX_MSG, &n, &ov)) {
			err = GetLastError();
			if (err != ERROR_IO_PENDING) {
				break;
			}
			if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
				/* 그만두라는 신호다. 걸어 둔 읽기를 거두고 나간다. */
				CancelIoEx(h, &ov);
				GetOverlappedResult(h, &ov, &n, TRUE);
				break;
			}
			if (!GetOverlappedResult(h, &ov, &n, FALSE)) {
				break;
			}
		}

		if (on_message(s, msg, n) < 0) {
			break;
		}
	}

out:
	/* UI 스레드가 이 핸들로 쓰는 중일 수 있다. 락을 잡고 치운 뒤에 닫는다. */
	EnterCriticalSection(&s->lock);
	s->pipe = INVALID_HANDLE_VALUE;
	LeaveCriticalSection(&s->lock);

	CloseHandle(h);
	if (ov.hEvent) {
		CloseHandle(ov.hEvent);
	}
	if (msg) {
		SecureZeroMemory(msg, IPC_MAX_MSG);
		HeapFree(GetProcessHeap(), 0, msg);
	}

	/* 등록의 답을 기다리던 쪽이 있으면 풀어 준다. */
	EnterCriticalSection(&s->lock);
	s->enroll_result.result = TUNNEL_ENROLL_ERROR;
	s->active = 0;
	memset(&s->login, 0, sizeof(s->login));	/* 서비스는 떨어진 GUI 의 토큰을 버린다 */
	LeaveCriticalSection(&s->lock);
	SetEvent(s->enroll_done);
	post(s, WM_VPN_LOGIN, 0);

	/* 버전이 달라 끊은 것이면 그 표시를 남긴다. 그 밖에는 서비스가 사라진 것이다. */
	if (vpn_remote_link(s) == VPN_REMOTE_UP) {
		set_link(s, VPN_REMOTE_DOWN);
	}
}

static DWORD WINAPI reader_main(LPVOID arg)
{
	vpn_session_t *s = (vpn_session_t *)arg;

	/* 서비스가 나중에 뜨거나 다시 떠도 붙는다. 이 프로그램을 다시 켤 필요가 없다. */
	for (;;) {
		attach(s);
		if (WaitForSingleObject(s->quit, RETRY_MSEC) != WAIT_TIMEOUT) {
			break;
		}
	}

	return 0;
}

/* ---- vpn_session.h ---------------------------------------------------------- */
vpn_session_t *vpn_session_create(HWND notify)
{
	vpn_session_t *s;

	s = (vpn_session_t *)calloc(1, sizeof(*s));
	if (!s) {
		return NULL;
	}

	s->notify = notify;
	s->pipe = INVALID_HANDLE_VALUE;
	s->link = VPN_REMOTE_DOWN;
	InitializeCriticalSection(&s->lock);

	s->ring = (tunnel_packet_t *)calloc(VPN_PACKET_RING, sizeof(*s->ring));
	s->quit = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->enroll_done = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->dpop_done = CreateEventW(NULL, TRUE, FALSE, NULL);
	InitializeCriticalSection(&s->dpop_lock);
	if (s->ring && s->quit && s->enroll_done && s->dpop_done) {
		s->thread = CreateThread(NULL, 0, reader_main, s, 0, NULL);
	}

	if (!s->thread) {
		if (s->quit) {
			CloseHandle(s->quit);
		}
		if (s->enroll_done) {
			CloseHandle(s->enroll_done);
		}
		if (s->dpop_done) {
			CloseHandle(s->dpop_done);
		}
		free(s->ring);
		DeleteCriticalSection(&s->dpop_lock);
		DeleteCriticalSection(&s->lock);
		free(s);
		return NULL;
	}

	return s;
}

/* 서비스에서 떨어진다. 터널은 건드리지 않는다 — 이 프로그램을 닫아도 연결은 그대로다. */
void vpn_session_destroy(vpn_session_t *s)
{
	if (!s) {
		return;
	}

	SetEvent(s->quit);
	WaitForSingleObject(s->thread, VPN_STOP_TIMEOUT_MS);
	CloseHandle(s->thread);
	CloseHandle(s->quit);
	CloseHandle(s->enroll_done);
	CloseHandle(s->dpop_done);
	DeleteCriticalSection(&s->dpop_lock);
	DeleteCriticalSection(&s->lock);
	SecureZeroMemory(&s->enroll_result, sizeof(s->enroll_result));
	free(s->ring);
	free(s);
}

int vpn_session_start(vpn_session_t *s, const tunnel_config_t *cfg)
{
	ipc_connect_t c;

	if (!s || !cfg) {
		return -1;
	}

	memset(&c, 0, sizeof(c));
	wcsncpy(c.adapter_name, cfg->adapter_name, TUNNEL_ADAPTER_NAME_LEN - 1);
	c.server_ip = cfg->server_ip.s_addr;
	c.server_port = cfg->server_port;
	c.n_alt = (uint16_t)cfg->n_alt;
	for (int i = 0; i < cfg->n_alt; i++) {
		c.alt_ips[i] = cfg->alt_ips[i].s_addr;
	}

	if (command(s, IPC_CMD_CONNECT, &c, sizeof(c)) < 0) {
		return -1;
	}

	/* 서비스의 STATE 가 곧 오지만, 버튼을 누른 직후부터 "열려는 중"으로 본다. 그 사이에
	 * 한 번 더 누르면 연결이 아니라 해제여야 한다. */
	EnterCriticalSection(&s->lock);
	s->active = 1;
	LeaveCriticalSection(&s->lock);

	return 0;
}

void vpn_session_stop(vpn_session_t *s)
{
	if (s) {
		command(s, IPC_CMD_DISCONNECT, NULL, 0);
	}
}

/* 기다릴 워커가 여기에는 없다. 터널을 정리하는 것은 서비스다. */
int vpn_session_join(vpn_session_t *s, DWORD timeout_ms)
{
	(void)s;
	(void)timeout_ms;

	return 0;
}

int vpn_session_active(const vpn_session_t *s)
{
	return s != NULL && s->active;
}

void vpn_session_drain(HWND notify)
{
	MSG msg;

	while (PeekMessageW(&msg, notify, WM_VPN_LOG, WM_VPN_LOG, PM_REMOVE)) {
		vpn_session_free_log((char *)msg.lParam);
	}
}

void vpn_session_free_log(char *line)
{
	if (line) {
		HeapFree(GetProcessHeap(), 0, line);
	}
}

int vpn_session_drain_packets(vpn_session_t *s, tunnel_packet_t *out, int max)
{
	int n = 0;

	if (!s || !out || max <= 0) {
		return 0;
	}

	/* 비우기 **전에** 플래그를 내린다. 꺼내는 중에 들어온 패킷이 새 알림을 보낼 수
	 * 있어야 한다. */
	InterlockedExchange(&s->notify_pending, 0);

	EnterCriticalSection(&s->lock);
	while (n < max && s->ring_count > 0) {
		out[n++] = s->ring[s->ring_head];
		s->ring_head = (s->ring_head + 1) % VPN_PACKET_RING;
		s->ring_count--;
	}
	LeaveCriticalSection(&s->lock);

	return n;
}

uint64_t vpn_session_lost_packets(vpn_session_t *s)
{
	uint64_t lost;

	if (!s) {
		return 0;
	}

	EnterCriticalSection(&s->lock);
	lost = s->ring_lost + s->svc_lost;
	LeaveCriticalSection(&s->lock);

	return lost;
}

/* ---- vpn_remote.h ----------------------------------------------------------- */
int vpn_remote_link(const vpn_session_t *s)
{
	return s ? s->link : VPN_REMOTE_DOWN;
}

ULONGLONG vpn_remote_connected_since(vpn_session_t *s)
{
	ULONGLONG since;

	if (!s) {
		return 0;
	}

	EnterCriticalSection(&s->lock);
	since = s->link == VPN_REMOTE_UP ? s->connected_since : 0;
	LeaveCriticalSection(&s->lock);

	return since;
}

int vpn_remote_device(vpn_session_t *s, uint8_t id[DEVICE_ID_LEN])
{
	int enrolled;

	if (!s) {
		return 0;
	}

	EnterCriticalSection(&s->lock);
	enrolled = s->enrolled && s->link == VPN_REMOTE_UP;
	memcpy(id, s->device_id, DEVICE_ID_LEN);
	LeaveCriticalSection(&s->lock);

	return enrolled;
}

/* 명령을 보내고 ENROLL_RESULT 가 올 때까지 기다린다. 읽는 스레드가 따로 있으므로 이
 * 스레드가 멈춰 있어도 답은 들어온다. */
static int enroll_wait(vpn_session_t *s, uint32_t type, const void *body, uint32_t len,
		ipc_enroll_result_t *out)
{
	ResetEvent(s->enroll_done);

	if (command(s, type, body, len) < 0) {
		return -1;
	}
	if (WaitForSingleObject(s->enroll_done, ENROLL_WAIT_MSEC) != WAIT_OBJECT_0) {
		return -1;
	}

	EnterCriticalSection(&s->lock);
	*out = s->enroll_result;
	SecureZeroMemory(&s->enroll_result, sizeof(s->enroll_result));
	LeaveCriticalSection(&s->lock);

	return 0;
}

int vpn_remote_enroll(vpn_session_t *s, uint32_t server_ip, uint16_t server_port, const char *code)
{
	ipc_enroll_result_t r;
	ipc_enroll_t e;
	int ret;

	if (!s || !code || strlen(code) >= IPC_CODE_LEN) {
		return s && code ? TUNNEL_ENROLL_BAD_CODE : TUNNEL_ENROLL_ERROR;
	}

	memset(&e, 0, sizeof(e));
	e.server_ip = server_ip;
	e.server_port = server_port;
	strcpy(e.code, code);

	ret = enroll_wait(s, IPC_CMD_ENROLL, &e, sizeof(e), &r);
	SecureZeroMemory(&e, sizeof(e));
	if (ret < 0) {
		return TUNNEL_ENROLL_ERROR;
	}

	ret = (int)r.result;
	SecureZeroMemory(&r, sizeof(r));

	return ret;
}

int vpn_remote_enroll_manual(vpn_session_t *s, device_t *out)
{
	ipc_enroll_result_t r;
	int ret = DEVICE_ERROR;

	if (!s || !out) {
		return DEVICE_ERROR;
	}

	if (enroll_wait(s, IPC_CMD_ENROLL_MANUAL, NULL, 0, &r) < 0) {
		return DEVICE_ERROR;
	}

	if (r.result == TUNNEL_ENROLL_OK && r.has_key) {
		memcpy(out->id, r.id, sizeof(out->id));
		memcpy(out->key, r.key, sizeof(out->key));
		ret = DEVICE_OK;
	}
	SecureZeroMemory(&r, sizeof(r));

	return ret;
}

int vpn_remote_dpop(vpn_session_t *s, const char *htu, char *out, size_t cap)
{
	ipc_dpop_req_t q;
	int ret = -1;

	if (!s || !htu || strlen(htu) >= sizeof(q.htu) || cap == 0) {
		return -1;
	}
	memset(&q, 0, sizeof(q));
	strcpy(q.htu, htu);

	EnterCriticalSection(&s->dpop_lock);
	ResetEvent(s->dpop_done);
	if (command(s, IPC_CMD_DPOP, &q, sizeof(q)) == 0 &&
			WaitForSingleObject(s->dpop_done, 5000) == WAIT_OBJECT_0) {
		EnterCriticalSection(&s->lock);
		if (s->dpop.proof[0] != '\0' && strlen(s->dpop.proof) < cap) {
			strcpy(out, s->dpop.proof);
			ret = 0;
		}
		LeaveCriticalSection(&s->lock);
	}
	LeaveCriticalSection(&s->dpop_lock);
	return ret;
}

int vpn_remote_login(vpn_session_t *s, const char *token, size_t len)
{
	if (!s || !token || len == 0 || len > LOGIN_TOKEN_MAX) {
		return -1;
	}

	return command(s, IPC_CMD_LOGIN, token, (uint32_t)len);
}

void vpn_remote_logout(vpn_session_t *s)
{
	if (s) {
		command(s, IPC_CMD_LOGOUT, NULL, 0);
	}
}

void vpn_remote_login_info(vpn_session_t *s, ipc_login_t *out)
{
	memset(out, 0, sizeof(*out));
	if (!s) {
		return;
	}

	EnterCriticalSection(&s->lock);
	*out = s->login;
	LeaveCriticalSection(&s->lock);
}
