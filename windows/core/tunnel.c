#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wintun.h"
#include "json.h"
#include "proto.h"
#include "posture.h"
#include "secure.h"
#include "tunnel.h"

#define HS_TIMEOUT_MSEC 1000
#define HS_RETRY 5

#define HS_OK		0
#define HS_FAIL		(-1)	/* 응답 없음 / 오류 / 중지 요청 */
#define HS_DENIED	(-2)	/* 서버가 거절했다. 다시 보내도 같은 답이 온다 */

#define LOOP_TICK_MSEC 1000
#define POSTURE_POLL_MSEC 2000
#define SERVER_TIMEOUT_MSEC (SERVER_TIMEOUT_SEC * 1000)

/* 답이 없는 LOGIN 을 다시 보내는 간격. keepalive 보다 짧게 잡아 로그인이 늦지 않게 한다. */
#define LOGIN_RETRY_MSEC 3000

#define TUN_RING_CAPACITY 0x400000 /* 4MiB */

/* 구버전 SDK / MinGW의 mstcpip.h에는 없다. */
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

#define RECV_EMPTY (-1)
#define RECV_ERROR (-2)

/* 어댑터 GUID를 고정해 두면 Windows가 매번 새 네트워크로 인식하지 않는다. */
static const GUID ADAPTER_GUID =
	{ 0x6f1d2c4a, 0x8b3e, 0x4d57, { 0x9a, 0x21, 0x5c, 0x7e, 0x0b, 0x4f, 0xd3, 0x18 } };

typedef struct session {
	uint32_t idx;
	secure_session_t secure;	/* 세션 키, 보낼 counter, 받은 counter 의 창 */
	struct sockaddr_in server;
	uint64_t last_rx_ms;
	uint64_t last_tx_ms;
	uint64_t last_ka_ms;	/* 마지막 keepalive 송신 */
	posture_report_t posture;	/* 서버에 마지막으로 보고한 포스처 */
	int denied;		/* 서버가 접근을 거절한 상태. 다시 받아 줄 때까지 보내지 않는다 */
	uint64_t last_posture_ms;	/* 포스처를 마지막으로 읽은 시각 */
} session_t;

typedef struct tunnel {
	const tunnel_config_t *cfg;
	HANDLE stop_event;
	HANDLE sock_event;
	HANDLE tun_event;
	SOCKET sock;
	HMODULE wintun;
	WINTUN_ADAPTER_HANDLE adapter;
	WINTUN_SESSION_HANDLE tun;
	uint32_t bcast;		/* 터널 대역의 브로드캐스트 주소 (network byte order) */
	NET_LUID luid;		/* 어댑터. 주소와 경로를 넣고 뺄 때 쓴다 */
	net_config_t want;	/* 서버가 마지막으로 준 터널 설정 */
	net_config_t applied;	/* 어댑터에 실제로 넣어 둔 것 */
	int has_applied;
	int readdress;		/* 서버가 터널 주소를 바꿨다. 다시 핸드셰이크해서 새 주소로 세션을 연다 */
	int server_closed;	/* 서버가 DISCONNECT 로 세션을 끝냈다. 30초를 기다리지 않고 다시 핸드셰이크한다 */
	uint32_t login_gen;	/* cfg->login 에서 마지막으로 읽은 gen */
	int login_has;		/* 보낼 토큰이 있다 */
	int login_due;		/* 이 세션에 토큰을 보내야 하는데 아직 답을 받지 못했다 */
	int login_sent;		/* 이 세션에 토큰을 보낸 적이 있다 */
	int logout;		/* 로그아웃했다. 사용자가 붙지 않은 새 세션을 연다 */
	int64_t login_exp;	/* 지금 토큰의 exp. 읽지 못했으면 -1 */
	uint64_t last_login_ms;
	uint64_t t0_ms;		/* 패킷 타임스탬프 기준점 */
	uint64_t seq;		/* 패킷 일련번호 */

	/* 이 PC 의 네트워크가 바뀌었다 (net_changed). 알림은 다른 스레드에서 와 net_event 만 세운다. */
	HANDLE net_event;
	HANDLE net_notify;
	uint64_t net_changed_ms;	/* 마지막 알림. 0 이면 처리할 것이 없다 */
	uint64_t net_probe_ms;		/* 바뀐 뒤 확인하려고 keepalive 를 보낸 때. 0 이면 기다리지 않는다 */
	int net_lost;			/* 그 keepalive 에 답이 없다. 다시 핸드셰이크한다 */
	int hs_failed;			/* 마지막 재핸드셰이크가 실패해 30초 뒤를 기다리는 중 */

	/* TCP 로 붙었다 (server/include/tcp.h). UDP 핸드셰이크에 답이 없으면 같은 번호의 TCP 포트로
	 * 바꿔 본다 — UDP 를 막는 네트워크(호텔, 카페, 일부 회사망). 서버는 vpn_server -t <같은 번호>.
	 * 패킷마다 len(2) 을 붙이고, 받은 스트림은 trbuf 에 모아 틀 하나씩 꺼낸다. */
	int tcp;
	int tcp_lost;			/* 연결이 끊겼다. 다시 열고 핸드셰이크한다 */
	uint8_t trbuf[2 + BUF_SIZE];
	size_t trlen;

	session_t session;
} tunnel_t;

/* ---- wintun.dll ---------------------------------------------------------- */
/* Wintun은 import lib 없이 DLL만 배포되므로 실행 중에 함수 주소를 얻는다. */
static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE wintun_load(void)
{
	HMODULE mod;

	mod = LoadLibraryExW(L"wintun.dll", NULL,
			LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!mod) {
		return NULL;
	}

#define X(name) ((*(FARPROC *)&name = GetProcAddress(mod, #name)) == NULL)
	if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunGetAdapterLUID) ||
			X(WintunStartSession) || X(WintunEndSession) || X(WintunGetReadWaitEvent) ||
			X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
			X(WintunAllocateSendPacket) || X(WintunSendPacket)) {
		DWORD err = GetLastError();

		FreeLibrary(mod);
		SetLastError(err);
		return NULL;
	}
#undef X

	return mod;
}

/* ---- callbacks ----------------------------------------------------------- */
static void tlog(const tunnel_t *t, const char *fmt, ...)
{
	char line[256];
	va_list ap;

	if (!t->cfg->on_log) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	t->cfg->on_log(t->cfg->ctx, line);
}

static void set_state(const tunnel_t *t, tunnel_state_t state)
{
	if (t->cfg->on_state) {
		t->cfg->on_state(t->cfg->ctx, state);
	}
}

/* ---- adapter / socket setup ---------------------------------------------- */
/* 터널 대역의 브로드캐스트 주소. prefix가 /32면 브로드캐스트가 없으므로 0을 돌려준다
 * (dst 0.0.0.0은 어차피 전달 대상이 아니라 비교에 써도 무해하다). */
static uint32_t subnet_broadcast(uint32_t addr, uint8_t prefix_len)
{
	uint32_t mask;

	if (prefix_len == 0) {
		return 0xFFFFFFFFu;
	}
	if (prefix_len >= 32) {
		return 0;
	}

	mask = htonl(0xFFFFFFFFu << (32 - prefix_len));

	return (addr & mask) | ~mask;
}

static const char *ip4(uint32_t addr, char *dst)
{
	struct in_addr a;

	a.s_addr = addr;

	return inet_ntop(AF_INET, &a, dst, INET_ADDRSTRLEN);
}

/* 서버가 준 설정을 그대로 쓸 수 있는가. 서버는 인증된 상대지만, 받은 값을 OS 에 넣기
 * 전에 말이 되는지는 본다. 터널 주소가 없거나 MTU 가 버퍼보다 크면 어댑터를 올려도
 * 통하지 않는다. */
static int netcfg_usable(const net_config_t *c)
{
	return c->tun_ip != 0 && c->prefix_len >= 8 && c->prefix_len <= 30 &&
		c->mtu >= 576 && c->mtu <= BUF_SIZE - PKT_OVERHEAD;
}

/* 이 대역을 터널로 돌려도 되는가.
 *
 *   /0                모든 트래픽을 터널로 보내라는 뜻이다. 서버가 그런 값을 줄 일은
 *                     없지만(acl.c 의 acl_routes), 준다고 따르지는 않는다.
 *   서버 주소를 덮는 대역  서버로 가는 UDP 가 터널로 들어간다. 터널 패킷을 싣고 가야
 *                     할 길이 터널 자신이 되어, 넣는 순간 연결이 끊긴다. */
static int route_usable(const tunnel_t *t, const net_route_t *r)
{
	uint32_t mask;

	if (r->prefix_len == 0) {
		return 0;
	}

	mask = htonl(0xFFFFFFFFu << (32 - r->prefix_len));

	return (t->cfg->server_ip.s_addr & mask) != r->addr;
}

static void route_row(const tunnel_t *t, const net_route_t *r, MIB_IPFORWARD_ROW2 *row)
{
	InitializeIpForwardEntry(row);
	row->InterfaceLuid = t->luid;
	row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = r->addr;
	row->DestinationPrefix.PrefixLength = r->prefix_len;
	/* 다음 홉을 0.0.0.0 으로 두면 "이 인터페이스에 바로 붙어 있다"는 뜻이다. 터널은
	 * 점대점이라 게이트웨이가 따로 없고, 어댑터에 넣으면 서버가 받는다. */
	row->NextHop.Ipv4.sin_family = AF_INET;
	row->Metric = 0;
	row->Protocol = MIB_IPPROTO_NETMGMT;
}

static void route_add(tunnel_t *t, const net_route_t *r)
{
	char ib[INET_ADDRSTRLEN];
	MIB_IPFORWARD_ROW2 row;
	DWORD err;

	if (!route_usable(t, r)) {
		tlog(t, "[cfg] route %s/%u ignored (%s)", ip4(r->addr, ib), r->prefix_len,
				r->prefix_len == 0 ? "default route" : "it covers the server address");
		return;
	}

	route_row(t, r, &row);
	err = CreateIpForwardEntry2(&row);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
		tlog(t, "[cfg] route %s/%u failed: %lu", ip4(r->addr, ib), r->prefix_len, err);
		return;
	}

	tlog(t, "[cfg] route + %s/%u", ip4(r->addr, ib), r->prefix_len);
}

static void route_delete(tunnel_t *t, const net_route_t *r)
{
	char ib[INET_ADDRSTRLEN];
	MIB_IPFORWARD_ROW2 row;

	if (!route_usable(t, r)) {
		return;		/* 넣은 적이 없다 */
	}

	route_row(t, r, &row);
	DeleteIpForwardEntry2(&row);
	tlog(t, "[cfg] route - %s/%u", ip4(r->addr, ib), r->prefix_len);
}

static int route_in(const net_config_t *c, const net_route_t *r)
{
	int i;

	for (i = 0; i < c->n_routes; i++) {
		if (c->routes[i].addr == r->addr && c->routes[i].prefix_len == r->prefix_len) {
			return 1;
		}
	}

	return 0;
}

static void address_row(const tunnel_t *t, const net_config_t *c, MIB_UNICASTIPADDRESS_ROW *addr)
{
	InitializeUnicastIpAddressEntry(addr);
	addr->InterfaceLuid = t->luid;
	addr->Address.Ipv4.sin_family = AF_INET;
	addr->Address.Ipv4.sin_addr.s_addr = c->tun_ip;
	addr->OnLinkPrefixLength = c->prefix_len;
	addr->DadState = IpDadStatePreferred;
}

static int mtu_set(tunnel_t *t, uint16_t mtu)
{
	MIB_IPINTERFACE_ROW iface;
	DWORD err;

	InitializeIpInterfaceEntry(&iface);
	iface.Family = AF_INET;
	iface.InterfaceLuid = t->luid;

	err = GetIpInterfaceEntry(&iface);
	if (err != NO_ERROR) {
		tlog(t, "GetIpInterfaceEntry failed: %lu", err);
		return -1;
	}

	iface.NlMtu = mtu;
	iface.SitePrefixLength = 0; /* IPv4에서는 0이어야 SetIpInterfaceEntry가 받아준다 */

	err = SetIpInterfaceEntry(&iface);
	if (err != NO_ERROR) {
		tlog(t, "SetIpInterfaceEntry failed: %lu", err);
		return -1;
	}

	return 0;
}

/* 어댑터를 서버가 준 설정(t->want)에 맞춘다. Linux 의 `ip addr add` / `ip link set mtu` /
 * `ip route add` 에 해당한다.
 *
 * 처음 한 번만 부르는 것이 아니다. 다시 핸드셰이크했을 때와 keepalive 응답으로 새 설정이
 * 왔을 때에도 부른다. 그래서 "설정을 넣는다"가 아니라 "지금 넣어 둔 것(t->applied)과 다른
 * 부분만 고친다"로 짰다. 통째로 지우고 다시 넣으면 바뀌지 않은 경로까지 잠깐 사라져
 * 그 사이의 연결이 끊긴다. */
/* ---- 내부 DNS (NRPT) -------------------------------------------------------------
 *
 * 서버가 내려 준 도메인(과 그 아래 이름)만 내부 DNS 로 묻게 한다 (proto.h 의 분할 DNS).
 * 어댑터에 DNS 서버를 넣는 것만으로는 Windows 가 어느 어댑터의 DNS 에 물을지를 인터페이스
 * 순서로 정해, 모든 이름이 회사로 가거나 내부 이름이 공유기로 간다. NRPT(이름 해석 정책
 * 표)는 "이 이름은 이 DNS 로"를 이름 단위로 정한다. 그룹 정책이 쓰는 키와 같은 모양으로
 * DNS 클라이언트의 로컬 정책 키에 규칙 하나를 둔다.
 *
 * 규칙은 터널이 도는 동안만 둔다. 끝날 때 지우고, 서비스가 죽어 남은 것은 다음에 시작할 때
 * 지운다 — 남아 있으면 내부 이름을 닿지 않는 DNS 로 묻게 된다. */
#define NRPT_KEY L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\ztgate"

/* DNS 클라이언트가 규칙을 다시 읽고, 예전 답을 잊게 한다. 둘 다 실패해도 터널은 돈다 —
 * 그러면 길어야 캐시의 수명 동안 예전 답이 남는다. */
static void nrpt_refresh(void)
{
	typedef BOOL (WINAPI *flush_fn)(void);
	HMODULE dnsapi;
	SC_HANDLE scm, svc;
	SERVICE_STATUS st;

	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm) {
		svc = OpenServiceW(scm, L"Dnscache", SERVICE_PAUSE_CONTINUE);
		if (svc) {
			ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &st);
			CloseServiceHandle(svc);
		}
		CloseServiceHandle(scm);
	}

	/* 문서에 없는 함수지만 ipconfig /flushdns 가 부르는 것이다. 없으면 건너뛴다. */
	dnsapi = LoadLibraryExW(L"dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (dnsapi) {
		flush_fn flush = (flush_fn)(void (*)(void))GetProcAddress(dnsapi, "DnsFlushResolverCache");
		if (flush) {
			flush();
		}
		FreeLibrary(dnsapi);
	}
}

static void nrpt_clear(tunnel_t *t)
{
	LSTATUS err = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, NRPT_KEY, KEY_WOW64_64KEY, 0);

	if (err == ERROR_SUCCESS) {
		if (t) {
			tlog(t, "[cfg] dns: none");
		}
		nrpt_refresh();
	}
}

static void nrpt_apply(tunnel_t *t, const net_config_t *c)
{
	/* 도메인마다 ".corp.example"(그 아래 이름)과 "corp.example"(그 이름 자신) 둘을 적는다. */
	wchar_t names[NET_MAX_DOMAINS * 2 * (NET_DOMAIN_MAX + 2) + 1];
	wchar_t servers[NET_MAX_DNS * (INET_ADDRSTRLEN + 1)];
	char ib[INET_ADDRSTRLEN];
	DWORD v;
	HKEY key;
	LSTATUS err;
	size_t off = 0;
	int i;

	if (c->n_domains == 0) {
		nrpt_clear(t);
		return;
	}

	for (i = 0; i < c->n_domains; i++) {
		off += (size_t)swprintf(names + off, sizeof(names) / sizeof(names[0]) - off, L".%hs", c->domains[i]) + 1;
		off += (size_t)swprintf(names + off, sizeof(names) / sizeof(names[0]) - off, L"%hs", c->domains[i]) + 1;
	}
	names[off++] = L'\0';

	servers[0] = L'\0';
	for (i = 0; i < c->n_dns; i++) {
		size_t len = wcslen(servers);
		swprintf(servers + len, sizeof(servers) / sizeof(servers[0]) - len, L"%s%hs",
				i == 0 ? L"" : L";", ip4(c->dns[i], ib));
	}

	err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, NRPT_KEY, 0, NULL, REG_OPTION_VOLATILE,
			KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &key, NULL);
	if (err != ERROR_SUCCESS) {
		tlog(t, "[cfg] dns: cannot write the name resolution policy: %ld", (long)err);
		return;
	}

	/* 값의 이름과 뜻은 그룹 정책의 NRPT 와 같다. ConfigOptions 8 = GenericDNSServers 를 쓴다. */
	RegSetValueExW(key, L"Name", 0, REG_MULTI_SZ, (const BYTE *)names, (DWORD)(off * sizeof(wchar_t)));
	RegSetValueExW(key, L"GenericDNSServers", 0, REG_SZ, (const BYTE *)servers,
			(DWORD)((wcslen(servers) + 1) * sizeof(wchar_t)));
	v = 0x8;
	RegSetValueExW(key, L"ConfigOptions", 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
	v = 0x2;
	RegSetValueExW(key, L"Version", 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
	RegSetValueExW(key, L"IPSECCARestriction", 0, REG_SZ, (const BYTE *)L"", sizeof(wchar_t));
	RegCloseKey(key);

	nrpt_refresh();
	for (i = 0; i < c->n_domains; i++) {
		tlog(t, "[cfg] dns: %s -> %ls", c->domains[i], servers);
	}
}

static int netcfg_apply(tunnel_t *t)
{
	const net_config_t *want = &t->want;
	net_config_t *cur = &t->applied;
	MIB_UNICASTIPADDRESS_ROW addr;
	char ib[INET_ADDRSTRLEN];
	DWORD err;
	int i;

	if (!t->adapter) {
		return 0;	/* 아직 어댑터가 없다. 만든 뒤에 다시 부른다 */
	}

	if (!t->has_applied || cur->tun_ip != want->tun_ip || cur->prefix_len != want->prefix_len) {
		if (t->has_applied) {
			address_row(t, cur, &addr);
			DeleteUnicastIpAddressEntry(&addr);
		}

		address_row(t, want, &addr);
		err = CreateUnicastIpAddressEntry(&addr);
		if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
			tlog(t, "CreateUnicastIpAddressEntry failed: %lu", err);
			return -1;
		}
		tlog(t, "[cfg] address %s/%u", ip4(want->tun_ip, ib), want->prefix_len);
	}

	if ((!t->has_applied || cur->mtu != want->mtu) && mtu_set(t, want->mtu) < 0) {
		return -1;
	}

	/* 경로 하나가 들어가지 않는 것은 터널 전체를 내릴 이유가 아니다. 그 대역만 못 간다. */
	if (t->has_applied) {
		for (i = 0; i < cur->n_routes; i++) {
			if (!route_in(want, &cur->routes[i])) {
				route_delete(t, &cur->routes[i]);
			}
		}
	}
	for (i = 0; i < want->n_routes; i++) {
		if (!t->has_applied || !route_in(cur, &want->routes[i])) {
			route_add(t, &want->routes[i]);
		}
	}

	if (!t->has_applied ? want->n_domains > 0 : !net_dns_equal(cur, want)) {
		nrpt_apply(t, want);
	}

	*cur = *want;
	t->has_applied = 1;
	t->bcast = subnet_broadcast(cur->tun_ip, cur->prefix_len);

	return 0;
}

/* 서버에 TCP 로 붙는다. 기다리는 것은 5초까지. 이벤트는 지금의 sock_event 를 그대로 쓴다 — 터널
 * 루프가 그 핸들을 기다리고 있다. */
static int socket_open_tcp(tunnel_t *t)
{
	u_long nb = 1;
	BOOL one = TRUE;
	fd_set wr;
	struct timeval tv = { 5, 0 };
	int err = 0, errlen = (int)sizeof(err);

	t->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (t->sock == INVALID_SOCKET) {
		tlog(t, "socket (tcp) failed: %d", WSAGetLastError());
		return -1;
	}
	ioctlsocket(t->sock, FIONBIO, &nb);
	setsockopt(t->sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
	if (connect(t->sock, (struct sockaddr *)&t->session.server, sizeof(t->session.server)) == SOCKET_ERROR &&
			WSAGetLastError() != WSAEWOULDBLOCK) {
		tlog(t, "[tcp] connect failed: %d", WSAGetLastError());
		return -1;
	}
	FD_ZERO(&wr);
	FD_SET(t->sock, &wr);
	if (select(0, NULL, &wr, NULL, &tv) != 1 ||
			getsockopt(t->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) == SOCKET_ERROR || err != 0) {
		tlog(t, "[tcp] no connection to the server (%d)", err);
		return -1;
	}
	if (WSAEventSelect(t->sock, t->sock_event, FD_READ | FD_CLOSE) == SOCKET_ERROR) {
		tlog(t, "WSAEventSelect failed: %d", WSAGetLastError());
		return -1;
	}
	t->tcp = 1;
	t->tcp_lost = 0;
	t->trlen = 0;
	return 0;
}

/* 지금의 소켓을 닫고 UDP(tcp=0) 또는 TCP(tcp=1) 로 새로 연다. */
static int socket_open(tunnel_t *t);

static int transport_switch(tunnel_t *t, int tcp)
{
	if (t->sock != INVALID_SOCKET) {
		closesocket(t->sock);
		t->sock = INVALID_SOCKET;
	}
	t->tcp = 0;
	if (tcp) {
		if (socket_open_tcp(t) < 0) {
			return -1;
		}
		tlog(t, "[tcp] connected to the server over tcp");
		return 0;
	}
	return socket_open(t);
}

static int socket_open(tunnel_t *t)
{
	struct sockaddr_in local;
	BOOL connreset = FALSE;
	DWORD bytes = 0;

	t->tcp = 0;
	t->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (t->sock == INVALID_SOCKET) {
		tlog(t, "socket failed: %d", WSAGetLastError());
		return -1;
	}

	/* 보내기 전에 recvfrom을 불러도 WSAEINVAL이 나지 않도록 미리 bind 해 둔다. */
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = 0;
	if (bind(t->sock, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR) {
		tlog(t, "bind failed: %d", WSAGetLastError());
		return -1;
	}

	/* Windows는 ICMP port unreachable을 받으면 다음 recvfrom을 WSAECONNRESET으로 실패시킨다.
	 * 서버가 잠시 내려가 있는 동안에도 계속 돌아야 하므로 이 동작을 끈다. */
	if (WSAIoctl(t->sock, SIO_UDP_CONNRESET, &connreset, sizeof(connreset),
				NULL, 0, &bytes, NULL, NULL) == SOCKET_ERROR) {
		tlog(t, "SIO_UDP_CONNRESET failed: %d", WSAGetLastError());
	}

	/* auto-reset 이벤트. WSAEventSelect를 걸면 소켓은 non-blocking이 된다. 전송을 바꿀 때는 같은
	 * 이벤트를 다시 쓴다 (transport_switch). */
	if (!t->sock_event) {
		t->sock_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	}
	if (!t->sock_event) {
		tlog(t, "CreateEvent failed: %lu", GetLastError());
		return -1;
	}

	if (WSAEventSelect(t->sock, t->sock_event, FD_READ) == SOCKET_ERROR) {
		tlog(t, "WSAEventSelect failed: %d", WSAGetLastError());
		return -1;
	}

	return 0;
}

/* ---- udp helpers --------------------------------------------------------- */
/* 받은 바이트 수를 돌려준다. 큐가 비었으면 RECV_EMPTY, 복구할 수 없는 오류는 RECV_ERROR. */
/* TCP 로 받아 둔 것에서 다 들어온 틀 하나. 없으면 소켓에서 더 읽어 본다. 끊기면 tcp_lost 를 세우고
 * RECV_EMPTY — 터널 루프가 다시 열고 핸드셰이크한다. */
static int tcp_recv(tunnel_t *t, uint8_t *buf, int cap, struct sockaddr_in *from)
{
	size_t len;
	int n;

	for (;;) {
		if (t->trlen >= 2) {
			len = (size_t)(t->trbuf[0] << 8 | t->trbuf[1]);
			if (len == 0 || len > BUF_SIZE || len > (size_t)cap) {
				tlog(t, "[tcp] broken frame from the server");
				t->tcp_lost = 1;
				t->trlen = 0;
				return RECV_EMPTY;
			}
			if (t->trlen >= 2 + len) {
				memcpy(buf, t->trbuf + 2, len);
				memmove(t->trbuf, t->trbuf + 2 + len, t->trlen - 2 - len);
				t->trlen -= 2 + len;
				*from = t->session.server;
				return (int)len;
			}
		}
		if (t->tcp_lost) {
			return RECV_EMPTY;
		}
		n = recv(t->sock, (char *)t->trbuf + t->trlen, (int)(sizeof(t->trbuf) - t->trlen), 0);
		if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
			return RECV_EMPTY;
		}
		if (n <= 0) {
			if (!t->tcp_lost) {
				tlog(t, "[tcp] connection to the server closed");
			}
			t->tcp_lost = 1;
			return RECV_EMPTY;
		}
		t->trlen += (size_t)n;
	}
}

static int udp_recv(tunnel_t *t, uint8_t *buf, int cap, struct sockaddr_in *from)
{
	int fromlen;
	int n;
	int err;

	if (t->tcp) {
		return tcp_recv(t, buf, cap, from);
	}

	for (;;) {
		fromlen = (int)sizeof(*from);
		n = recvfrom(t->sock, (char *)buf, cap, 0, (struct sockaddr *)from, &fromlen);
		if (n != SOCKET_ERROR) {
			return n;
		}

		err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			return RECV_EMPTY;
		}
		if (err == WSAECONNRESET || err == WSAEMSGSIZE) {
			continue;
		}

		tlog(t, "recvfrom failed: %d", err);
		return RECV_ERROR;
	}
}

/* 틀 하나를 끝까지 보낸다 (반만 보내면 뒤의 틀이 모두 어긋난다). 소켓이 non-blocking 이라 버퍼가
 * 차면 1초까지 기다린다. 그래도 안 되면 연결을 버린다. */
static void tcp_send(tunnel_t *t, const uint8_t *buf, int len)
{
	uint8_t frame[2 + BUF_SIZE];
	int off = 0, total = 2 + len, n;
	fd_set wr;
	struct timeval tv = { 1, 0 };

	if (t->tcp_lost || len <= 0 || len > BUF_SIZE) {
		return;
	}
	frame[0] = (uint8_t)(len >> 8);
	frame[1] = (uint8_t)len;
	memcpy(frame + 2, buf, (size_t)len);
	while (off < total) {
		n = send(t->sock, (const char *)frame + off, total - off, 0);
		if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
			FD_ZERO(&wr);
			FD_SET(t->sock, &wr);
			if (select(0, NULL, &wr, NULL, &tv) == 1) {
				continue;
			}
		}
		if (n <= 0) {
			tlog(t, "[tcp] send failed: %d", WSAGetLastError());
			t->tcp_lost = 1;
			return;
		}
		off += n;
	}
}

static void udp_send(tunnel_t *t, const uint8_t *buf, int len)
{
	session_t *session = &t->session;

	if (t->tcp) {
		tcp_send(t, buf, len);
		session->last_tx_ms = GetTickCount64();
		return;
	}
	if (sendto(t->sock, (const char *)buf, len, 0,
				(struct sockaddr *)&session->server, sizeof(session->server)) == SOCKET_ERROR) {
		tlog(t, "sendto failed: %d", WSAGetLastError());
	}
	session->last_tx_ms = GetTickCount64();
}

static int from_server(const session_t *session, const struct sockaddr_in *from)
{
	return from->sin_addr.s_addr == session->server.sin_addr.s_addr &&
		from->sin_port == session->server.sin_port;
}

/* ---- outbound filter ----------------------------------------------------- */
/* 서버는 inner dst로 피어를 1:1로 찾아(peer_lookup) 그 피어에게만 보내므로,
 * 멀티캐스트나 브로드캐스트는 애초에 전달할 상대가 없다.
 *
 * Linux의 tun0은 조용하지만 Windows는 어댑터가 올라오는 순간부터 모든 인터페이스에
 * mDNS / LLMNR / SSDP / IGMP를 꾸준히 내보낸다. 이를 그대로 터널에 넣으면
 *   1) 서버는 자기 tun에 write한 뒤 커널이 버리므로 응답이 돌아오지 않고,
 *   2) udp_send()가 last_tx_ms를 10초 안에 계속 갱신해 유휴 keepalive가 영구히 억제되어
 * 결국 서버가 살아 있는데도 30초마다 재핸드셰이크가 돈다. */
static int deliverable_dst(const tunnel_t *t, const uint8_t *ip)
{
	uint32_t dst;

	/* 224.0.0.0/4 멀티캐스트와 240.0.0.0/4 (255.255.255.255 포함) */
	if (ip[IP_DST_OFF] >= 224) {
		return 0;
	}

	memcpy(&dst, ip + IP_DST_OFF, IP_ADDR_LEN);

	return dst != t->bcast;
}

/* ---- packet events ------------------------------------------------------- */
const char *tunnel_verdict_name(int verdict)
{
	switch (verdict) {
	case TUNNEL_PASS:		return "pass";
	case TUNNEL_DROP_NON_IPV4:	return "non-IPv4";
	case TUNNEL_DROP_NON_UNICAST:	return "non-unicast";
	case TUNNEL_DROP_TOO_LONG:	return "too long";
	case TUNNEL_DROP_NOT_SERVER:	return "not from server";
	case TUNNEL_DROP_BAD_HEADER:	return "bad header";
	case TUNNEL_DROP_WRONG_SESSION:	return "wrong session";
	case TUNNEL_DROP_UNKNOWN_TYPE:	return "unknown type";
	case TUNNEL_DROP_IO_ERROR:	return "io error";
	case TUNNEL_DROP_DENIED:	return "access denied";
	case TUNNEL_DROP_BAD_TAG:	return "tag does not match";
	case TUNNEL_DROP_REPLAY:	return "counter already seen";
	default:			return "?";
	}
}

static void pkt_init(const tunnel_t *t, tunnel_packet_t *p, int dir, int verdict)
{
	memset(p, 0, sizeof(*p));
	p->t_ms = GetTickCount64() - t->t0_ms;
	p->dir = (uint8_t)dir;
	p->verdict = (uint8_t)verdict;
}

/* inner IPv4 헤더에서 주소 / 프로토콜과 L4 식별 정보를 꺼낸다.
 * ihl 을 신뢰하지 않고 길이를 매번 확인한다 — 신뢰할 수 없는 입력이다. */
static void pkt_inner(tunnel_packet_t *p, const uint8_t *ip, uint32_t len)
{
	uint32_t ihl;

	if (len < IP_MIN_HDR) {
		return;
	}

	p->has_inner = 1;
	p->inner_len = len;
	p->proto = ip[IP_PROTO_OFF];
	memcpy(&p->inner_src, ip + IP_SRC_OFF, IP_ADDR_LEN);
	memcpy(&p->inner_dst, ip + IP_DST_OFF, IP_ADDR_LEN);

	ihl = (uint32_t)IP_IHL(ip);
	if (ihl < IP_MIN_HDR || ihl > len) {
		return;
	}

	if (p->proto == 1) {			/* ICMP: type / code */
		if (len - ihl >= 2) {
			p->has_l4 = 1;
			p->icmp_type = ip[ihl];
			p->icmp_code = ip[ihl + 1];
		}
	}
	else if (p->proto == 6 || p->proto == 17) {	/* TCP / UDP: 포트 */
		if (len - ihl >= 4) {
			uint16_t v;

			p->has_l4 = 1;
			memcpy(&v, ip + ihl + L4_SPORT_OFF, L4_PORT_LEN);
			p->sport = ntohs(v);
			memcpy(&v, ip + ihl + L4_DPORT_OFF, L4_PORT_LEN);
			p->dport = ntohs(v);
		}
	}
}

/* 상세창 hex 덤프용. 와이어 앞부분을 그대로 떠 둔다. */
static void pkt_snap(tunnel_packet_t *p, const uint8_t *wire, uint32_t len)
{
	uint32_t n = len < TUNNEL_SNAP_LEN ? len : TUNNEL_SNAP_LEN;

	memcpy(p->snap, wire, n);
	p->snap_len = (uint8_t)n;
}

/* 보낸 패킷은 감싸기 전의 모습으로 떠 둔다: 우리 헤더와 counter(sealed 의 앞 16B,
 * 암호화되지 않는 부분) 뒤에 원래의 inner 패킷. */
static void pkt_snap_plain(tunnel_packet_t *p, const uint8_t *sealed, const uint8_t *inner, uint32_t len)
{
	uint32_t room = TUNNEL_SNAP_LEN - (uint32_t)PKT_HDR_LEN;
	uint32_t n = len < room ? len : room;

	memcpy(p->snap, sealed, PKT_HDR_LEN);
	memcpy(p->snap + PKT_HDR_LEN, inner, n);
	p->snap_len = (uint8_t)(PKT_HDR_LEN + n);
}

static void pkt_emit(tunnel_t *t, tunnel_packet_t *p)
{
	if (!t->cfg->on_packet) {
		return;
	}

	p->seq = ++t->seq;
	t->cfg->on_packet(t->cfg->ctx, p);
}

/* 패킷 텍스트 로그는 on_packet 이 없을 때만 남긴다 (콘솔 클라이언트용).
 * 둘 다 켜면 같은 내용을 두 번 만드는 셈이다. */
static int pkt_log_text(const tunnel_t *t)
{
	return t->cfg->log_packets && !t->cfg->on_packet;
}

static const char *deny_reason_name(uint8_t reason)
{
	switch (reason) {
	case DENY_UNKNOWN_DEVICE:	return "unknown device";
	case DENY_BAD_AUTH:		return "bad auth";
	case DENY_TUN_IP:		return "tunnel ip not assigned to this device";
	case DENY_POSTURE:		return "posture does not meet policy";
	default:			return "?";
	}
}

static const char *login_status_name(uint8_t status)
{
	switch (status) {
	case LOGIN_OK:		return "ok";
	case LOGIN_NO_IDP:	return "this server does not take user logins";
	case LOGIN_MALFORMED:	return "not a JWT, or too large";
	case LOGIN_UNTRUSTED:	return "signature not trusted (algorithm, key id or signature)";
	case LOGIN_WRONG_TOKEN:	return "token is for another issuer or audience";
	case LOGIN_EXPIRED:	return "token expired or not yet valid";
	case LOGIN_BAD_USER:	return "no usable user name in the token";
	default:		return "?";
	}
}

/* 수집한 포스처를 와이어 형식으로 옮긴다. 지금은 값이 같지만 수집 쪽 enum 과
 * 와이어 값을 캐스팅으로 잇지 않는다. 한쪽 순서를 바꾸면 조용히 어긋난다. */
static uint8_t posture_wire_state(uint8_t state)
{
	switch (state) {
	case POSTURE_ON:	return POSTURE_STATE_ON;
	case POSTURE_OFF:	return POSTURE_STATE_OFF;
	default:		return POSTURE_STATE_UNKNOWN;
	}
}

static void posture_report_now(posture_report_t *report)
{
	posture_t p;

	posture_collect(&p);

	memset(report, 0, sizeof(*report));
	report->os_build = p.os_build;
	report->firewall = posture_wire_state(p.firewall);
	report->antivirus = posture_wire_state(p.antivirus);
	report->disk = posture_wire_state(p.disk);
}

static void pkt_netcfg(tunnel_packet_t *p, const net_config_t *c)
{
	p->has_netcfg = 1;
	p->cfg_tun_ip.s_addr = c->tun_ip;
	p->cfg_prefix_len = c->prefix_len;
	p->cfg_routes = c->n_routes;
}

/* 핸드셰이크 패킷 하나를 UI 로 올린다. */
static void hs_emit(tunnel_t *t, int dir, const msg_header_t *h, const uint8_t *wire, int len,
		const posture_report_t *posture, uint8_t deny_reason)
{
	tunnel_packet_t pkt;

	pkt_init(t, &pkt, dir, TUNNEL_PASS);
	pkt.msg_type = h->type;
	pkt.session_idx = h->session_idx;
	pkt.deny_reason = deny_reason;
	if (posture) {
		pkt.has_posture = 1;
		pkt.posture = *posture;
	}
	/* 받아들인 수락에는 서버가 정해 준 터널 설정이 들어 있다 (accept_hs_response 가
	 * t->want 에 풀어 둔다). 화면이 "어떤 주소를 받았는가"를 여기서 읽는다. */
	if (dir == TUNNEL_DIR_RX && h->type == MSG_TYPE_RES_HANDSHAKE) {
		pkt_netcfg(&pkt, &t->want);
	}
	pkt.wire_len = (uint32_t)len;
	pkt_snap(&pkt, wire, (uint32_t)len);
	pkt_emit(t, &pkt);
}

/* deadline 까지 서버가 보낸 우리 버전의 패킷 하나를 기다린다.
 * 받은 길이(>= 헤더 길이)를 돌려주고, 시간이 다 되면 0, 오류나 중지 요청은 HS_FAIL. */
static int hs_recv(tunnel_t *t, uint64_t deadline, uint8_t *buf, int cap, msg_header_t *h)
{
	HANDLE waits[2] = { t->stop_event, t->sock_event };
	struct sockaddr_in from;
	uint64_t now;
	DWORD w;
	int n;

	for (;;) {
		while ((n = udp_recv(t, buf, cap, &from)) >= 0) {
			if (!from_server(&t->session, &from)) {
				continue;
			}
			if (msg_decode(buf, (size_t)n, h) < 0 || h->version != PROTOCOL_VERSION) {
				continue;
			}
			return n;
		}
		if (n == RECV_ERROR) {
			return HS_FAIL;
		}

		now = GetTickCount64();
		if (now >= deadline) {
			return 0;
		}

		w = WaitForMultipleObjects(2, waits, FALSE, (DWORD)(deadline - now));
		if (w == WAIT_OBJECT_0) {
			return HS_FAIL;
		}
		if (w == WAIT_FAILED) {
			tlog(t, "WaitForMultipleObjects failed: %lu", GetLastError());
			return HS_FAIL;
		}
	}
}

/* REQ_HANDSHAKE: zero(80). 누구인지 밝히지 않는다 — 기기 ID 는 AUTH 에 감싸 보낸다. */
static void send_hs_request(tunnel_t *t)
{
	uint8_t req[sizeof(msg_header_t) + REQ_HS_PAYLOAD_LEN];
	msg_header_t h;

	memset(req, 0, sizeof(req));
	memset(&h, 0, sizeof(h));
	h.version = PROTOCOL_VERSION;
	h.type = MSG_TYPE_REQ_HANDSHAKE;
	msg_encode(req, sizeof(req), &h);

	udp_send(t, req, (int)sizeof(req));
	hs_emit(t, TUNNEL_DIR_TX, &h, req, (int)sizeof(req), NULL, 0);
}

/* 진행 중인 핸드셰이크 한 번의 상태. 세션 키에는 내가 보낸 AUTH 의 바이트와 그때 쓴
 * 일회용 키가 들어가므로 수락이 올 때까지 들고 있는다. */
typedef struct handshake {
	crypt_ecdh_t *ecdh;
	uint8_t auth[AUTH_PACKET_LEN];
	int auth_sent;
} handshake_t;

static void hs_reset(handshake_t *hs)
{
	crypt_ecdh_free(hs->ecdh);
	memset(hs, 0, sizeof(*hs));
}

/* AUTH: pub_c(64) | nonce(16) | sealed(device_id(16) | posture(8)) | tag(16) | mac(32)
 *
 * challenge 는 CHALLENGE 의 페이로드 nonce(16) | server_pub(64). 기기 ID 와 포스처는 server_pub 과
 * 이번 일회용 키로 감싼다 (secure_auth_seal) — 엿보는 쪽에게는 매번 다른 바이트다.
 *
 * mac 은 헤더부터 그 앞까지 전체를 덮는다. 서버가 방금 준 nonce 가 들어가므로 이
 * 패킷은 이번 핸드셰이크에만 유효하고, 포스처도 서명 범위 안이라 전달 도중에
 * "방화벽 꺼짐"을 "켜짐"으로 고칠 수 없다. 포스처는 핸드셰이크를 시작할 때가
 * 아니라 AUTH 를 만드는 지금 읽는다.
 *
 * pub_c 도 서명 범위 안이다. 사이에 낀 쪽이 이것을 자기 공개키로 바꾸면 mac 이
 * 틀려 서버가 받지 않는다. */
static int send_hs_auth(tunnel_t *t, handshake_t *hs, const uint8_t *challenge)
{
	posture_report_t *report = &t->session.posture;
	uint8_t *auth = hs->auth;
	uint8_t *body = auth + sizeof(msg_header_t);
	msg_header_t h;

	memset(&h, 0, sizeof(h));
	h.version = PROTOCOL_VERSION;
	h.type = MSG_TYPE_AUTH;
	msg_encode(auth, sizeof(hs->auth), &h);

	memcpy(body + AUTH_OFF_NONCE, challenge, AUTH_NONCE_LEN);

	/* 핸드셰이크마다 새 키 쌍이다. 다시 쓰면 "지난 세션은 풀리지 않는다"가 깨진다. */
	hs->ecdh = crypt_ecdh_new(body + AUTH_OFF_PUB);
	if (hs->ecdh == NULL) {
		tlog(t, "[HS] key generation failed");
		return -1;
	}

	/* 세션에 남겨 둔다. 이후 keepalive 가 "보고한 값에서 달라졌는가"를 이것과 비교한다. */
	posture_report_now(report);
	t->session.last_posture_ms = GetTickCount64();
	posture_encode(body + AUTH_OFF_POSTURE, sizeof(*report), report);
	memcpy(body + AUTH_OFF_ID, t->cfg->device_id, DEVICE_ID_LEN);
	if (secure_auth_seal(hs->ecdh, challenge + AUTH_NONCE_LEN, auth) < 0) {
		tlog(t, "[HS] the server's public key is not usable");
		return -1;
	}

	if (crypt_hmac(t->cfg->device_key, AUTH_KEY_LEN, auth, AUTH_SIGNED_LEN,
				body + AUTH_OFF_MAC) < 0) {
		tlog(t, "[HS] hmac failed");
		return -1;
	}

	tlog(t, "[HS] auth: build=%u firewall=%u antivirus=%u disk=%u",
			report->os_build, report->firewall, report->antivirus, report->disk);

	udp_send(t, auth, (int)AUTH_PACKET_LEN);
	hs_emit(t, TUNNEL_DIR_TX, &h, auth, (int)AUTH_PACKET_LEN, report, 0);
	hs->auth_sent = 1;

	return 0;
}

/* RES_HANDSHAKE: pub_s(64) | 암호화된 net_config | tag(16)
 *
 * 서버의 일회용 공개키와 내 것으로 합의하고, 거기에 기기 키를 섞어 세션 키를 뽑는다.
 * tag 가 맞으면 상대도 같은 키에 닿았다는 뜻이고, 그러려면 이 기기의 키를 알아야 한다.
 * 맞지 않으면 서버가 보낸 것이 아니므로 버린다. 0 을 돌려주면 세션이 열린 것이다.
 *
 * 수락에는 서버가 이 기기에 정해 준 터널 설정이 들어 있다. 주소와 경로를 사용자가
 * 적는 것이 아니라 서버의 정책에서 받는다. */
static int accept_hs_response(tunnel_t *t, handshake_t *hs, uint8_t *res, int len, uint32_t session_idx)
{
	uint8_t secret[VPN_SECRET_LEN];
	secure_keys_t keys;
	net_config_t cfg;
	int cfg_len;
	int ret = -1;

	if (crypt_ecdh_derive(hs->ecdh, res + sizeof(msg_header_t), secret) < 0 ||
			secure_derive(t->cfg->device_key, secret, hs->auth, res, &keys) < 0) {
		goto out;
	}

	cfg_len = secure_res_open(keys.res, res, (size_t)len);
	if (cfg_len < 0) {
		goto out;
	}

	/* 여기부터는 서버가 보낸 것이 맞다. 그래도 쓸 수 없는 설정이면 세션을 열지 않는다 —
	 * 주소 없이 열린 터널은 아무 데도 닿지 않는데 화면에는 "연결됨"으로 보인다. */
	if (net_config_decode(res + RES_HS_HEAD_LEN, (size_t)cfg_len, &cfg) < 0 || !netcfg_usable(&cfg)) {
		tlog(t, "[HS] the server sent a tunnel configuration this client cannot use");
		goto out;
	}

	if (secure_session_open(&t->session.secure, keys.c2s, keys.s2c) < 0) {
		goto out;
	}
	t->session.idx = session_idx;
	t->want = cfg;
	t->readdress = 0;
	ret = 0;

out:
	crypt_wipe(secret, sizeof(secret));
	crypt_wipe(&keys, sizeof(keys));

	return ret;
}

/* 핸드셰이크 중에 온 DENY 를 서버가 보낸 것으로 믿어도 되는가.
 *
 * 서버는 서명이 맞는 AUTH 를 받은 뒤의 거절(터널 IP, 포스처)에 기기 키로 만든 mac 을
 * 붙인다. 그 전의 거절(모르는 기기, 인증 실패)은 서버가 우리 키를 확인하지 못한
 * 상태에서 나오므로 mac 이 없고, 서버 주소를 위조할 수 있는 누구나 만들 수 있다. */
static int deny_verified(const tunnel_t *t, const handshake_t *hs, const uint8_t *body)
{
	uint8_t want[AUTH_MAC_LEN];

	if (!hs->auth_sent) {
		return 0;
	}

	if (secure_deny_mac(t->cfg->device_key, body[0],
				hs->auth + AUTH_SIGNED_LEN, want) < 0) {
		return 0;
	}

	return crypt_equal(want, body + 1, AUTH_MAC_LEN);
}

/* ---- protocol ------------------------------------------------------------ */
/*   C -> S  REQ_HANDSHAKE     "핸드셰이크를 하고 싶다" (누구인지는 아직 말하지 않는다)
 *   S -> C  CHALLENGE         "이 nonce 에 서명해 봐라. ID 는 이 공개키로 감싸라"
 *   C -> S  AUTH              내 일회용 공개키 + nonce + 감싼 기기 ID + 포스처 + mac
 *   S -> C  RES_HANDSHAKE     세션 idx + 서버의 일회용 공개키 + tag   (또는 DENY 와 사유)
 *
 * HS_OK / HS_FAIL / HS_DENIED 를 돌려준다. */
static int do_handshake(tunnel_t *t)
{
	uint8_t res[BUF_SIZE];
	const uint8_t *body;
	handshake_t hs;
	msg_header_t h;
	uint64_t deadline;
	uint8_t loose_deny;
	int body_len;
	int ret = HS_FAIL;
	int tries;
	int n;

	memset(&hs, 0, sizeof(hs));

	for (tries = 1; tries <= HS_RETRY; tries++) {
		tlog(t, "[HS] request %d/%d", tries, HS_RETRY);
		hs_reset(&hs);
		loose_deny = 0;
		send_hs_request(t);

		deadline = GetTickCount64() + HS_TIMEOUT_MSEC;
		for (;;) {
			n = hs_recv(t, deadline, res, (int)sizeof(res), &h);
			if (n == HS_FAIL) {
				goto out;
			}
			if (n == 0) {
				break;	/* 응답이 없다. REQ 부터 다시 */
			}

			body = res + sizeof(msg_header_t);
			body_len = n - (int)sizeof(msg_header_t);

			switch (h.type) {
			case MSG_TYPE_CHALLENGE:
				/* 한 번의 시도에 AUTH 는 하나다. 중복된 CHALLENGE 에 다시 답하면
				 * 일회용 키가 바뀌어, 먼저 보낸 AUTH 에 대한 수락을 열지 못한다. */
				if (body_len < CHALLENGE_PAYLOAD_LEN || hs.auth_sent) {
					continue;
				}
				hs_emit(t, TUNNEL_DIR_RX, &h, res, n, NULL, 0);

				/* 등록 때 받은 서버 공개키와 다르면 그 공개키로 ID 를 감싸지 않는다. 진짜
				 * 서버의 CHALLENGE 가 따로 오면 그것에 답한다. */
				if (t->cfg->has_server_pub &&
						!crypt_equal(t->cfg->server_pub, body + AUTH_NONCE_LEN, VPN_PUB_LEN)) {
					tlog(t, "[HS] the server's key is not the one this device enrolled with; ignoring that challenge");
					continue;
				}

				if (send_hs_auth(t, &hs, body) < 0) {
					goto out;
				}
				deadline = GetTickCount64() + HS_TIMEOUT_MSEC;
				continue;

			case MSG_TYPE_DENY:
				/* 세션 번호가 붙은 DENY 는 열려 있던 세션에 대한 것이다. 여기서는
				 * 그 세션을 버리고 새로 여는 중이므로 볼 필요가 없다. */
				if (n < (int)DENY_HS_LEN || h.session_idx != 0) {
					continue;
				}
				hs_emit(t, TUNNEL_DIR_RX, &h, res, n, NULL, body[0]);

				if (deny_verified(t, &hs, body)) {
					tlog(t, "[HS] denied: %s", deny_reason_name(body[0]));
					ret = HS_DENIED;
					goto out;
				}

				/* 확인할 수 없는 거절이다. 곧바로 믿으면 서버 주소를 위조한 패킷 한
				 * 통으로 접속을 막을 수 있다. 기억만 해 두고 진짜 서버의 답을 끝까지
				 * 기다린다 — 그동안 아무것도 오지 않았을 때에만 이것을 답으로 친다. */
				if (loose_deny == 0) {
					loose_deny = body[0];
				}
				continue;

			case MSG_TYPE_RES_HANDSHAKE:
				/* AUTH 를 보내기 전에 온 수락은 받지 않는다. 그리고 tag 가 맞지 않는
				 * 수락도 받지 않는다 — 기기 키를 모르는 쪽은 맞는 tag 를 만들 수 없다. */
				if (!hs.auth_sent || h.session_idx == 0 || n < (int)RES_HS_MIN_LEN) {
					continue;
				}
				if (accept_hs_response(t, &hs, res, n, h.session_idx) < 0) {
					tlog(t, "[HS] response did not verify, ignored");
					continue;
				}
				hs_emit(t, TUNNEL_DIR_RX, &h, res, n, NULL, 0);

				tlog(t, "[HS] established idx=%08x", t->session.idx);
				ret = HS_OK;
				goto out;

			default:
				continue;
			}
		}

		if (loose_deny != 0) {
			tlog(t, "[HS] denied: %s", deny_reason_name(loose_deny));
			ret = HS_DENIED;
			goto out;
		}
	}

	tlog(t, "[HS] no response from server");

out:
	hs_reset(&hs);

	return ret;
}

/* KEEPALIVE: counter(8) | 암호화된 posture(8) | tag(16)
 *
 * 핸드셰이크에서 한 번 통과했다고 세션이 끝날 때까지 믿지 않는다. keepalive 마다
 * 지금의 포스처를 다시 싣고, 서버는 받을 때마다 정책을 다시 평가한다.
 *
 * 데이터 패킷과 같은 세션 키, 같은 counter 로 감싼다. 세션 키는 이 세션에서만 쓰이고
 * counter 는 패킷마다 늘어나므로, 다른 세션의 것을 끼워 넣거나 예전 것을 다시 보내면
 * 서버가 열지 못한다. */
static void send_keepalive(tunnel_t *t)
{
	session_t *session = &t->session;
	uint8_t packet[PKT_OVERHEAD + sizeof(posture_report_t)];
	uint8_t plain[PKT_HDR_LEN + sizeof(posture_report_t)];
	tunnel_packet_t pkt;
	uint64_t counter = session->secure.tx_counter;
	int n;

	posture_encode(packet + PKT_HDR_LEN, sizeof(posture_report_t), &session->posture);
	memcpy(plain + PKT_HDR_LEN, packet + PKT_HDR_LEN, sizeof(posture_report_t));

	n = secure_seal(&session->secure, MSG_TYPE_KEEPALIVE, session->idx,
			packet, sizeof(packet), sizeof(posture_report_t));
	if (n < 0) {
		tlog(t, "[keepalive] seal failed");
		return;
	}
	memcpy(plain, packet, PKT_HDR_LEN);

	udp_send(t, packet, n);
	t->session.last_ka_ms = t->session.last_tx_ms;

	if (pkt_log_text(t)) {
		tlog(t, "[keepalive] sent");
	}

	/* 화면에는 감싸기 전의 모습을 올린다. 암호문을 올리면 상세창이 보여 줄 것이 없다. */
	pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_PASS);
	pkt.msg_type = MSG_TYPE_KEEPALIVE;
	pkt.session_idx = session->idx;
	pkt.has_counter = 1;
	pkt.counter = counter;
	pkt.has_posture = 1;
	pkt.posture = session->posture;
	pkt.wire_len = (uint32_t)n;
	pkt_snap(&pkt, plain, sizeof(plain));
	pkt_emit(t, &pkt);
}

/* ---- 네트워크가 바뀔 때 --------------------------------------------------------
 *
 * 와이파이를 바꾸거나 랜선을 꽂거나 절전에서 깨어나면 이 PC 의 외부 주소가 바뀐다. 서버는
 * 세션 키로 열리는 패킷이 새 주소에서 오면 그 주소로 갈아탄다 (peer_touch). 그러니 바뀐
 * 즉시 keepalive 를 하나 보내 보면 대개 그것으로 이어진다. 답이 없으면 그 길로는 서버에
 * 닿지 않는 것이라(새 네트워크가 UDP 를 막거나, 서버가 세션을 잃었다) 30초를 기다리지 않고
 * 다시 핸드셰이크한다.
 *
 * 주소가 생기고 DHCP 가 끝나는 동안 알림이 몇 번 몰려 오므로 NET_SETTLE_MSEC 동안 조용해진
 * 뒤에 한 번만 본다. */
#define NET_SETTLE_MSEC 1500
#define NET_PROBE_MSEC 3000

/* IPv4 주소가 생기거나 사라졌다. 알림 스레드에서 불리므로 이벤트만 세운다. 터널 어댑터
 * 자신의 주소는 netcfg_apply 가 넣는 것이라 보지 않는다. */
static VOID NETIOAPI_API_ on_address_change(PVOID ctx, PMIB_UNICASTIPADDRESS_ROW row,
		MIB_NOTIFICATION_TYPE type)
{
	tunnel_t *t = ctx;

	if (type == MibInitialNotification) {
		return;
	}
	if (row != NULL && row->InterfaceLuid.Value == t->luid.Value) {
		return;
	}
	SetEvent(t->net_event);
}

static void net_watch_start(tunnel_t *t)
{
	DWORD err;

	t->net_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (!t->net_event) {
		return;
	}
	err = NotifyUnicastIpAddressChange(AF_INET, on_address_change, t, FALSE, &t->net_notify);
	if (err != NO_ERROR) {
		/* 없어도 돈다. 그때는 예전처럼 30초 동안 답이 없을 때 다시 핸드셰이크한다. */
		tlog(t, "[net] cannot watch for network changes: %lu", err);
		CloseHandle(t->net_event);
		t->net_event = NULL;
		t->net_notify = NULL;
	}
}

static void net_watch_stop(tunnel_t *t)
{
	/* 알림 콜백이 끝날 때까지 기다린 뒤 돌아온다. 그 뒤에 이벤트를 닫아야 한다. */
	if (t->net_notify) {
		CancelMibChangeNotify2(t->net_notify);
		t->net_notify = NULL;
	}
	if (t->net_event) {
		CloseHandle(t->net_event);
		t->net_event = NULL;
	}
}

/* 이벤트 루프가 돌 때마다 부른다. 바뀐 뒤 조용해졌으면 keepalive 를 보내 보고, 그 답을
 * 기다리다 넘치면 net_lost 를 세운다. */
static void net_tick(tunnel_t *t, uint64_t now)
{
	session_t *session = &t->session;

	if (t->net_changed_ms && now - t->net_changed_ms >= NET_SETTLE_MSEC) {
		t->net_changed_ms = 0;
		/* 절전에서 깨어난 직후의 재핸드셰이크는 네트워크가 붙기 전이라 대개 실패한다.
		 * 그 뒤에 네트워크가 생겼으면 30초를 마저 기다리지 않고 바로 다시 해 본다. */
		if (t->hs_failed) {
			tlog(t, "[net] the network changed while reconnecting, trying now");
			t->net_lost = 1;
		}
		else if (!session->denied) {
			tlog(t, "[net] the network changed, checking the session");
			send_keepalive(t);
			t->net_probe_ms = now;
		}
	}

	if (t->net_probe_ms) {
		if (session->last_rx_ms >= t->net_probe_ms) {
			tlog(t, "[net] the session carried over to the new network");
			t->net_probe_ms = 0;
		}
		else if (now - t->net_probe_ms > NET_PROBE_MSEC) {
			t->net_probe_ms = 0;
			t->net_lost = 1;
		}
	}
}

/* DISCONNECT: 이 세션을 끝낸다고 서버에 알린다 (proto.h). 한 번 보내고 답을 기다리지
 * 않는다 — 잃어버려도 서버는 만료(60초)로 정리한다. */
static void send_disconnect(tunnel_t *t, uint8_t reason)
{
	session_t *session = &t->session;
	uint8_t packet[PKT_OVERHEAD + 1];
	uint8_t plain[PKT_HDR_LEN + 1];
	tunnel_packet_t pkt;
	uint64_t counter = session->secure.tx_counter;
	int n;

	if (session->idx == 0 || session->denied) {
		return;
	}

	packet[PKT_HDR_LEN] = reason;
	plain[PKT_HDR_LEN] = reason;
	n = secure_seal(&session->secure, MSG_TYPE_DISCONNECT, session->idx, packet, sizeof(packet), 1);
	if (n < 0) {
		return;
	}
	memcpy(plain, packet, PKT_HDR_LEN);

	udp_send(t, packet, n);
	tlog(t, "[HS] session closed");

	pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_PASS);
	pkt.msg_type = MSG_TYPE_DISCONNECT;
	pkt.session_idx = session->idx;
	pkt.has_counter = 1;
	pkt.counter = counter;
	pkt.wire_len = (uint32_t)n;
	pkt_snap(&pkt, plain, sizeof(plain));
	pkt_emit(t, &pkt);
}

/* 포스처를 다시 읽어 마지막으로 보고한 값과 달라졌는지 본다. 달라졌으면 세션의
 * 값을 갱신하고 1 을 돌려줘 다음 keepalive 주기를 기다리지 않고 바로 보고하게 한다.
 *
 * 10초 주기만으로는 방화벽을 끈 뒤 최대 10초 동안 서버가 모른다. 읽는 것은
 * 수십 ms 로 싸므로 2초마다 읽고, 보내는 것은 값이 바뀌었을 때만 앞당긴다. */
static int posture_changed(tunnel_t *t, uint64_t now)
{
	session_t *session = &t->session;
	posture_report_t report;

	if (now - session->last_posture_ms < POSTURE_POLL_MSEC) {
		return 0;
	}
	session->last_posture_ms = now;

	posture_report_now(&report);
	if (memcmp(&report, &session->posture, sizeof(report)) == 0) {
		return 0;
	}

	tlog(t, "[posture] changed: build=%u firewall=%u antivirus=%u disk=%u",
			report.os_build, report.firewall, report.antivirus, report.disk);
	session->posture = report;

	return 1;
}

/* ---- 사용자 로그인 --------------------------------------------------------- */
void tunnel_login_init(tunnel_login_t *l)
{
	memset(l, 0, sizeof(*l));
	InitializeSRWLock(&l->lock);
}

int tunnel_login_set(tunnel_login_t *l, const char *token, size_t len)
{
	if (len > sizeof(l->token)) {
		return -1;
	}

	AcquireSRWLockExclusive(&l->lock);
	SecureZeroMemory(l->token, sizeof(l->token));
	if (len > 0) {
		memcpy(l->token, token, len);
	}
	l->len = (uint32_t)len;
	l->gen++;
	ReleaseSRWLockExclusive(&l->lock);

	return 0;
}

static int b64url_value(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '-') return 62;
	if (c == '_') return 63;
	return -1;
}

/* 토큰(JWT)의 exp. 서버가 OK 와 함께 돌려주는 expires 와 맞춰, 그 답이 지금 들고 있는 토큰에
 * 대한 것인지 가린다. 서명은 보지 않는다 (서버가 본다). 읽지 못하면 -1. */
static int64_t token_exp(const char *tok, uint32_t len)
{
	uint8_t payload[LOGIN_TOKEN_MAX];
	json_tok_t jt[512];
	const char *seg;
	const char *end;
	uint32_t acc = 0;
	int64_t exp;
	size_t o = 0;
	int bits = 0;
	int i;

	seg = memchr(tok, '.', len);
	if (!seg) {
		return -1;
	}
	seg++;
	end = memchr(seg, '.', len - (uint32_t)(seg - tok));
	if (!end) {
		return -1;
	}

	for (; seg < end; seg++) {
		const int v = b64url_value(*seg);

		if (v < 0) {
			return -1;
		}
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= sizeof(payload)) {
				return -1;
			}
			payload[o++] = (uint8_t)(acc >> bits);
		}
	}

	if (json_parse((const char *)payload, o, jt, (int)(sizeof(jt) / sizeof(jt[0]))) <= 0 ||
			jt[0].type != JSON_OBJECT) {
		return -1;
	}
	i = json_get((const char *)payload, jt, 0, "exp");
	if (i < 0 || json_int64((const char *)payload, jt, i, &exp) < 0) {
		return -1;
	}

	return exp;
}

/* 새 세션이 열렸다. 서버의 새 세션에는 사용자가 붙어 있지 않으므로 토큰이 있으면 다시 보낸다. */
static void login_new_session(tunnel_t *t)
{
	t->login_due = t->login_has;
	t->login_sent = 0;
	t->last_login_ms = 0;
}

/* LOGIN (C -> S): 세션 패킷. 암호문 = 토큰.
 *
 * 토큰이 바뀌면 바로 보내고, 답이 없으면 LOGIN_RETRY_MSEC 마다 다시 보낸다. 서버는 같은
 * 토큰에 같은 답을 하므로 다시 보내도 된다.
 *
 * 프로토콜에 로그아웃 메시지는 없다. 서버에 붙은 사용자를 떼려면 사용자가 없는 새 세션을
 * 연다 (logout). 기다리면 토큰이 끝나며 떨어지지만, 그때까지 다음 사람이 앞사람의 권한으로
 * 쓰게 된다. */
static void login_tick(tunnel_t *t, uint64_t now)
{
	tunnel_login_t *l = t->cfg->login;
	session_t *session = &t->session;
	uint8_t packet[PKT_OVERHEAD + LOGIN_TOKEN_MAX];
	tunnel_packet_t pkt;
	uint64_t counter;
	uint32_t len = 0;
	int n;

	if (!l) {
		return;
	}

	AcquireSRWLockShared(&l->lock);
	if (l->gen != t->login_gen) {
		t->login_gen = l->gen;
		t->login_has = l->len != 0;
		t->login_due = t->login_has;
		t->last_login_ms = 0;
		t->login_exp = t->login_has ? token_exp(l->token, l->len) : -1;
		if (!t->login_has && t->login_sent) {
			t->logout = 1;
		}
	}
	if (t->login_due && !session->denied && now - t->last_login_ms >= LOGIN_RETRY_MSEC) {
		len = l->len;
		memcpy(packet + PKT_HDR_LEN, l->token, len);
	}
	ReleaseSRWLockShared(&l->lock);

	if (len == 0) {
		return;
	}

	counter = session->secure.tx_counter;
	n = secure_seal(&session->secure, MSG_TYPE_LOGIN, session->idx, packet, sizeof(packet), len);
	if (n < 0) {
		tlog(t, "[login] seal failed");
		SecureZeroMemory(packet, sizeof(packet));
		return;
	}

	udp_send(t, packet, n);
	t->last_login_ms = now;
	t->login_sent = 1;
	tlog(t, "[login] token sent (%u bytes)", len);

	/* 화면에는 헤더만 올린다. 토큰은 가진 사람이 곧 그 사용자라 진단 창의 덤프에도 남기지
	 * 않는다. */
	pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_PASS);
	pkt.msg_type = MSG_TYPE_LOGIN;
	pkt.session_idx = session->idx;
	pkt.has_counter = 1;
	pkt.counter = counter;
	pkt.wire_len = (uint32_t)n;
	pkt_snap(&pkt, packet, PKT_HDR_LEN);
	pkt_emit(t, &pkt);

	SecureZeroMemory(packet, sizeof(packet));
}

/* LOGIN (S -> C): status(1) | expires(8, 빅엔디언) | 사용자 이름 */
static void login_response(tunnel_t *t, const uint8_t *body, int n)
{
	char name[LOGIN_USER_MAX + 1];
	uint64_t expires = 0;
	int nl;
	int i;

	if (n < LOGIN_RES_HEAD_LEN) {
		tlog(t, "[login] short response (%d bytes)", n);
		return;
	}

	for (i = 1; i < LOGIN_RES_HEAD_LEN; i++) {
		expires = (expires << 8) | body[i];
	}
	nl = n - LOGIN_RES_HEAD_LEN;
	if (nl > LOGIN_USER_MAX) {
		nl = LOGIN_USER_MAX;
	}
	memcpy(name, body + LOGIN_RES_HEAD_LEN, (size_t)nl);
	name[nl] = '\0';

	/* 늦게 온 답을 지금 토큰의 답으로 읽지 않는다. 토큰을 갈아 끼운 직후에 새 토큰의 LOGIN 이
	 * 사라지고 옛 토큰의 답이 오면, 새 토큰을 다시 보내지 않게 되고 서버는 옛 토큰의 exp 에
	 * 사용자를 떼어 버린다 (서버는 그것을 알리지 않는다). OK 의 expires 는 그 토큰의 exp 이므로
	 * 그것으로 가린다. 로그아웃한 뒤의 답은 모두 버린다. */
	if (!t->login_has) {
		tlog(t, "[login] reply after logout, ignored");
		return;
	}
	if (body[0] == LOGIN_OK && t->login_exp >= 0 && (int64_t)expires != t->login_exp) {
		tlog(t, "[login] reply for an earlier token, ignored");
		return;
	}

	t->login_due = 0;

	if (body[0] == LOGIN_OK) {
		tlog(t, "[login] logged in as %s", name);
	}
	else {
		tlog(t, "[login] rejected: %s", login_status_name(body[0]));
		name[0] = '\0';
	}

	if (t->cfg->on_login) {
		t->cfg->on_login(t->cfg->ctx, body[0], (int64_t)expires, name);
	}
}

/* TUN -> UDP. Wintun 링버퍼에 쌓인 패킷을 모두 비운다. */
static int pump_tun(tunnel_t *t)
{
	session_t *session = &t->session;
	uint8_t packet[BUF_SIZE];
	tunnel_packet_t pkt;
	uint64_t counter;
	BYTE *ip;
	DWORD n;
	DWORD err;
	int wire;

	for (;;) {
		ip = WintunReceivePacket(t->tun, &n);
		if (!ip) {
			err = GetLastError();
			if (err == ERROR_NO_MORE_ITEMS) {
				return 0;
			}
			tlog(t, "WintunReceivePacket failed: %lu", err);
			return -1;
		}

		if (n < IP_MIN_HDR || IP_VERSION(ip) != 4) {
			if (pkt_log_text(t)) {
				tlog(t, "[skip] non-IPv4 (ver=%d, %lu bytes)", IP_VERSION(ip), n);
			}
			pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_DROP_NON_IPV4);
			pkt.wire_len = n;
			pkt_snap(&pkt, ip, n);
			pkt_emit(t, &pkt);
		}
		else if (n > sizeof(packet) - PKT_OVERHEAD) {
			if (pkt_log_text(t)) {
				tlog(t, "[skip] too long (%lu bytes)", n);
			}
			pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_DROP_TOO_LONG);
			pkt.wire_len = n;
			pkt_inner(&pkt, ip, n);
			pkt_snap(&pkt, ip, n);
			pkt_emit(t, &pkt);
		}
		else if (!deliverable_dst(t, ip)) {
			if (pkt_log_text(t)) {
				tlog(t, "[skip] non-unicast dst (%lu bytes, proto=%d)", n, ip[IP_PROTO_OFF]);
			}
			pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_DROP_NON_UNICAST);
			pkt.wire_len = n;
			pkt_inner(&pkt, ip, n);
			pkt_snap(&pkt, ip, n);
			pkt_emit(t, &pkt);
		}
		else if (session->denied) {
			/* 서버는 이 세션을 이미 내렸으므로 보내도 버려진다. 여기서 막고 이유를
			 * 올려야 사용자가 "왜 안 통하는지"를 패킷 목록에서 볼 수 있다. */
			if (pkt_log_text(t)) {
				tlog(t, "[skip] access denied (%lu bytes, proto=%d)", n, ip[IP_PROTO_OFF]);
			}
			pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_DROP_DENIED);
			pkt.wire_len = n;
			pkt_inner(&pkt, ip, n);
			pkt_snap(&pkt, ip, n);
			pkt_emit(t, &pkt);
		}
		else {
			if (pkt_log_text(t)) {
				tlog(t, "[tun->udp] %lu bytes, proto=%d", n, ip[IP_PROTO_OFF]);
			}

			counter = session->secure.tx_counter;

			/* 패킷이 Wintun 링버퍼 안에 있어 Linux처럼 헤드룸을 둘 수 없으므로 한 번
			 * 복사한다. 암호화는 복사한 자리에서 한다. */
			memcpy(packet + PKT_HDR_LEN, ip, n);

			wire = secure_seal(&session->secure, MSG_TYPE_DATA, session->idx,
					packet, sizeof(packet), n);
			if (wire < 0) {
				tlog(t, "[skip] seal failed (%lu bytes)", n);
				pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_DROP_IO_ERROR);
				pkt.wire_len = n;
				pkt_inner(&pkt, ip, n);
				pkt_snap(&pkt, ip, n);
				pkt_emit(t, &pkt);
			}
			else {
				udp_send(t, packet, wire);

				/* 화면에는 감싸기 전의 모습을 올린다: 우리 헤더 뒤에 원래의 패킷. */
				pkt_init(t, &pkt, TUNNEL_DIR_TX, TUNNEL_PASS);
				pkt.msg_type = MSG_TYPE_DATA;
				pkt.session_idx = session->idx;
				pkt.has_counter = 1;
				pkt.counter = counter;
				pkt.wire_len = (uint32_t)wire;
				pkt_inner(&pkt, ip, n);
				pkt_snap_plain(&pkt, packet, ip, n);
				pkt_emit(t, &pkt);
			}
		}

		WintunReleaseReceivePacket(t->tun, ip);
	}
}

/* 서버의 keepalive 응답에 실려 온 터널 설정을 지금 것과 비교한다.
 *
 * 관리자가 ACL 을 고쳐 이 기기가 갈 수 있는 대역이 바뀌면 여기서 경로가 따라 바뀐다.
 * 연결을 끊었다 다시 맺을 필요가 없다.
 *
 * 터널 주소가 바뀐 경우만은 그 자리에서 고치지 않는다. 서버의 세션은 예전 주소로 등록돼
 * 있어서, 어댑터만 새 주소로 바꾸면 내가 보내는 패킷이 "세션의 주소가 아닌 출발지"로
 * 버려진다. 다시 핸드셰이크해서 서버가 새 주소로 세션을 열게 한다. */
static void netcfg_refresh(tunnel_t *t, const uint8_t *body, int len, tunnel_packet_t *pkt)
{
	net_config_t cfg;

	if (net_config_decode(body, (size_t)len, &cfg) < 0 || !netcfg_usable(&cfg)) {
		tlog(t, "[cfg] unusable tunnel configuration in keepalive, kept the current one");
		return;
	}

	pkt_netcfg(pkt, &cfg);

	if (net_config_equal(&cfg, &t->applied)) {
		return;
	}

	if (cfg.tun_ip != t->applied.tun_ip || cfg.prefix_len != t->applied.prefix_len) {
		if (!t->readdress) {
			tlog(t, "[cfg] the server assigned a different tunnel address");
		}
		t->readdress = 1;
		return;
	}

	t->want = cfg;
	netcfg_apply(t);
}

/* UDP -> TUN. 소켓 수신 큐를 모두 비운다. */
static int pump_udp(tunnel_t *t)
{
	session_t *session = &t->session;
	uint8_t packet[BUF_SIZE];
	msg_header_t msg_header;
	tunnel_packet_t pkt;
	struct sockaddr_in from;
	uint64_t counter;
	uint8_t *ip;
	BYTE *out;
	int wire;	/* 수신한 UDP 페이로드 길이 */
	int n;		/* 푼 뒤의 평문 길이 */

	while ((wire = udp_recv(t, packet, (int)sizeof(packet), &from)) >= 0) {
		/* 검증 단계마다 verdict만 바꿔 같은 이벤트를 내보낸다.
		 * 폐기된 패킷도 올려야 UI가 "왜 안 통했는지"를 집계할 수 있다. */
		pkt_init(t, &pkt, TUNNEL_DIR_RX, TUNNEL_PASS);
		pkt.wire_len = (uint32_t)wire;
		pkt_snap(&pkt, packet, (uint32_t)wire);

		if (!from_server(session, &from)) {
			tlog(t, "[drop] not from server");
			pkt.verdict = TUNNEL_DROP_NOT_SERVER;
			pkt_emit(t, &pkt);
			continue;
		}

		if (msg_decode(packet, (size_t)wire, &msg_header) < 0 ||
				msg_header.version != PROTOCOL_VERSION) {
			pkt.verdict = TUNNEL_DROP_BAD_HEADER;
			pkt_emit(t, &pkt);
			continue;
		}

		pkt.msg_type = msg_header.type;
		pkt.session_idx = msg_header.session_idx;

		if (msg_header.session_idx != session->idx) {
			tlog(t, "[drop] wrong session [%08x][%08x]", msg_header.session_idx, session->idx);
			pkt.verdict = TUNNEL_DROP_WRONG_SESSION;
			pkt_emit(t, &pkt);
			continue;
		}

		/* 출발지 주소와 세션 번호는 위조할 수 있다. 여기까지 온 패킷이 정말 서버가 이
		 * 세션에 보낸 것인지는 tag 가 말해 준다. 그 전에는 내용을 믿지 않고, 세션의
		 * 상태도 바꾸지 않는다 — "서버가 살아 있다"는 표시(last_rx_ms)도 그 뒤에 한다.
		 * 순서가 반대면 위조 패킷이 죽은 서버를 살아 있는 것처럼 보이게 한다. */
		n = secure_open(&session->secure, packet, (size_t)wire, &counter);
		if (n < 0) {
			tlog(t, "[drop] %s", n == SECURE_REPLAY ? "counter already seen" : "tag does not match");
			pkt.verdict = (uint8_t)(n == SECURE_REPLAY ? TUNNEL_DROP_REPLAY : TUNNEL_DROP_BAD_TAG);
			pkt_emit(t, &pkt);
			continue;
		}

		session->last_rx_ms = GetTickCount64();

		/* 풀린 모습으로 다시 떠 둔다. */
		pkt.has_counter = 1;
		pkt.counter = counter;
		pkt_snap(&pkt, packet, (uint32_t)PKT_HDR_LEN + (uint32_t)n);

		ip = packet + PKT_HDR_LEN;

		switch (msg_header.type) {
			case MSG_TYPE_KEEPALIVE:
				/* 세션이 살아 있다는 증거라 유휴 시나리오에서 확인할 수 있게 로그를 남긴다. */
				if (pkt_log_text(t)) {
					tlog(t, "[keepalive] recv");
				}
				netcfg_refresh(t, ip, n, &pkt);
				pkt_emit(t, &pkt);
				continue;
			case MSG_TYPE_DENY:
				/* 세션 중의 거절. 방금 보낸 keepalive 의 포스처가 정책에 못 미쳤거나
				 * 서버 쪽 정책이 바뀌었다. 터널은 닫지 않는다 — 어댑터를 없애면 사용자가
				 * 방화벽을 다시 켰을 때 스스로 돌아올 수 없다. */
				if (n < 1) {
					pkt.verdict = TUNNEL_DROP_BAD_HEADER;
					pkt_emit(t, &pkt);
					continue;
				}
				tlog(t, "[deny] %s", deny_reason_name(ip[0]));
				pkt.deny_reason = ip[0];
				session->denied = 1;
				set_state(t, TUNNEL_STATE_DENIED);
				pkt_emit(t, &pkt);
				continue;
			case MSG_TYPE_LOGIN:
				login_response(t, ip, n);
				pkt_emit(t, &pkt);
				continue;
			case MSG_TYPE_DISCONNECT:
				/* 서버가 끝나거나(다시 시작하는 중일 수 있다) 세션 키의 수명이 다했다.
				 * 다음 틱에 바로 다시 핸드셰이크한다. 거절과 달리 사용자가 고칠 것이 없다. */
				tlog(t, "[HS] server closed the session (%s), reconnecting",
						n < 1 ? "closed" : ip[0] == DISCONNECT_SERVER_SHUTDOWN ? "shutting down" :
						ip[0] == DISCONNECT_REKEY ? "new session key" : "closed");
				t->server_closed = 1;
				pkt_emit(t, &pkt);
				continue;
			case MSG_TYPE_DATA:
				break;
			default:
				tlog(t, "[drop] unknown type(%d bytes)", wire);
				pkt.verdict = TUNNEL_DROP_UNKNOWN_TYPE;
				pkt_emit(t, &pkt);
				continue;
		}

		if (n < IP_MIN_HDR || IP_VERSION(ip) != 4) {
			tlog(t, "[drop] udp: not IPv4 (%d bytes)", n);
			pkt.verdict = TUNNEL_DROP_NON_IPV4;
			pkt_emit(t, &pkt);
			continue;
		}

		pkt_inner(&pkt, ip, (uint32_t)n);

		if (pkt_log_text(t)) {
			tlog(t, "[udp->tun] %d bytes, proto=%d", n, ip[IP_PROTO_OFF]);
		}

		out = WintunAllocateSendPacket(t->tun, (DWORD)n);
		if (!out) {
			tlog(t, "WintunAllocateSendPacket failed: %lu", GetLastError());
			pkt.verdict = TUNNEL_DROP_IO_ERROR;
			pkt_emit(t, &pkt);
			continue;
		}

		memcpy(out, ip, (size_t)n);
		WintunSendPacket(t->tun, out);

		pkt_emit(t, &pkt);
	}

	return wire == RECV_ERROR ? -1 : 0;
}

/* ---- enrollment ---------------------------------------------------------- */
#define ENROLL_TRIES 3
#define ENROLL_TIMEOUT_MSEC 1500

/* 등록 코드로 서버에 이 기기를 올린다 (proto.h 의 "기기 등록").
 *
 * 코드에서 뽑은 임시 신원으로 평소의 핸드셰이크를 그대로 돈다. 그러면 코드를 아는
 * 서버인지가 확인되고(수락의 tag), 세션 키가 생긴다. 그 세션으로 이 기기가 만든 ID 와
 * 키를 보낸다. 어댑터는 만들지 않는다 — 등록용 세션으로는 터널을 쓸 수 없고, 그래서
 * 관리자 권한도 필요 없다. */
int tunnel_enroll(const tunnel_config_t *base, const char *code,
		const uint8_t id[DEVICE_ID_LEN], uint8_t key[AUTH_KEY_LEN],
		uint8_t server_pub[VPN_PUB_LEN_WIRE], HANDLE stop_event)
{
	tunnel_config_t cfg = *base;
	tunnel_t tunnel;
	tunnel_t *t = &tunnel;
	uint8_t packet[BUF_SIZE];
	uint8_t pub[VPN_PUB_LEN];
	crypt_ecdh_t *mine = NULL;
	msg_header_t h;
	WSADATA wsa;
	uint64_t deadline;
	int ret = TUNNEL_ENROLL_ERROR;
	int tries;
	int n;

	/* 패킷 이벤트는 올리지 않는다. 화면의 패킷 목록은 터널의 것이다. */
	cfg.on_packet = NULL;
	cfg.on_state = NULL;

	if (secure_enroll_identity(code, cfg.device_id, cfg.device_key) < 0) {
		return TUNNEL_ENROLL_BAD_CODE;
	}
	/* 아직 서버 공개키를 모른다. 이번만은 CHALLENGE 의 것으로 감싼다. */
	cfg.has_server_pub = 0;

	/* 이 기기의 고정 키 쌍 (proto.h 의 "기기 등록", v8). 비밀키는 기기 키를 뽑는 데 한 번 쓰고
	 * 버린다 — 저장하는 것은 그 결과뿐이라 DPAPI 에 두는 신원의 모양이 그대로다. */
	mine = crypt_ecdh_new(pub);
	if (mine == NULL) {
		crypt_wipe(&cfg, sizeof(cfg));
		return TUNNEL_ENROLL_ERROR;
	}

	memset(t, 0, sizeof(*t));
	t->cfg = &cfg;
	t->stop_event = stop_event;
	t->sock = INVALID_SOCKET;
	t->t0_ms = GetTickCount64();
	t->session.server.sin_family = AF_INET;
	t->session.server.sin_addr = cfg.server_ip;
	t->session.server.sin_port = htons(cfg.server_port);

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		crypt_ecdh_free(mine);
		crypt_wipe(&cfg, sizeof(cfg));
		return TUNNEL_ENROLL_ERROR;
	}

	if (socket_open(t) < 0) {
		goto out;
	}

	switch (do_handshake(t)) {
	case HS_OK:
		break;
	case HS_DENIED:
		/* 서버가 그 코드를 모른다: 잘못 적었거나, 만료됐거나, 이미 쓰였다. */
		ret = TUNNEL_ENROLL_REJECTED;
		goto out;
	default:
		ret = TUNNEL_ENROLL_NO_RESPONSE;
		goto out;
	}

	ret = TUNNEL_ENROLL_NO_RESPONSE;

	for (tries = 1; tries <= ENROLL_TRIES; tries++) {
		/* 다시 보낼 때마다 새로 감싼다. counter 가 달라져야 서버가 재전송으로 버리지
		 * 않는다. 내용이 같으므로 서버는 같은 답을 한다. */
		memcpy(packet + PKT_HDR_LEN, id, DEVICE_ID_LEN);
		memcpy(packet + PKT_HDR_LEN + DEVICE_ID_LEN, pub, VPN_PUB_LEN);
		n = secure_seal(&t->session.secure, MSG_TYPE_ENROLL, t->session.idx,
				packet, sizeof(packet), ENROLL_PAYLOAD_LEN);
		if (n < 0) {
			ret = TUNNEL_ENROLL_ERROR;
			goto out;
		}
		udp_send(t, packet, n);
		tlog(t, "[enroll] sent %d/%d", tries, ENROLL_TRIES);

		deadline = GetTickCount64() + ENROLL_TIMEOUT_MSEC;
		for (;;) {
			n = hs_recv(t, deadline, packet, (int)sizeof(packet), &h);
			if (n == HS_FAIL) {
				ret = TUNNEL_ENROLL_ERROR;
				goto out;
			}
			if (n == 0) {
				break;
			}
			if (h.type != MSG_TYPE_ENROLL || h.session_idx != t->session.idx) {
				continue;
			}

			/* 세션 키로 열려야 서버의 답이다. */
			n = secure_open(&t->session.secure, packet, (size_t)n, NULL);
			if (n < (int)ENROLL_REPLY_LEN) {
				continue;
			}

			switch (packet[PKT_HDR_LEN]) {
			case ENROLL_OK:		ret = TUNNEL_ENROLL_OK; break;
			case ENROLL_GONE:	ret = TUNNEL_ENROLL_REJECTED; break;
			case ENROLL_CONFLICT:	ret = TUNNEL_ENROLL_CONFLICT; break;
			default:		ret = TUNNEL_ENROLL_SERVER_FAILED; break;
			}
			tlog(t, "[enroll] server answered %u", packet[PKT_HDR_LEN]);

			/* 서버의 공개키는 코드를 아는 서버만 열 수 있는 이 세션으로 왔다. 그것과 이 기기의
			 * 비밀키로 기기 키를 뽑는다. 서버는 자기 비밀키와 이 기기의 공개키로 같은 값을 뽑는다. */
			if (ret == TUNNEL_ENROLL_OK &&
					secure_static_key(mine, packet + PKT_HDR_LEN + 1, pub, packet + PKT_HDR_LEN + 1, key) < 0) {
				ret = TUNNEL_ENROLL_ERROR;
			}
			if (ret == TUNNEL_ENROLL_OK) {
				memcpy(server_pub, packet + PKT_HDR_LEN + 1, VPN_PUB_LEN_WIRE);
			}
			goto out;
		}
	}

out:
	secure_session_close(&t->session.secure);
	if (t->sock != INVALID_SOCKET) {
		closesocket(t->sock);
	}
	if (t->sock_event) {
		CloseHandle(t->sock_event);
	}
	WSACleanup();

	/* 코드에서 뽑은 키가 든 설정의 사본과 이 기기의 비밀키. */
	crypt_ecdh_free(mine);
	crypt_wipe(packet, sizeof(packet));
	crypt_wipe(&cfg, sizeof(cfg));

	return ret;
}

/* ---- entry --------------------------------------------------------------- */
int tunnel_run(const tunnel_config_t *cfg, HANDLE stop_event)
{
	tunnel_t tunnel;
	tunnel_t *t = &tunnel;
	session_t *session = &t->session;
	HANDLE waits[4];
	DWORD nwaits = 3;
	int hs;
	WSADATA wsa;
	char server_str[INET_ADDRSTRLEN];
	uint64_t now;
	DWORD err;
	DWORD w;
	int wsa_ready = 0;
	int ret = 1;

	memset(t, 0, sizeof(*t));
	t->cfg = cfg;
	t->stop_event = stop_event;
	t->sock = INVALID_SOCKET;

	t->t0_ms = GetTickCount64();

	session->server.sin_family = AF_INET;
	session->server.sin_addr = cfg->server_ip;
	session->server.sin_port = htons(cfg->server_port);
	inet_ntop(AF_INET, &cfg->server_ip, server_str, sizeof(server_str));

	set_state(t, TUNNEL_STATE_CONNECTING);

	/* 지난번에 끝나지 못하고(서비스가 죽었다) 남은 이름 해석 규칙. */
	nrpt_clear(t);

	err = (DWORD)WSAStartup(MAKEWORD(2, 2), &wsa);
	if (err != 0) {
		tlog(t, "WSAStartup failed: %lu", err);
		goto out;
	}
	wsa_ready = 1;

	/* 서버가 받아 준 뒤에 어댑터를 만든다. 순서를 반대로 하면 서버에 닿지 못하거나
	 * 거절당하는 경우에도 PC 에 네트워크 어댑터와 터널 대역 경로가 잠깐 생겼다
	 * 사라진다. 접근이 허락되기 전에는 터널이 존재하지 않는 편이 맞다. */
	if (socket_open(t) < 0) {
		goto out;
	}

	tlog(t, "[%ls] tunneling to %s:%u", cfg->adapter_name, server_str, cfg->server_port);

	hs = do_handshake(t);
	if (hs == HS_FAIL && WaitForSingleObject(t->stop_event, 0) != WAIT_OBJECT_0) {
		tlog(t, "[HS] no answer over udp, trying tcp on the same port");
		if (transport_switch(t, 1) == 0) {
			hs = do_handshake(t);
		}
	}
	if (hs != HS_OK) {
		goto out;
	}

	t->wintun = wintun_load();
	if (!t->wintun) {
		tlog(t, "failed to load wintun.dll: %lu", GetLastError());
		goto out;
	}

	t->adapter = WintunCreateAdapter(cfg->adapter_name, L"ztgate", &ADAPTER_GUID);
	if (!t->adapter) {
		err = GetLastError();
		tlog(t, "WintunCreateAdapter failed: %lu%s", err,
				err == ERROR_ACCESS_DENIED ? " (run as Administrator)" : "");
		goto out;
	}

	/* 주소, MTU, 경로는 서버가 수락에 실어 준 것(t->want)을 넣는다. */
	WintunGetAdapterLUID(t->adapter, &t->luid);
	if (netcfg_apply(t) < 0) {
		goto out;
	}

	t->tun = WintunStartSession(t->adapter, TUN_RING_CAPACITY);
	if (!t->tun) {
		tlog(t, "WintunStartSession failed: %lu", GetLastError());
		goto out;
	}
	t->tun_event = WintunGetReadWaitEvent(t->tun);

	tlog(t, "[%ls] tun device ready", cfg->adapter_name);

	session->last_rx_ms = GetTickCount64();
	login_new_session(t);
	set_state(t, TUNNEL_STATE_CONNECTED);

	waits[0] = t->stop_event;
	waits[1] = t->tun_event;
	waits[2] = t->sock_event;

	net_watch_start(t);
	if (t->net_event) {
		waits[nwaits++] = t->net_event;
	}

	for (;;) {
		/* Linux의 epoll_wait(…, 1000)에 해당. 어느 쪽이 깨웠는지와 관계없이
		 * 아래에서 TUN과 소켓을 둘 다 비우므로 한쪽이 굶지 않는다. */
		w = WaitForMultipleObjects(nwaits, waits, FALSE, LOOP_TICK_MSEC);
		if (w == WAIT_OBJECT_0) {
			/* 사용자가 끊었거나 서비스를 멈춘다. 서버가 이 세션을 만료까지 붙잡아 두지
			 * 않게 알린다. */
			send_disconnect(t, DISCONNECT_CLIENT_EXIT);
			break;
		}
		if (w == WAIT_FAILED) {
			tlog(t, "WaitForMultipleObjects failed: %lu", GetLastError());
			goto out;
		}

		now = GetTickCount64();

		if (nwaits == 4 && w == WAIT_OBJECT_0 + 3) {
			t->net_changed_ms = now;
		}
		net_tick(t, now);

		/* 다시 핸드셰이크하는 경우
		 *  - 서버가 30초 동안 조용하다 (재시작했거나 세션이 만료됐다). 절전에서 깨어나면
		 *    시계(GetTickCount64)는 잠든 시간만큼 가 있어 바로 여기에 걸린다.
		 *  - 서버가 DISCONNECT 로 끝냈다 (다시 시작하는 중, 키 교체).
		 *  - 네트워크가 바뀐 뒤 보낸 keepalive 에 답이 없다 (net_tick).
		 *  - 서버가 다른 터널 주소를 주었다, 로그아웃했다.
		 *  - 거절된 상태에서 포스처가 바뀌었다. 사용자가 방화벽을 다시 켠 것일 수
		 *    있으니 30초를 기다리지 않고 바로 다시 물어본다.
		 * 거절된 상태에서도 첫 번째 조건이 그대로 걸려, 포스처가 그대로여도 30초마다
		 * 다시 물어본다. 서버 쪽 정책이 풀렸을 수 있다. */
		if (now - session->last_rx_ms > SERVER_TIMEOUT_MSEC || t->readdress || t->logout ||
				t->server_closed || t->net_lost || t->tcp_lost || (session->denied && posture_changed(t, now))) {
			if (session->denied) {
				tlog(t, "[HS] retry after deny");
			}
			else if (t->server_closed) {
				set_state(t, TUNNEL_STATE_RECONNECTING);
			}
			else if (t->net_lost) {
				tlog(t, "[HS] no answer on the new network, re-handshake");
				set_state(t, TUNNEL_STATE_RECONNECTING);
			}
			else if (t->logout) {
				/* 연결은 그대로인 채 사용자만 바뀌는 것이라 재연결 중으로 보이지 않게 한다. */
				tlog(t, "[login] logged out, opening a session without the user");
			}
			else if (t->readdress) {
				tlog(t, "[HS] re-handshake for the new tunnel address");
				set_state(t, TUNNEL_STATE_RECONNECTING);
			}
			else {
				tlog(t, "[HS] no rx from server for %ds, re-handshake", SERVER_TIMEOUT_SEC);
				set_state(t, TUNNEL_STATE_RECONNECTING);
			}

			/* 실패하면 여기서 다시 묻지 않는다. 세션이 살아 있으면 다음 keepalive 응답이
			 * 주소가 다르다는 것을 다시 알려 준다. 그대로 두면 매 틱마다 핸드셰이크한다. */
			t->readdress = 0;
			t->logout = 0;
			t->server_closed = 0;
			t->net_lost = 0;
			t->net_probe_ms = 0;
			if (t->tcp_lost && transport_switch(t, 1) < 0) {
				/* 다시 열지 못했다. 다음에는 UDP 로 해 본다 (그 사이 네트워크가 바뀌었을 수 있다). */
				transport_switch(t, 0);
			}

			switch (do_handshake(t)) {
			case HS_OK:
				/* 다시 받은 설정을 어댑터에 맞춘다. 주소가 바뀌었으면 여기서 바뀐다. */
				if (netcfg_apply(t) < 0) {
					goto out;
				}
				session->denied = 0;
				t->hs_failed = 0;
				login_new_session(t);
				set_state(t, TUNNEL_STATE_CONNECTED);
				break;
			case HS_DENIED:
				session->denied = 1;
				t->hs_failed = 0;
				set_state(t, TUNNEL_STATE_DENIED);
				break;
			default:
				t->hs_failed = 1;
				/* 지금 전송으로 답이 없다. 다음에는 다른 쪽(UDP <-> TCP)으로 해 본다. */
				transport_switch(t, !t->tcp);
				tlog(t, "[HS] failed re-handshake[%s][%u], retry in %ds",
						server_str, cfg->server_port, SERVER_TIMEOUT_SEC);
				break;
			}
			now = GetTickCount64();
			session->last_rx_ms = now;
		}

		/* keepalive 는 이제 세 가지를 맡는다.
		 *  - NAT 매핑 유지
		 *  - 생존 확인: 데이터 패킷은 서버가 버릴 수 있어 응답을 보장하지 못하지만
		 *    keepalive 는 서버가 반드시 되돌려준다.
		 *  - 포스처 재보고
		 * 앞의 둘만 있을 때는 "10초 동안 보낸 것 / 받은 것이 없을 때"만 보내면 됐다.
		 * 포스처는 트래픽이 흐르는 중에도 보고돼야 하므로 유휴 여부와 관계없이 10초마다
		 * 보낸다. 그러면 앞의 두 조건은 저절로 채워진다.
		 *
		 * 거절된 상태에서는 보내지 않는다. 서버에 세션이 없어 받아 줄 곳이 없다. */
		if (!session->denied && (posture_changed(t, now) ||
				now - session->last_ka_ms > KEEPALIVE_INTERVAL_MSEC)) {
			send_keepalive(t);
		}

		login_tick(t, now);

		if (pump_tun(t) < 0 || pump_udp(t) < 0) {
			goto out;
		}
	}
	ret = 0;

out:
	net_watch_stop(t);
	nrpt_clear(t);
	secure_session_close(&session->secure);
	if (t->sock != INVALID_SOCKET) {
		closesocket(t->sock);
	}
	if (t->sock_event) {
		CloseHandle(t->sock_event);
	}
	if (t->tun) {
		WintunEndSession(t->tun);
	}
	if (t->adapter) {
		WintunCloseAdapter(t->adapter);
	}
	if (t->wintun) {
		FreeLibrary(t->wintun);
	}
	if (wsa_ready) {
		WSACleanup();
	}

	set_state(t, TUNNEL_STATE_STOPPED);
	return ret;
}
