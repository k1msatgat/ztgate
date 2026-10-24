#ifndef TUNNEL_H
#define TUNNEL_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <wchar.h>
#include <stdint.h>

#include "proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNEL_ADAPTER_NAME_LEN 64

typedef enum tunnel_state {
	TUNNEL_STATE_STOPPED = 0,
	TUNNEL_STATE_CONNECTING,	/* 어댑터 생성 ~ 첫 핸드셰이크 */
	TUNNEL_STATE_CONNECTED,
	TUNNEL_STATE_RECONNECTING,	/* 서버 무응답으로 재핸드셰이크 중 */
	TUNNEL_STATE_DENIED		/* 세션 중 서버가 접근을 거절했다. 터널은 열려 있지만 통하지 않는다 */
} tunnel_state_t;

typedef enum tunnel_dir {
	TUNNEL_DIR_TX = 0,		/* TUN -> UDP (내가 보냄) */
	TUNNEL_DIR_RX			/* UDP -> TUN (내가 받음) */
} tunnel_dir_t;

/* 패킷을 어떻게 처리했는지. 폐기 이유를 그대로 올려 UI가 집계할 수 있게 한다. */
typedef enum tunnel_verdict {
	TUNNEL_PASS = 0,
	TUNNEL_DROP_NON_IPV4,		/* IPv6 등 */
	TUNNEL_DROP_NON_UNICAST,	/* 멀티캐스트 / 브로드캐스트 — 전달할 피어가 없다 */
	TUNNEL_DROP_TOO_LONG,
	TUNNEL_DROP_NOT_SERVER,		/* 출발지가 서버가 아니다 */
	TUNNEL_DROP_BAD_HEADER,		/* 길이 부족 / 버전 불일치 */
	TUNNEL_DROP_WRONG_SESSION,
	TUNNEL_DROP_UNKNOWN_TYPE,
	TUNNEL_DROP_IO_ERROR,		/* 검증은 통과했지만 전달 자체가 실패 */
	TUNNEL_DROP_DENIED,		/* 서버가 접근을 거절한 상태라 보내지 않았다 */
	TUNNEL_DROP_BAD_TAG,		/* tag 가 맞지 않는다. 서버가 이 세션에 보낸 것이 아니다 */
	TUNNEL_DROP_REPLAY,		/* 이미 받은 counter. 같은 패킷이 다시 왔다 */
	TUNNEL_VERDICT_COUNT		/* 항목 수. 집계 배열의 크기로 쓴다 */
} tunnel_verdict_t;

/* 상세창 hex 덤프용으로 와이어 앞부분만 떠 둔다 (16B 헤더 + inner 헤더가 보일 정도). */
#define TUNNEL_SNAP_LEN 64

/* 패킷 한 건의 디코드 결과.
 *
 * 포맷된 문자열이 아니라 필드 그대로 올리는 것이 핵심이다. tunnel.c 는 이미
 * 세션 idx, counter, inner src/dst 를 알고 있는데, 이를 문자열로 만들어 넘기면
 * UI 는 그 정보를 되찾을 수 없다. 와이어 포맷을 열로 펼치거나 헤더를 필드별로
 * 분해해 보여주려면 구조체로 올려야 한다. */
typedef struct tunnel_packet {
	uint64_t seq;			/* 1부터 증가 */
	uint64_t t_ms;			/* tunnel_run 시작 기준 경과 시간 */

	uint8_t dir;			/* tunnel_dir_t */
	uint8_t verdict;		/* tunnel_verdict_t */
	uint8_t msg_type;		/* MSG_TYPE_*, 헤더를 못 읽었으면 0 */
	uint8_t has_counter;		/* data_header 가 있었나 */

	uint32_t session_idx;
	uint64_t counter;

	uint32_t wire_len;		/* UDP 페이로드 길이 (우리 헤더 포함) */
	uint32_t inner_len;		/* inner IP 패킷 길이, 없으면 0 */

	struct in_addr inner_src;
	struct in_addr inner_dst;
	uint8_t has_inner;
	uint8_t proto;			/* inner IP protocol */

	uint8_t has_l4;
	uint8_t icmp_type;		/* proto == 1 */
	uint8_t icmp_code;
	uint16_t sport;			/* proto == 6 / 17 */
	uint16_t dport;

	/* 인증 / 포스처 메시지에서만 채워진다. 스냅샷의 바이트를 UI 가 다시 해석하게
	 * 두지 않고 여기서도 필드로 올린다 (와이어 배치를 아는 쪽은 코어 하나여야 한다). */
	uint8_t has_posture;		/* AUTH, 내가 보낸 KEEPALIVE */
	uint8_t deny_reason;		/* DENY 의 deny_reason_t, 아니면 0 */
	posture_report_t posture;

	/* 서버가 정해 준 터널 설정. 받아들인 RES_HANDSHAKE 와 서버의 KEEPALIVE 에서 채워진다.
	 * 경로 목록 전체는 싣지 않는다 (패킷마다 복사되는 구조체다). 개수만 올리고 내용은
	 * 로그에 남긴다. */
	uint8_t has_netcfg;
	uint8_t cfg_prefix_len;
	uint8_t cfg_routes;
	struct in_addr cfg_tun_ip;

	uint8_t snap[TUNNEL_SNAP_LEN];
	uint8_t snap_len;
} tunnel_packet_t;

/* 사용자 로그인 토큰을 터널에 건네는 자리.
 *
 * 토큰은 터널이 도는 중에 바뀐다 (사용자가 로그인하거나 로그아웃하고, 토큰이 끝나기 전에
 * GUI 가 새 것을 받아 온다). cfg 는 tunnel_run 이 시작할 때 받은 것을 끝까지 쓰므로, 바뀌는
 * 값은 cfg 가 가리키는 이 자리에 둔다. 쓰는 쪽은 tunnel_login_set 만 부르고, 터널은 루프를
 * 돌 때마다(1초) gen 이 바뀌었는지 본다. */
typedef struct tunnel_login {
	SRWLOCK lock;
	uint32_t gen;			/* 토큰이 바뀔 때마다 는다 */
	uint32_t len;			/* 0 이면 로그인하지 않은 상태 */
	char token[LOGIN_TOKEN_MAX];
} tunnel_login_t;

void tunnel_login_init(tunnel_login_t *l);

/* 토큰을 바꾼다. len 이 0 이면 로그아웃이다. 0 성공, -1 토큰이 패킷 하나에 들어가지 않는다. */
int tunnel_login_set(tunnel_login_t *l, const char *token, size_t len);

/* 콜백은 tunnel_run()을 호출한 스레드에서 불린다.
 * GUI에서는 여기서 컨트롤을 직접 건드리지 말고 PostMessage로 넘겨야 한다. */
/* 서버를 여럿 적으면(이중화) 첫 서버 말고 셋까지 더 둔다. 지금 서버가 UDP 로도 TCP 로도 답하지
 * 않으면 다음 서버로 넘어간다. 서버들은 같은 기기 목록과 서버 키를 쓴다고 본다. */
#define TUNNEL_ALT_SERVERS	3

/* 서버 주소. IPv4 또는 IPv6 (si_family). 포트는 server_port 로 따로 두고 소켓을 열 때 채운다. */
typedef SOCKADDR_INET tunnel_addr_t;

typedef struct tunnel_config {
	wchar_t adapter_name[TUNNEL_ADAPTER_NAME_LEN];
	tunnel_addr_t server_ip;
	uint16_t server_port;		/* host byte order */
	tunnel_addr_t alt_ips[TUNNEL_ALT_SERVERS];	/* 같은 포트의 다른 서버 */
	int n_alt;

	/* 기기 신원. 호출자가 device_load() 로 읽어 채운다. 포인터가 아니라 배열로 둬서
	 * cfg 를 구조체째 복사해도 그대로 따라온다. */
	uint8_t device_id[DEVICE_ID_LEN];
	uint8_t device_key[AUTH_KEY_LEN];
	/* 등록 때 받은 서버 공개키 (device_t). 있으면 CHALLENGE 의 공개키가 이것일 때만 답한다. */
	uint8_t server_pub[VPN_PUB_LEN_WIRE];
	int has_server_pub;
	int log_packets;		/* 0이 아니면 패킷마다 on_log 로 한 줄 */

	void (*on_log)(void *ctx, const char *line);
	void (*on_state)(void *ctx, tunnel_state_t state);

	/* 설정하면 패킷마다 디코드 결과가 올라온다. 이때 log_packets 기반의
	 * 패킷 텍스트 로그는 중복이므로 생략한다. */
	void (*on_packet)(void *ctx, const tunnel_packet_t *pkt);

	/* 사용자 로그인. NULL 이면 토큰을 보내지 않는다 (기기 신원만으로 연다). */
	tunnel_login_t *login;

	/* 서버가 LOGIN 에 답했다. status 는 login_status_t, expires 는 토큰의 exp (Unix time,
	 * 실패면 0), user 는 성공했을 때의 사용자 이름이고 실패면 "". */
	void (*on_login)(void *ctx, int status, int64_t expires, const char *user);

	/* 서버가 준 터널 설정을 어댑터에 맞췄다 (처음과 바뀔 때마다). 서비스가 터널이 끊긴 동안 막을
	 * 내부 대역을 여기서 배운다 (wfp.h). NULL 이면 부르지 않는다. */
	void (*on_config)(void *ctx, const net_config_t *cfg);

	void *ctx;
} tunnel_config_t;

/* 터널을 열고 stop_event가 signaled 될 때까지 블로킹으로 돈다.
 * stop_event는 manual-reset 이벤트여야 한다.
 * 정상 종료 0, 초기화/핸드셰이크 실패나 I/O 오류는 1. */
int tunnel_run(const tunnel_config_t *cfg, HANDLE stop_event);

/* 등록 코드로 서버에 기기를 올린 결과. */
typedef enum tunnel_enroll_result {
	TUNNEL_ENROLL_OK = 0,
	TUNNEL_ENROLL_BAD_CODE,		/* 코드의 글자 수나 글자가 맞지 않는다. 서버에 묻지 않았다 */
	TUNNEL_ENROLL_NO_RESPONSE,	/* 서버가 답하지 않는다 */
	TUNNEL_ENROLL_REJECTED,		/* 서버가 그 코드를 받지 않는다: 잘못 적었거나, 만료됐거나, 이미 쓰였다 */
	TUNNEL_ENROLL_CONFLICT,		/* 그 기기 ID 나 그 터널 주소가 이미 서버에 있다 */
	TUNNEL_ENROLL_SERVER_FAILED,	/* 서버가 받았지만 기기 목록에 적지 못했다 */
	TUNNEL_ENROLL_ERROR		/* 이쪽의 오류 (소켓, 암호 도구) 또는 중지 요청 */
} tunnel_enroll_result_t;

/* 등록 코드(code)로 서버에 이 기기의 id 를 올린다 (proto.h 의 "기기 등록", v8). 이번에 만든 고정
 * 키 쌍의 공개키를 보내고, 서버가 받아 주면 답에 실린 서버 공개키로 기기 키를 뽑아 key 에 적는다
 * (TUNNEL_ENROLL_OK 일 때만). tunnel_enroll_result_t 를 돌려준다.
 *
 * cfg 에서는 서버 주소 / 포트와 on_log 만 쓴다. 어댑터를 만들지 않으므로 관리자 권한이
 * 필요 없다. 응답을 기다리는 동안 블로킹한다 (길어야 십여 초). stop_event 는
 * manual-reset 이벤트여야 하고, signaled 되면 기다리던 것을 그만둔다.
 *
 * id 는 호출자가 device_generate() 로 만든 것이고, OK 를 받은 뒤에 key, server_pub 과 함께
 * device_save() 로 저장해야 한다. 순서가 반대면 서버가 받지 않았을 때 예전 신원만 잃는다.
 * server_pub 은 서버가 답에 실어 준 서버 공개키다 — 다음 핸드셰이크부터 고정한다.
 *
 * device_pub 이 있으면(TPM 에 만든 고정 키의 공개키, device_tpm_begin) 그것을 올리고 key 는 채우지
 * 않는다 — 부르는 쪽이 TPM 으로 뽑는다 (device_tpm_finish). NULL 이면 소프트웨어 키를 만들어 쓰고 버린다. */
int tunnel_enroll(const tunnel_config_t *cfg, const char *code,
		const uint8_t id[DEVICE_ID_LEN], uint8_t key[AUTH_KEY_LEN],
		uint8_t server_pub[VPN_PUB_LEN_WIRE], const uint8_t *device_pub, HANDLE stop_event);

/* 폐기 이유의 짧은 영문 이름.
 * 코어는 표시 문자열을 가지지 않는다 — 여기서 한국어를 돌려주면 char* 가 되어
 * UI 가 ANSI 코드페이지로 변환하면서 깨진다. 화면에 쓸 라벨은 UI 가 enum 을
 * 보고 와이드 문자열로 직접 고른다. 이 함수는 콘솔 로그용이다. */
const char *tunnel_verdict_name(int verdict);

/* 주소 하나: "203.0.113.10", "2001:db8::10", "[2001:db8::10]". 0 성공. */
static __inline int tunnel_parse_addr(const wchar_t *s, tunnel_addr_t *out)
{
	wchar_t host[INET6_ADDRSTRLEN + 2];
	size_t n = wcslen(s);

	memset(out, 0, sizeof(*out));
	if (n >= 2 && s[0] == L'[' && s[n - 1] == L']' && n - 2 < sizeof(host) / sizeof(host[0])) {
		wmemcpy(host, s + 1, n - 2);
		host[n - 2] = L'\0';
	}
	else if (n < sizeof(host) / sizeof(host[0])) {
		wcscpy_s(host, sizeof(host) / sizeof(host[0]), s);
	}
	else {
		return -1;
	}
	if (InetPtonW(AF_INET, host, &out->Ipv4.sin_addr) == 1) {
		out->si_family = AF_INET;
		return 0;
	}
	if (InetPtonW(AF_INET6, host, &out->Ipv6.sin6_addr) == 1) {
		out->si_family = AF_INET6;
		return 0;
	}
	return -1;
}

/* 로그에 쓸 주소 (포트 없이). out 은 INET6_ADDRSTRLEN 이상. */
static __inline const char *tunnel_addr_str(const tunnel_addr_t *a, char *out, size_t cap)
{
	if (!inet_ntop(a->si_family, a->si_family == AF_INET6 ? (const void *)&a->Ipv6.sin6_addr :
				(const void *)&a->Ipv4.sin_addr, out, cap)) {
		strcpy_s(out, cap, "?");
	}
	return out;
}

/* "10.0.0.10,10.0.0.11" 을 첫 서버와 나머지로 나눈다 (IPv6 도). 틀리면(주소가 아님, 넷보다 많음) -1. */
static __inline int tunnel_parse_servers(const wchar_t *list, tunnel_addr_t *first,
		tunnel_addr_t alt[TUNNEL_ALT_SERVERS], int *n_alt)
{
	wchar_t buf[256];
	wchar_t *tok, *ctx = NULL;
	int n = 0;

	if (wcslen(list) >= sizeof(buf) / sizeof(buf[0])) {
		return -1;
	}
	wcscpy_s(buf, sizeof(buf) / sizeof(buf[0]), list);
	for (tok = wcstok_s(buf, L", ", &ctx); tok != NULL; tok = wcstok_s(NULL, L", ", &ctx)) {
		tunnel_addr_t a;

		if (n > TUNNEL_ALT_SERVERS || tunnel_parse_addr(tok, &a) < 0) {
			return -1;
		}
		if (n == 0) {
			*first = a;
		}
		else {
			alt[n - 1] = a;
		}
		n++;
	}
	if (n == 0) {
		return -1;
	}
	*n_alt = n - 1;
	return 0;
}


#ifdef __cplusplus
}
#endif

#endif
