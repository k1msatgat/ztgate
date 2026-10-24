#ifndef PROTO_H
#define PROTO_H

/* 와이어 프로토콜 정의. Linux(client/server)와 Windows 클라이언트가 함께 쓰므로
 * OS 전용 헤더를 포함하지 않는다. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#define PROTO_STATIC_ASSERT static_assert
#else
#define PROTO_STATIC_ASSERT _Static_assert
#endif

#define PROTOCOL_VERSION 9 /* 서버와 클라이언트가 같은 값을 쓴다. 2: 기기 인증, 3: 세션 암호화, 4: 서버가 터널 설정을 내려 준다, 5: 사용자 로그인, 6: 이름을 ztgate 로 바꾸며 키 유도 / 거절 / 등록 코드의 라벨을 바꿈, 7: 터널 설정에 내부 DNS, 8: 등록이 기기 공개키를 올리고 서버 공개키를 받는다, 9: 핸드셰이크가 기기 ID 를 감싸 보낸다 */

#define TUN_MTU		1400
#define BUF_SIZE	2048
#define TUN_PROR	9000

#define IP_PROTO_OFF    9
#define IP_SRC_OFF     12
#define IP_DST_OFF     16
#define IP_ADDR_LEN     4
#define IP_MIN_HDR     20

#define L4_SPORT_OFF   0
#define L4_DPORT_OFF   2
#define L4_PORT_LEN    2

#define IP_VERSION(buf)  ((buf)[0] >> 4)
#define IP_IHL(buf)      (((buf)[0] & 0x0F) * 4)

#define PKT_HDR_LEN (sizeof(msg_header_t) + sizeof(data_header_t))

#define KEEPALIVE_INTERVAL_SEC 10
#define KEEPALIVE_INTERVAL_MSEC (KEEPALIVE_INTERVAL_SEC * 1000)
#define SESSION_TIMEOUT_SEC 60
#define SERVER_TIMEOUT_SEC 30

/* 기기 인증 + 포스처 보고 + 세션 암호화 (ZTNA).
 *
 * 핸드셰이크는 네 메시지다. 모두 msg_header(8B) 뒤에 아래 페이로드가 붙는다.
 *
 *   C -> S  REQ_HANDSHAKE  zero(80)
 *   S -> C  CHALLENGE      nonce(16) | server_pub(64)
 *   C -> S  AUTH           pub_c(64) | nonce(16) | sealed(device_id(16) | posture(8)) | tag(16) | mac(32)
 *   S -> C  RES_HANDSHAKE  pub_s(64) | 암호화된 net_config | tag(16)     헤더의 session_idx 가 세션 번호
 *        또는 DENY          reason(1) | mac(32)          헤더의 session_idx 는 0
 *
 * AUTH 의 mac 은 HMAC-SHA256(기기 키, 헤더부터 mac 앞까지 112B) 이다. 서버가 매번 새로
 * 뽑은 nonce 가 들어가므로 예전 AUTH 를 녹화해 다시 보내도 통과하지 못한다.
 *
 * 기기 ID 와 포스처는 평문으로 다니지 않는다 (v9). 평문 ID 는 그 기기가 어느 망에서 언제
 * 붙는지를, 평문 포스처는 그 PC 의 방화벽 / 백신 상태와 OS 빌드를 엿보는 누구에게나 알려
 * 준다. AUTH 는 둘을 서버 공개키로 감싸 싣는다:
 *
 *   k      = HMAC-SHA256(ECDH(pub_c 의 비밀키, server_pub), "ztgate v9 auth" | pub_c | server_pub)
 *   sealed = AES-256-GCM(k, nonce 0, aad = 헤더 | pub_c | nonce, device_id | posture)
 *
 * pub_c 는 세션 키를 뽑는 바로 그 일회용 키다. 서버는 자기 비밀키로 같은 k 를 얻어 ID 와
 * 포스처를 풀고, 그다음은 전과 같다 (기기 키로 mac 확인). mac 은 감싼 바이트를 덮는다. server_pub 은 CHALLENGE 가 알려 준다 — 서버
 * 키(-k)가 있으면 그 공개키, 없으면 서버가 뜰 때 만든 일회용 키의 것이다. 그 공개키는 확인되지
 * 않은 채 오므로 사이에 끼어 공개키를 바꿔 끼우는 쪽에게는 ID 가 보인다. 숨기는 상대는 엿보기만
 * 하는 쪽이다. 바꿔 끼워도 인증과 세션 키는 전과 같이 기기 키가 지킨다.
 *
 * REQ 에는 아무것도 없다. CHALLENGE 의 크기만큼 0 을 채우는 것은 출발지를 위조한 REQ 로
 * 남에게 더 큰 답을 쏟게 하지 못하게 하려는 것이다 (증폭). 서버는 REQ 에 상태를 남기지 않는다.
 * nonce 는 발급 시각(8, 마이크로초)과 그 시각 | 출발지 IP 에 서버만 아는 키로 붙인 mac(8)이다.
 * 서버는 AUTH 에서 그 mac 과 수명(NONCE_TTL_SEC)을 확인하고, 기기마다 마지막으로 받아들인 nonce
 * 의 시각을 기억해 그보다 늦게 발급된 것만 받는다 — 같은 AUTH 를 두 번 받지 않는다. 출발지
 * 포트는 넣지 않는다. NAT 뒤에서는 두 메시지 사이에 출발지 포트가 바뀔 수 있다.
 *
 * pub_c / pub_s 는 이번 핸드셰이크에만 쓰고 버리는 ECDH P-256 공개키다. 둘로 합의한
 * 값과 기기 키에서 세션 키를 뽑는다 (secure.h). 기기 키가 들어가므로 그 키를 모르는
 * 쪽은 같은 세션 키에 닿지 못한다 — RES_HANDSHAKE 의 tag 가 맞았다는 것이 곧 "상대가
 * 이 기기의 키를 아는 서버"라는 증명이다. 그래서 클라이언트는 tag 가 맞지 않는 수락을
 * 받지 않는다.
 *
 * DENY 의 mac 은 HMAC-SHA256(기기 키, "ztgate deny" | reason | AUTH 의 mac) 이다.
 * 서명이 맞는 AUTH 를 받은 뒤의 거절(터널 IP, 포스처)에만 채워지고, 그 전의 거절은
 * 서버가 상대의 키를 확인하지 못한 상태라 0 으로 둔다. 클라이언트는 mac 이 맞는 거절만
 * 서버의 답으로 믿는다.
 *
 * 세션이 열린 뒤의 패킷은 종류와 관계없이 같은 모양이다.
 *
 *   msg_header(8) | counter(8) | 암호문 | tag(16)
 *
 *   DATA       C <-> S   암호문 = inner IPv4 패킷
 *   KEEPALIVE  C  -> S   암호문 = posture(8)       포스처 재보고
 *              S  -> C   암호문 = net_config      지금의 터널 설정
 *   DENY       S  -> C   암호문 = reason(1)        세션 중의 거절. 헤더의 session_idx 는 그 세션
 *   LOGIN      C  -> S   암호문 = 사용자의 토큰     아래 "사용자 로그인"
 *              S  -> C   암호문 = status(1) | expires(8) | 사용자 이름
 *   DISCONNECT C <-> S   암호문 = reason(1)        세션을 끝낸다 (disconnect_reason_t)
 *
 * DISCONNECT 는 끝내는 쪽이 한 번 보내고 답을 기다리지 않는다. 받은 쪽은 그 세션을 바로
 * 닫는다 — 클라이언트가 끝났는데 서버가 60초 동안 세션을 붙잡아 두거나, 서버가 다시
 * 시작하는데 클라이언트가 30초 동안 죽은 세션으로 보내는 일이 없어진다. 잃어버려도 지금처럼
 * 만료로 정리된다. 세션 키로 감싸므로 세션 번호를 엿본 제3자가 남의 세션을 끝낼 수 없다.
 * 프로토콜 v6 그대로 더한 종류라, 모르는 쪽(이전 빌드)은 모르는 종류로 버린다.
 *
 * AES-256-GCM 이고, 앞의 16B(헤더와 counter)는 암호화하지 않지만 tag 가 함께 덮는다.
 * 방향마다 키가 다르고 counter 가 그대로 nonce 가 된다. */
typedef enum MSG_TYPE {
	MSG_TYPE_REQ_HANDSHAKE = 1,
	MSG_TYPE_RES_HANDSHAKE,
	MSG_TYPE_DATA,
	MSG_TYPE_KEEPALIVE,
	MSG_TYPE_CHALLENGE,
	MSG_TYPE_AUTH,
	MSG_TYPE_DENY,
	MSG_TYPE_ENROLL,
	MSG_TYPE_LOGIN,
	MSG_TYPE_DISCONNECT
} msg_type_t;

typedef enum DISCONNECT_REASON {
	DISCONNECT_CLIENT_EXIT = 1,	/* 클라이언트가 끝난다 (사용자가 끊었다, 서비스를 멈췄다) */
	DISCONNECT_SERVER_SHUTDOWN,	/* 서버가 끝난다. 다시 시작하는 중일 수 있으니 바로 다시 붙어 본다 */
	DISCONNECT_REKEY		/* 세션의 수명이 다했다. 바로 다시 핸드셰이크해 새 키로 연다 */
} disconnect_reason_t;

/* 세션 키의 수명. 키는 핸드셰이크에서만 바뀌므로 오래 열린 세션은 같은 키로 계속 감싼다.
 * 서버가 세션을 연 지 SESSION_LIFETIME_SEC (vpn_server -L 로 바꾼다) 가 지났거나 한쪽
 * 방향의 counter 가 REKEY_AFTER_PACKETS 에 닿으면 DISCONNECT(REKEY) 를 보내고 세션을 내린다.
 * 클라이언트는 그것을 받고 바로 다시 핸드셰이크하므로 새 일회용 키 쌍으로 새 키를 뽑는다.
 * 그 사이(왕복 두 번)의 패킷만 잃는다. IPsec 의 Child SA 수명(보통 1시간)과 같은 자리다.
 *
 * counter 는 GCM nonce 이므로 같은 키로 같은 값을 두 번 쓰면 안 된다. 64bit 라 다 쓸 일은
 * 없지만, 같은 키로 감싼 양이 많을수록 안전 여유가 준다. SECURE_COUNTER_LIMIT 은 서버가
 * 세션을 내리지 못했을 때의 마지막 선이다 — secure_seal / secure_open 이 그 뒤로는 거부한다. */
#define SESSION_LIFETIME_SEC	3600
#define REKEY_AFTER_PACKETS	(1ull << 36)
#define SECURE_COUNTER_LIMIT	(1ull << 40)

#define DEVICE_ID_LEN	16
#define VPN_PUB_LEN_WIRE	64	/* P-256 공개키 X | Y. crypt.h 의 VPN_PUB_LEN 과 같다 */
#define AUTH_KEY_LEN	32
#define AUTH_NONCE_LEN	16
#define AUTH_MAC_LEN	32	/* HMAC-SHA256 출력 전체 */

typedef enum DENY_REASON {
	DENY_UNKNOWN_DEVICE = 1,	/* 등록되지 않은 device_id */
	DENY_BAD_AUTH,			/* nonce 불일치 / 만료, mac 불일치 */
	DENY_TUN_IP,			/* (버전 3 까지) 그 기기에 배정된 터널 IP 가 아니다. 이제 터널 IP 는 서버가 정해 내려 주므로 보내지 않는다 */
	DENY_POSTURE			/* 인증은 됐지만 포스처가 정책에 못 미친다 */
} deny_reason_t;

/* 포스처 항목의 와이어 값. 0 이 "모름"이라 비워 둔 필드가 통과로 읽히지 않는다. */
typedef enum POSTURE_STATE {
	POSTURE_STATE_UNKNOWN = 0,
	POSTURE_STATE_OFF,
	POSTURE_STATE_ON
} posture_state_wire_t;

typedef struct posture_report {
	uint32_t os_build;	/* 못 읽었으면 0 */
	uint8_t firewall;	/* POSTURE_STATE_* */
	uint8_t antivirus;	/* POSTURE_STATE_* */
	/* 시스템 디스크(OS 가 깔린 볼륨)의 암호화. Windows 는 BitLocker 의 보호 상태, Linux 는 / 가
	 * dm-crypt(LUKS) 위에 있는가. 예전에 비어 있던 자리라 이전 빌드는 0(모름)을 보낸다 — 프로토콜
	 * 버전을 올리지 않고 더했다. */
	uint8_t disk;		/* POSTURE_STATE_* */
	uint8_t reserved;
} posture_report_t;

/* 기기 등록.
 *
 * 기기를 서버에 올리려면 기기에서 만든 ID(32자)와 키(64자)를 관리자가 서버의 목록에
 * 손으로 옮겨 적어야 했다. 키가 화면과 클립보드와 메신저를 거치고, 한 글자만 틀려도
 * "인증 실패"만 돌아온다.
 *
 * 이제 관리자는 등록 코드 하나를 만들어 건넨다. 코드는 한 번만 쓸 수 있고 곧 만료된다.
 * 기기는 코드로 서버와 세션을 열고, 그 세션 안에서 자기가 만든 ID 와 키를 보낸다.
 *
 * 새 핸드셰이크를 만들지 않았다. 코드에서 임시 신원(ID 와 키)을 뽑아 평소의 핸드셰이크를
 * 그대로 돈다 (secure.h 의 secure_enroll_identity). 그러면 이미 있는 것이 전부 따라온다 —
 * 코드를 모르는 쪽은 세션을 열지 못하고, 서버인 척하는 쪽은 코드를 모르므로 수락을
 * 만들지 못하고, 기기의 진짜 키는 그 세션의 키로 감싸여 가므로 코드를 나중에 알게 된
 * 사람도 녹화해 둔 등록에서 키를 꺼내지 못한다.
 *
 * 등록용 세션으로는 아래 한 가지만 할 수 있다. 터널 패킷은 받지 않는다.
 *
 *   C -> S  ENROLL   세션 패킷. 암호문 = device_id(16) | device_pub(64)
 *   S -> C  ENROLL   세션 패킷. 암호문 = status(1) | server_pub(64)
 *
 * 답이 사라지면 클라이언트는 같은 것을 다시 보낸다. 서버는 같은 ID 로 다시 온 요청에
 * 같은 답을 한다 — 한 번 더 등록하지 않는다.
 *
 * v8 부터 기기는 비밀 키가 아니라 공개키를 올린다. 서버의 목록에는 공개키만 남고(p256:...),
 * 서버가 뚫리거나 목록 파일이 새어도 기기의 키는 드러나지 않는다. 기기 키는 양쪽의 고정 키로
 * 한 번 더 한 ECDH 에서 뽑는다 (secure.h 의 secure_static_key):
 *
 *   기기   key = static_key(기기 비밀키, 서버 공개키)    등록할 때 한 번 계산해 저장하고 비밀키는 버린다
 *   서버   key = static_key(서버 비밀키, 기기 공개키)    목록을 읽을 때 계산한다
 *
 * 그 값이 지금까지의 "기기 키" 자리에 들어가므로 핸드셰이크와 세션 키는 그대로다. 서버의 비밀은
 * 서버 키 파일(vpn_server -k) 하나로 줄어든다. 서버 공개키는 등록 세션 안에서 오므로(코드를 아는
 * 서버만 그 세션을 열 수 있다) 기기는 따로 확인할 것이 없다. 관리자가 손으로 적는 공유 키
 * 기기(64 hex)도 그대로 받는다. */
typedef enum ENROLL_STATUS {
	ENROLL_OK = 0,
	ENROLL_GONE,		/* 코드가 그 사이에 만료됐거나 다른 기기가 먼저 썼다 */
	ENROLL_CONFLICT,	/* 그 ID 나 그 터널 주소가 이미 목록에 있다 */
	ENROLL_FAILED		/* 서버가 목록에 적지 못했다 */
} enroll_status_t;

#define ENROLL_PAYLOAD_LEN	(DEVICE_ID_LEN + VPN_PUB_LEN_WIRE)
#define ENROLL_REPLY_LEN	(1 + VPN_PUB_LEN_WIRE)

/* 등록 코드: 0-9 와 헷갈리는 글자(I L O U)를 뺀 대문자, 25자 (125비트).
 * 보여 줄 때는 다섯 자씩 끊는다: 7K2QF-9XWM4-... */
#define ENROLL_CODE_LEN		25

/* 사용자 로그인.
 *
 * 기기 인증은 장비를 확인할 뿐 그 장비를 누가 쓰는지는 모른다. 사용자는 회사의 IdP 에
 * 로그인해 토큰(JWT)을 받고, 클라이언트는 열린 세션 안에서 그 토큰을 서버에 보낸다.
 *
 *   C -> S  LOGIN   세션 패킷. 암호문 = 토큰 (ASCII, header.payload.signature)
 *   S -> C  LOGIN   세션 패킷. 암호문 = status(1) | expires(8) | 사용자 이름
 *
 * 토큰을 핸드셰이크에 싣지 않고 세션이 열린 뒤에 보낸다. 핸드셰이크의 AUTH 는 암호화되지
 * 않으므로 거기에 실으면 토큰이 그대로 보이고, 토큰은 가진 사람이 곧 그 사용자인
 * 증표다. 세션 패킷은 서버만 열 수 있고, 수락의 tag 로 상대가 진짜 서버임도 이미 확인했다.
 *
 * 로그인하지 않아도 세션은 열린다. 기기만으로 갈 수 있는 곳(사용자 조건이 없는 ACL
 * 규칙)은 그대로 가고, user= / group= 이 걸린 규칙만 맞지 않는다. 토큰이 만료되면 서버는
 * 그때부터 그 사용자를 세션에서 떼고, 클라이언트는 새 토큰을 받는 대로 다시 보낸다.
 * 세션도 터널도 끊지 않는다.
 *
 * expires 는 토큰의 exp (Unix time, 빅엔디언)이고 실패하면 0 이다. 이름은 성공했을 때만
 * 붙는다 (NUL 없이, 패킷 끝까지). 같은 토큰을 다시 보내면 같은 답을 한다 — 답이
 * 사라졌을 때 클라이언트가 그냥 다시 보내면 된다.
 *
 * 토큰은 UDP 패킷 하나에 들어가야 한다. 그룹이 아주 많은 토큰은 IdP 쪽에서 줄인다
 * (요청하는 scope 나 그룹 매퍼). */
#define LOGIN_TOKEN_MAX		(BUF_SIZE - PKT_OVERHEAD - 64)
#define LOGIN_RES_HEAD_LEN	9	/* status(1) | expires(8) */
#define LOGIN_USER_MAX		63	/* 답에 실리는 사용자 이름의 최대 길이 */

typedef enum LOGIN_STATUS {
	LOGIN_OK = 0,
	LOGIN_NO_IDP,		/* 이 서버는 사용자 로그인을 받지 않는다 (-u 를 주지 않았다) */
	LOGIN_MALFORMED,	/* JWT 의 모양이 아니다, 너무 크다 */
	LOGIN_UNTRUSTED,	/* 받지 않는 알고리즘, 모르는 키, 서명이 맞지 않는다 */
	LOGIN_WRONG_TOKEN,	/* 서명은 맞지만 다른 서비스나 다른 IdP 에 준 토큰이다 (iss / aud) */
	LOGIN_EXPIRED,		/* 만료됐거나 아직 쓸 수 없는 토큰이다 (exp / nbf) */
	LOGIN_BAD_USER,		/* 사용자 이름이 없거나 쓸 수 없는 글자가 있다 */
	LOGIN_DPOP		/* 기기에 묶인 토큰인데 증명이 없거나 맞지 않는다, 또는 묶이지 않은 토큰을 받지 않는다 */
} login_status_t;

/* DPoP — 토큰을 이 기기의 키에 묶는다 (RFC 9449 를 터널에 맞춘 것).
 *
 * IdP 에 토큰을 청할 때 기기의 서명 키(P-256)로 만든 증명을 붙이면 IdP 는 그 키의 지문(RFC 7638 의
 * JWK SHA-256 thumbprint)을 토큰의 cnf.jkt 에 적어 준다. 그런 토큰은 그 키를 가진 쪽만 쓸 수 있다.
 * LOGIN 에 토큰과 함께 새 증명을 싣는다 — 둘 사이는 공백 하나:
 *
 *   암호문 = 토큰 [ " " 증명 ]
 *   증명 = ES256 JWS. 헤더 {"typ":"dpop+jwt","alg":"ES256","jwk":{공개키}},
 *          본문 {"htm":"LOGIN","htu":"ztgate:login","iat":<지금>,"jti":<한 번만>,"ath":<b64url(SHA-256(토큰))>}
 *
 * 서버는 증명의 서명, jwk 의 지문 == 토큰의 cnf.jkt, ath, iat(앞뒤 DPOP_IAT_WINDOW 초), jti 의 재사용을
 * 본다. 훔친 토큰은 그 기기의 키 없이는 증명을 만들 수 없어 쓸 수 없다. 묶이지 않은 토큰은 서버
 * 설정(idp.conf 의 dpop required)이 아니면 지금처럼 받는다. */
#define DPOP_HTM		"LOGIN"
#define DPOP_HTU		"ztgate:login"
#define DPOP_IAT_WINDOW		120

#define ECDH_PUB_LEN	64	/* P-256 공개키 X(32) | Y(32) */
#define AEAD_TAG_LEN	16

/* CHALLENGE: nonce(16) | server_pub(64). REQ 는 그만큼의 0 이다 (증폭 방지). */
#define CHALLENGE_PAYLOAD_LEN	(AUTH_NONCE_LEN + ECDH_PUB_LEN)
#define REQ_HS_PAYLOAD_LEN	CHALLENGE_PAYLOAD_LEN

/* AUTH 페이로드 안에서의 위치 (헤더 뒤부터). ID 와 포스처는 감싸기 전에 이 자리에 쓰고, 그 자리에서
 * 암호문이 된다 (secure.h 의 secure_auth_seal). */
#define AUTH_SEALED_PLAIN_LEN	(DEVICE_ID_LEN + sizeof(posture_report_t))
#define AUTH_OFF_PUB		0
#define AUTH_OFF_NONCE		(AUTH_OFF_PUB + ECDH_PUB_LEN)
#define AUTH_OFF_ID		(AUTH_OFF_NONCE + AUTH_NONCE_LEN)
#define AUTH_OFF_POSTURE	(AUTH_OFF_ID + DEVICE_ID_LEN)
#define AUTH_OFF_TAG		(AUTH_OFF_ID + AUTH_SEALED_PLAIN_LEN)
#define AUTH_OFF_MAC		(AUTH_OFF_TAG + AEAD_TAG_LEN)
#define AUTH_PAYLOAD_LEN	(AUTH_OFF_MAC + AUTH_MAC_LEN)

/* mac 이 덮는 범위와 패킷 전체. 둘 다 패킷의 첫 바이트(헤더)부터 잰 길이다. */
#define AUTH_SIGNED_LEN		(sizeof(msg_header_t) + AUTH_OFF_MAC)
#define AUTH_PACKET_LEN		(sizeof(msg_header_t) + AUTH_PAYLOAD_LEN)

/* RES_HANDSHAKE: tag 가 덮는 앞부분(헤더 | pub_s)과 패킷의 최소 길이. */
#define RES_HS_HEAD_LEN		(sizeof(msg_header_t) + ECDH_PUB_LEN)
#define RES_HS_MIN_LEN		(RES_HS_HEAD_LEN + AEAD_TAG_LEN)

/* 핸드셰이크 중의 DENY: 헤더 | reason(1) | mac(32) */
#define DENY_HS_LEN		(sizeof(msg_header_t) + 1 + AUTH_MAC_LEN)

/* 세션 패킷에 우리가 덧붙이는 바이트: 헤더(8) + counter(8) + tag(16) */
#define PKT_OVERHEAD		(PKT_HDR_LEN + AEAD_TAG_LEN)

typedef struct msg_header {
	uint8_t version;
	uint8_t type;
	uint8_t reserved[2];
	uint32_t session_idx;
} msg_header_t;

typedef struct data_header {
	uint64_t counter;
} data_header_t;

PROTO_STATIC_ASSERT(sizeof(msg_header_t) == 8, "msg_header wire size");
PROTO_STATIC_ASSERT(sizeof(data_header_t) == 8, "data_header wire size");
PROTO_STATIC_ASSERT(sizeof(posture_report_t) == 8, "posture_report wire size");

int msg_encode(unsigned char *buf, size_t cap, const struct msg_header *h);
int msg_decode(const unsigned char *buf, size_t len, struct msg_header *h);

int data_encode(unsigned char *buf, size_t cap, const struct data_header *d);
int data_decode(const unsigned char *buf, size_t len, struct data_header *d);

int posture_encode(unsigned char *buf, size_t cap, const struct posture_report *p);
int posture_decode(const unsigned char *buf, size_t len, struct posture_report *p);

/* 터널 설정. 서버가 정해서 내려 주고 클라이언트는 받은 대로 맞춘다.
 *
 *   tun_ip(4) | prefix_len(1) | n_routes(1) | mtu(2) | n_routes x ( addr(4) | prefix_len(1) )
 *   | n_dns(1) | n_domains(1) | n_dns x addr(4) | n_domains x ( len(1) | 이름(len) )
 *
 * 뒤의 둘(v7)은 내부 DNS 다. 내부 자원을 IP 가 아니라 이름(intranet.corp.example)으로 쓰려면
 * 그 이름을 아는 DNS 에 물어야 하는데, PC 가 원래 쓰는 DNS(공유기, 통신사)는 모른다. 모든
 * 질의를 내부 DNS 로 보내면 회사와 무관한 이름까지 회사로 가고 내부 DNS 가 죽으면 인터넷도
 * 안 된다. 그래서 domains 에 적은 이름(과 그 아래 이름)만 dns 로 묻는다 — 분할 DNS.
 * Windows 는 NRPT, Linux 는 systemd-resolved 의 인터페이스별 도메인으로 건다.
 *
 * 전에는 클라이언트가 터널 IP 를 직접 적어야 했다. 서버가 이미 아는 값을 사용자가 한 번
 * 더 똑같이 입력하는 것이고, 틀리면 거절당할 뿐이다. 그리고 "무엇을 터널로 보낼
 * 것인가"는 정하는 곳이 없어서 터널 대역 말고는 갈 수 없었다. 둘 다 서버의 정책에서
 * 나와야 하는 값이다 — 관리자가 한 곳을 고치면 붙어 있는 기기가 따라오게 한다.
 *
 * RES_HANDSHAKE 와 서버의 keepalive 응답에 실린다. keepalive 마다 통째로 다시 보내므로
 * 클라이언트는 받은 것과 지금 적용한 것을 비교하기만 하면 된다. 바뀐 것만 따로 알리는
 * 메시지를 두면 그 한 통이 사라졌을 때를 위한 확인과 재전송이 필요해진다.
 *
 * 주소는 네트워크 바이트 순서 그대로 둔다 (in_addr.s_addr 와 같은 모양). */
#define NET_MAX_ROUTES	32
#define NET_MAX_DNS	2
#define NET_MAX_DOMAINS	4
#define NET_DOMAIN_MAX	100	/* 이름 하나의 글자 수 (NUL 빼고) */

typedef struct net_route {
	uint32_t addr;		/* 대역의 주소 */
	uint8_t prefix_len;
} net_route_t;

typedef struct net_config {
	uint32_t tun_ip;	/* 이 기기의 터널 주소 */
	uint8_t prefix_len;	/* 터널 대역의 prefix */
	uint8_t n_routes;
	uint16_t mtu;
	net_route_t routes[NET_MAX_ROUTES];	/* 터널 대역 말고 터널로 보낼 대역 */

	uint8_t n_dns;
	uint8_t n_domains;
	uint32_t dns[NET_MAX_DNS];		/* 내부 DNS 서버 */
	char domains[NET_MAX_DOMAINS][NET_DOMAIN_MAX + 1];	/* 그 DNS 에 물을 이름. 소문자, 앞뒤 점 없음 */
} net_config_t;

#define NET_CONFIG_HEAD_LEN	8
#define NET_ROUTE_LEN		5
#define NET_DNS_HEAD_LEN	2
#define NET_CONFIG_MAX_LEN	(NET_CONFIG_HEAD_LEN + NET_MAX_ROUTES * NET_ROUTE_LEN + NET_DNS_HEAD_LEN + \
				 NET_MAX_DNS * 4 + NET_MAX_DOMAINS * (1 + NET_DOMAIN_MAX))

/* 쓴 길이를 돌려준다. 자리가 모자라거나 값이 범위를 벗어나면 -1. */
int net_config_encode(unsigned char *buf, size_t cap, const net_config_t *c);

/* len 은 설정 하나의 길이와 정확히 같아야 한다. 맞지 않거나 값이 범위를 벗어나면 -1. */
int net_config_decode(const unsigned char *buf, size_t len, net_config_t *c);

/* 내용이 같으면 1. 구조체의 빈 자리는 보지 않는다. */
int net_config_equal(const net_config_t *a, const net_config_t *b);

/* DNS 부분(dns, domains)만 같으면 1. 클라이언트가 DNS 설정을 다시 걸지 볼 때 쓴다. */
int net_dns_equal(const net_config_t *a, const net_config_t *b);

/* DNS 이름으로 받을 수 있으면 1 (소문자, 숫자, -, 점. 앞뒤 점과 이어진 점은 안 된다). */
int net_domain_ok(const char *name);

#ifdef __cplusplus
}
#endif

#endif
