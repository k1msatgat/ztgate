#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include "session.h"

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

const char *session_deny_name(uint8_t reason)
{
	switch (reason) {
		case DENY_UNKNOWN_DEVICE:	return "unknown device";
		case DENY_BAD_AUTH:		return "bad auth";
		case DENY_TUN_IP:		return "tunnel ip not assigned to this device";
		case DENY_POSTURE:		return "posture does not meet policy";
		default:			return "?";
	}
}

const char *session_login_name(uint8_t status)
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

/* deadline 까지 패킷 하나를 기다린다. 받은 길이, 시간이 다 되면 0, 오류면 HS_FAIL.
 * 헤더가 깨졌거나 버전이 다른 것은 받지 않은 것으로 친다.
 *
 * connect() 한 UDP 소켓은 서버 쪽 포트가 닫혀 있다는 ICMP 를 받으면 다음 recv 가
 * ECONNREFUSED 로 끝난다. 서버가 막 재시작하는 중일 수 있으므로 오류로 보지 않고 계속
 * 기다린다 (Windows 는 같은 이유로 SIO_UDP_CONNRESET 을 끈다). */
static int hs_recv(vpn_session_t *s, uint64_t deadline, uint8_t *buf, size_t cap, msg_header_t *h)
{
	struct pollfd pfd = { .fd = s->sock, .events = POLLIN };
	uint64_t now;
	ssize_t n;
	int r;

	for (;;) {
		now = now_ms();
		if (now >= deadline) {
			return 0;
		}

		r = poll(&pfd, 1, (int)(deadline - now));
		if (r < 0) {
			if (errno == EINTR) {
				return HS_FAIL;	/* 종료 신호. 부르는 쪽이 running 을 본다 */
			}
			perror("poll");
			return HS_FAIL;
		}
		if (r == 0) {
			return 0;
		}

		n = recv(s->sock, buf, cap, 0);
		if (n < 0) {
			if (errno == ECONNREFUSED || errno == EAGAIN || errno == EINTR) {
				continue;
			}
			perror("recv");
			return HS_FAIL;
		}

		if (msg_decode(buf, (size_t)n, h) < 0 || h->version != PROTOCOL_VERSION) {
			continue;
		}

		return (int)n;
	}
}

static int send_all(vpn_session_t *s, const uint8_t *buf, size_t len)
{
	if (send(s->sock, buf, len, 0) < 0) {
		/* 지난번 보낸 것에 대한 ICMP 가 남아 있으면 send 도 ECONNREFUSED 로 끝난다. */
		if (errno == ECONNREFUSED) {
			return 0;
		}
		perror("send");
		return -1;
	}

	return 0;
}

static int send_request(vpn_session_t *s, const uint8_t id[DEVICE_ID_LEN])
{
	uint8_t req[sizeof(msg_header_t) + REQ_HS_PAYLOAD_LEN];
	msg_header_t h;

	memset(&h, 0, sizeof(h));
	h.version = PROTOCOL_VERSION;
	h.type = MSG_TYPE_REQ_HANDSHAKE;
	msg_encode(req, sizeof(req), &h);
	memcpy(req + sizeof(msg_header_t), id, DEVICE_ID_LEN);

	return send_all(s, req, sizeof(req));
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
	crypt_wipe(hs, sizeof(*hs));
}

/* AUTH: device_id(16) | nonce(16) | pub_c(64) | posture(8) | mac(32)
 *
 * mac 은 헤더부터 그 앞까지 전체를 덮는다. 서버가 방금 준 nonce 가 들어가므로 이
 * 패킷은 이번 핸드셰이크에만 유효하다. 포스처와 pub_c 도 서명 범위 안이라 사이에 낀
 * 쪽이 "방화벽 꺼짐"을 "켜짐"으로, pub_c 를 자기 공개키로 바꾸면 서버가 받지 않는다. */
static int send_auth(vpn_session_t *s, handshake_t *hs, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t key[AUTH_KEY_LEN], const uint8_t *nonce,
		const posture_report_t *posture)
{
	uint8_t *body = hs->auth + sizeof(msg_header_t);
	msg_header_t h;

	memset(&h, 0, sizeof(h));
	h.version = PROTOCOL_VERSION;
	h.type = MSG_TYPE_AUTH;
	msg_encode(hs->auth, sizeof(hs->auth), &h);

	memcpy(body + AUTH_OFF_DEVICE_ID, id, DEVICE_ID_LEN);
	memcpy(body + AUTH_OFF_NONCE, nonce, AUTH_NONCE_LEN);

	/* 핸드셰이크마다 새 키 쌍이다. 다시 쓰면 "지난 세션은 풀리지 않는다"가 깨진다. */
	hs->ecdh = crypt_ecdh_new(body + AUTH_OFF_PUB);
	if (hs->ecdh == NULL) {
		fprintf(stderr, "[HS] key generation failed\n");
		return -1;
	}

	posture_encode(body + AUTH_OFF_POSTURE, sizeof(*posture), posture);

	if (crypt_hmac(key, AUTH_KEY_LEN, hs->auth, AUTH_SIGNED_LEN, body + AUTH_OFF_MAC) < 0) {
		fprintf(stderr, "[HS] hmac failed\n");
		return -1;
	}

	if (send_all(s, hs->auth, sizeof(hs->auth)) < 0) {
		return -1;
	}
	hs->auth_sent = 1;

	return 0;
}

/* RES_HANDSHAKE: pub_s(64) | 암호화된 net_config | tag(16)
 *
 * 서버의 일회용 공개키와 내 것으로 합의하고, 거기에 기기 키를 섞어 세션 키를 뽑는다.
 * tag 가 맞으면 상대도 같은 키에 닿았다는 뜻이고, 그러려면 이 기기의 키를 알아야 한다.
 * 맞지 않으면 서버가 보낸 것이 아니므로 버린다. 0 을 돌려주면 세션이 열린 것이다. */
static int accept_response(vpn_session_t *s, handshake_t *hs, const uint8_t key[AUTH_KEY_LEN],
		uint8_t *res, int len, uint32_t session_idx)
{
	uint8_t secret[VPN_SECRET_LEN];
	secure_keys_t keys;
	net_config_t cfg;
	int cfg_len;
	int ret = -1;

	if (crypt_ecdh_derive(hs->ecdh, res + sizeof(msg_header_t), secret) < 0 ||
			secure_derive(key, secret, hs->auth, res, &keys) < 0) {
		goto out;
	}

	cfg_len = secure_res_open(keys.res, res, (size_t)len);
	if (cfg_len < 0) {
		goto out;
	}

	if (net_config_decode(res + RES_HS_HEAD_LEN, (size_t)cfg_len, &cfg) < 0) {
		fprintf(stderr, "[HS] the server sent a tunnel configuration this client cannot read\n");
		goto out;
	}

	if (secure_session_open(&s->secure, keys.c2s, keys.s2c) < 0) {
		goto out;
	}
	s->idx = session_idx;
	s->cfg = cfg;
	ret = 0;

out:
	crypt_wipe(secret, sizeof(secret));
	crypt_wipe(&keys, sizeof(keys));

	return ret;
}

/* 핸드셰이크 중에 온 DENY 를 서버가 보낸 것으로 믿어도 되는가.
 *
 * 서버는 서명이 맞는 AUTH 를 받은 뒤의 거절(포스처)에 기기 키로 만든 mac 을 붙인다.
 * 그 전의 거절(모르는 기기, 인증 실패)은 서버가 우리 키를 확인하지 못한 상태에서
 * 나오므로 mac 이 없고, 서버 주소를 위조할 수 있는 누구나 만들 수 있다. */
static int deny_verified(const handshake_t *hs, const uint8_t key[AUTH_KEY_LEN], const uint8_t *body)
{
	uint8_t want[AUTH_MAC_LEN];

	if (!hs->auth_sent) {
		return 0;
	}

	if (secure_deny_mac(key, body[0], hs->auth + AUTH_SIGNED_LEN, want) < 0) {
		return 0;
	}

	return crypt_equal(want, body + 1, AUTH_MAC_LEN);
}

/*   C -> S  REQ_HANDSHAKE     "나는 이 기기다"
 *   S -> C  CHALLENGE         "그렇다면 이 nonce 에 서명해 봐라"
 *   C -> S  AUTH              nonce + 내 일회용 공개키 + 포스처 + mac
 *   S -> C  RES_HANDSHAKE     세션 idx + 서버의 일회용 공개키 + 설정 + tag   (또는 DENY 와 사유) */
int session_handshake(vpn_session_t *s, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t key[AUTH_KEY_LEN], const posture_report_t *posture)
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

	/* 새로 인증하면 새 세션이다. 서버도 그 기기의 예전 세션을 내린다. */
	session_close(s);
	memset(&hs, 0, sizeof(hs));

	for (tries = 1; tries <= HS_RETRY; tries++) {
		printf("[HS] request %d/%d\n", tries, HS_RETRY);
		hs_reset(&hs);
		loose_deny = 0;
		if (send_request(s, id) < 0) {
			goto out;
		}

		deadline = now_ms() + HS_TIMEOUT_MSEC;
		for (;;) {
			n = hs_recv(s, deadline, res, sizeof(res), &h);
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
					if (body_len < AUTH_NONCE_LEN || hs.auth_sent) {
						continue;
					}
					if (send_auth(s, &hs, id, key, body, posture) < 0) {
						goto out;
					}
					deadline = now_ms() + HS_TIMEOUT_MSEC;
					continue;

				case MSG_TYPE_DENY:
					/* 세션 번호가 붙은 DENY 는 열려 있던 세션에 대한 것이다. 여기서는
					 * 그 세션을 버리고 새로 여는 중이므로 볼 필요가 없다. */
					if (n < (int)DENY_HS_LEN || h.session_idx != 0) {
						continue;
					}

					if (deny_verified(&hs, key, body)) {
						s->deny_reason = body[0];
						printf("[HS] denied: %s\n", session_deny_name(body[0]));
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
					if (accept_response(s, &hs, key, res, n, h.session_idx) < 0) {
						printf("[HS] response did not verify, ignored\n");
						continue;
					}

					printf("[HS] established idx=%08x\n", s->idx);
					ret = HS_OK;
					goto out;

				default:
					continue;
			}
		}

		if (loose_deny != 0) {
			s->deny_reason = loose_deny;
			printf("[HS] denied: %s\n", session_deny_name(loose_deny));
			ret = HS_DENIED;
			goto out;
		}
	}

	fprintf(stderr, "[HS] no response from server\n");

out:
	hs_reset(&hs);
	crypt_wipe(res, sizeof(res));

	return ret;
}

int session_enroll(vpn_session_t *s, const char *code, const uint8_t id[DEVICE_ID_LEN],
		uint8_t key[AUTH_KEY_LEN], const posture_report_t *posture)
{
	uint8_t tmp_id[DEVICE_ID_LEN];
	uint8_t tmp_key[AUTH_KEY_LEN];
	uint8_t packet[BUF_SIZE];
	uint8_t pub[VPN_PUB_LEN];
	crypt_ecdh_t *mine = NULL;
	msg_header_t h;
	uint64_t deadline;
	int ret = SESSION_ENROLL_NO_RESPONSE;
	int tries;
	int n;

	if (secure_enroll_identity(code, tmp_id, tmp_key) < 0) {
		return SESSION_ENROLL_BAD_CODE;
	}

	/* 이 기기의 고정 키 쌍. 비밀키는 기기 키를 뽑는 데 한 번 쓰고 버린다 — 저장하는 것은 그
	 * 결과(기기 키)뿐이라 신원 파일의 모양이 그대로다. */
	mine = crypt_ecdh_new(pub);
	if (mine == NULL) {
		return SESSION_ENROLL_ERROR;
	}

	switch (session_handshake(s, tmp_id, tmp_key, posture)) {
		case HS_OK:
			break;
		case HS_DENIED:
			/* 서버가 그 코드를 모른다: 잘못 적었거나, 만료됐거나, 이미 쓰였다. */
			ret = SESSION_ENROLL_REJECTED;
			goto out;
		default:
			goto out;
	}

	for (tries = 1; tries <= ENROLL_TRIES; tries++) {
		/* 다시 보낼 때마다 새로 감싼다. counter 가 달라져야 서버가 재전송으로 버리지
		 * 않는다. 내용이 같으므로 서버는 같은 답을 한다. */
		memcpy(packet + PKT_HDR_LEN, id, DEVICE_ID_LEN);
		memcpy(packet + PKT_HDR_LEN + DEVICE_ID_LEN, pub, VPN_PUB_LEN);
		if (session_send(s, MSG_TYPE_ENROLL, packet, sizeof(packet), ENROLL_PAYLOAD_LEN) < 0) {
			ret = SESSION_ENROLL_ERROR;
			goto out;
		}
		printf("[enroll] sent %d/%d\n", tries, ENROLL_TRIES);

		deadline = now_ms() + ENROLL_TIMEOUT_MSEC;
		for (;;) {
			n = hs_recv(s, deadline, packet, sizeof(packet), &h);
			if (n == HS_FAIL) {
				ret = SESSION_ENROLL_ERROR;
				goto out;
			}
			if (n == 0) {
				break;
			}
			if (h.type != MSG_TYPE_ENROLL || h.session_idx != s->idx) {
				continue;
			}

			/* 세션 키로 열려야 서버의 답이다. */
			n = secure_open(&s->secure, packet, (size_t)n, NULL);
			if (n < (int)ENROLL_REPLY_LEN) {
				continue;
			}

			ret = packet[PKT_HDR_LEN];
			printf("[enroll] server answered %d\n", ret);
			/* 서버의 공개키는 코드를 아는 서버만 열 수 있는 이 세션으로 왔다. */
			if (ret == ENROLL_OK &&
					secure_static_key(mine, packet + PKT_HDR_LEN + 1, pub, packet + PKT_HDR_LEN + 1, key) < 0) {
				ret = SESSION_ENROLL_ERROR;
			}
			goto out;
		}
	}

out:
	/* 등록용 세션으로는 터널을 쓸 수 없다. 남겨 둘 이유가 없다. */
	session_close(s);
	crypt_ecdh_free(mine);
	crypt_wipe(tmp_key, sizeof(tmp_key));
	crypt_wipe(packet, sizeof(packet));

	return ret;
}

int session_send(vpn_session_t *s, uint8_t type, uint8_t *pkt, size_t cap, size_t len)
{
	int n;

	n = secure_seal(&s->secure, type, s->idx, pkt, cap, len);
	if (n < 0) {
		return -1;
	}

	return send_all(s, pkt, (size_t)n);
}

/* KEEPALIVE: counter(8) | 암호화된 posture(8) | tag(16)
 *
 * 핸드셰이크에서 한 번 통과했다고 세션이 끝날 때까지 믿지 않는다. keepalive 마다
 * 지금의 포스처를 다시 싣고, 서버는 받을 때마다 정책을 다시 평가한다. 데이터 패킷과
 * 같은 세션 키, 같은 counter 로 감싸므로 예전 것을 다시 보내면 서버가 열지 못한다. */
int session_send_keepalive(vpn_session_t *s, const posture_report_t *posture)
{
	uint8_t packet[PKT_OVERHEAD + sizeof(posture_report_t)];

	posture_encode(packet + PKT_HDR_LEN, sizeof(posture_report_t), posture);

	return session_send(s, MSG_TYPE_KEEPALIVE, packet, sizeof(packet), sizeof(posture_report_t));
}

int session_send_disconnect(vpn_session_t *s, uint8_t reason)
{
	uint8_t packet[PKT_OVERHEAD + 1];

	if (s->idx == 0) {
		return 0;
	}
	packet[PKT_HDR_LEN] = reason;

	return session_send(s, MSG_TYPE_DISCONNECT, packet, sizeof(packet), 1);
}

void session_close(vpn_session_t *s)
{
	secure_session_close(&s->secure);
	s->idx = 0;
	s->deny_reason = 0;
}
