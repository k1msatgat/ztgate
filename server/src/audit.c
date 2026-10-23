#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "audit.h"
#include "idp.h"
#include "common.h"
#include "device.h"

/* 같은 목적지를 다시 적기까지의 시간. 길게 열어 둔 연결이 로그에서 사라지지 않게 하되
 * 패킷마다 적지는 않는다. */
#define ACCESS_REPEAT_SEC 60

/* 거절된 핸드셰이크는 1초에 이만큼만 적는다. 기기 ID 는 공개된 이름표라 누구나 틀린
 * 요청을 쏟아부을 수 있고, 그때마다 한 줄씩 쓰면 디스크가 먼저 찬다. 넘친 만큼은 세어
 * 두었다가 다음 줄에 적는다 — 버렸다는 사실까지 버리지는 않는다. */
#define DENIED_PER_SEC 20

static FILE *out;
static char out_path[256];

static time_t denied_sec;
static int denied_count;
static unsigned long denied_suppressed;

static int open_file(void)
{
	FILE *f;
	int fd;

	/* 기기 ID 와 접근 기록이 들어간다. 다른 사용자가 읽을 수 없게 만든다. */
	fd = open(out_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		perror(out_path);
		return -1;
	}

	f = fdopen(fd, "a");
	if (f == NULL) {
		close(fd);
		return -1;
	}

	/* 사건 하나가 줄 하나다. 줄 단위로 내보내야 서버가 죽어도 마지막 사건이 남는다. */
	setvbuf(f, NULL, _IOLBF, 0);

	if (out != NULL) {
		fclose(out);
	}
	out = f;

	return 0;
}

int audit_open(const char *path)
{
	if (strlen(path) >= sizeof(out_path)) {
		fprintf(stderr, "audit: path too long\n");
		return -1;
	}
	strcpy(out_path, path);

	return open_file();
}

void audit_reopen(void)
{
	if (out != NULL && open_file() < 0) {
		fprintf(stderr, "audit: reopen failed, still writing to the old file\n");
	}
}

void audit_close(void)
{
	if (out != NULL) {
		fclose(out);
		out = NULL;
	}
}

/* {"time":"2026-10-13T12:34:56Z","event":"...", — 사건의 시각은 벽시계다. 세션 만료처럼
 * "몇 초 지났는가"는 단조 시계로 재지만, 기록은 사람이 달력과 맞춰 봐야 한다. */
static void begin(const char *event)
{
	char stamp[32];
	struct tm tm;
	time_t now = time(NULL);

	gmtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
	/* 워커가 여럿이면 사건이 동시에 적힌다. 한 사건의 조각들이 섞이지 않게 end() 까지 파일을 쥔다. */
	flockfile(out);
	fprintf(out, "{\"time\":\"%s\",\"event\":\"%s\"", stamp, event);
}

static void field(const char *fmt, ...)
{
	va_list ap;

	fputc(',', out);
	va_start(ap, fmt);
	vfprintf(out, fmt, ap);
	va_end(ap);
}

static void end(void)
{
	fputs("}\n", out);
	funlockfile(out);
}

static const char *state_name(uint8_t state)
{
	switch (state) {
	case POSTURE_STATE_ON:	return "on";
	case POSTURE_STATE_OFF:	return "off";
	default:		return "unknown";
	}
}

static void session_fields(const peer_t *peer)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];

	field("\"device\":\"%s\"", device_id_str(peer->device_id, ids));
	field("\"tunnel_ip\":\"%s\"", ip_str(peer->inner, ib));
	field("\"session\":\"%08x\"", peer->session_idx);
	field("\"endpoint\":\"%s:%u\"", ip_str(peer->outer.sin_addr, ib), ntohs(peer->outer.sin_port));
	if (peer->logged_in) {
		field("\"user\":\"%s\"", peer->user.name);
	}
}

void audit_session_open(const peer_t *peer)
{
	if (out == NULL) {
		return;
	}

	begin("session_open");
	session_fields(peer);
	field("\"posture\":{\"os_build\":%u,\"firewall\":\"%s\",\"antivirus\":\"%s\"}",
			peer->posture.os_build, state_name(peer->posture.firewall),
			state_name(peer->posture.antivirus));
	end();
}

void audit_session_close(const peer_t *peer, const char *reason)
{
	/* 등록용 세션이 닫히는 것은 기기의 세션이 닫힌 것이 아니다. 등록은 enrolled 로 따로 남는다. */
	if (out == NULL || peer->enroll) {
		return;
	}

	begin("session_close");
	session_fields(peer);
	field("\"reason\":\"%s\"", reason);
	field("\"duration_sec\":%ld", (long)(mono_now() - peer->established_at));
	field("\"rx_packets\":%llu,\"rx_bytes\":%llu", (unsigned long long)peer->rx_packets,
			(unsigned long long)peer->rx_bytes);
	field("\"tx_packets\":%llu,\"tx_bytes\":%llu", (unsigned long long)peer->tx_packets,
			(unsigned long long)peer->tx_bytes);
	field("\"acl_denied\":%llu", (unsigned long long)peer->acl_denied);
	end();
}

static const char *deny_name(uint8_t reason)
{
	switch (reason) {
	case DENY_UNKNOWN_DEVICE:	return "unknown_device";
	case DENY_BAD_AUTH:		return "bad_auth";
	case DENY_POSTURE:		return "posture";
	default:			return "other";
	}
}

void audit_auth_denied(const uint8_t id[DEVICE_ID_LEN], const struct sockaddr_in *src, uint8_t reason)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];
	time_t now;

	if (out == NULL) {
		return;
	}

	now = mono_now();
	if (now != denied_sec) {
		denied_sec = now;
		denied_count = 0;
	}
	if (denied_count >= DENIED_PER_SEC) {
		denied_suppressed++;
		return;
	}
	denied_count++;

	begin("auth_denied");
	field("\"device\":\"%s\"", device_id_str(id, ids));
	field("\"endpoint\":\"%s:%u\"", ip_str(src->sin_addr, ib), ntohs(src->sin_port));
	field("\"reason\":\"%s\"", deny_name(reason));
	if (denied_suppressed != 0) {
		field("\"suppressed\":%lu", denied_suppressed);
		denied_suppressed = 0;
	}
	end();
}

void audit_access(peer_t *peer, const uint8_t *ip, int len, int allowed, const char *why)
{
	char ib[INET_ADDRSTRLEN];
	struct in_addr dst;
	audit_flow_t *f;
	uint16_t dport = 0;
	uint8_t proto;
	time_t now;
	int ihl;
	int i;

	if (out == NULL || len < IP_MIN_HDR) {
		return;
	}

	memcpy(&dst, ip + IP_DST_OFF, IP_ADDR_LEN);
	proto = ip[IP_PROTO_OFF];

	/* 길이는 받은 패킷이 말하는 값이라 그대로 믿지 않는다. */
	ihl = IP_IHL(ip);
	if ((proto == 6 || proto == 17) && ihl >= IP_MIN_HDR && len >= ihl + L4_DPORT_OFF + L4_PORT_LEN) {
		memcpy(&dport, ip + ihl + L4_DPORT_OFF, L4_PORT_LEN);
		dport = ntohs(dport);
	}

	now = mono_now();
	for (i = 0; i < AUDIT_FLOWS; i++) {
		f = &peer->flows[i];
		if (f->used && f->dst == dst.s_addr && f->proto == proto && f->dport == dport &&
				f->allowed == (uint8_t)allowed) {
			if (now - f->at < ACCESS_REPEAT_SEC) {
				return;
			}
			break;
		}
	}

	/* 처음 보는 목적지면 가장 오래된 자리에 적는다. 자리가 적어서 목적지를 많이 오가는
	 * 세션은 같은 목적지를 60초 안에 다시 적을 수 있다. 덜 적는 쪽이 아니라 더 적는
	 * 쪽으로 틀린다. */
	if (i == AUDIT_FLOWS) {
		i = peer->flow_next;
		peer->flow_next = (peer->flow_next + 1) % AUDIT_FLOWS;
	}

	f = &peer->flows[i];
	f->used = 1;
	f->dst = dst.s_addr;
	f->proto = proto;
	f->dport = dport;
	f->allowed = (uint8_t)allowed;
	f->at = now;

	begin("access");
	session_fields(peer);
	field("\"dst\":\"%s\",\"proto\":%u,\"dport\":%u", ip_str(dst, ib), proto, dport);
	field("\"verdict\":\"%s\"", allowed ? "allow" : "deny");
	if (!allowed && why != NULL) {
		field("\"why\":\"%s\"", why);
	}
	end();
}

void audit_reload(const char *what, int ok, int count)
{
	if (out == NULL) {
		return;
	}

	begin("reload");
	field("\"what\":\"%s\",\"ok\":%s", what, ok ? "true" : "false");
	if (ok) {
		field("\"count\":%d", count);
	}
	end();
}

void audit_enrolled(const uint8_t id[DEVICE_ID_LEN], struct in_addr tun_ip,
		const struct sockaddr_in *src, const char *label)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];

	if (out == NULL) {
		return;
	}

	begin("enrolled");
	field("\"device\":\"%s\"", device_id_str(id, ids));
	field("\"tunnel_ip\":\"%s\"", ip_str(tun_ip, ib));
	field("\"endpoint\":\"%s:%u\"", ip_str(src->sin_addr, ib), ntohs(src->sin_port));
	/* 이름은 enroll.c 가 받는 글자를 정해 둔 값이라 그대로 적어도 JSON 이 깨지지 않는다. */
	field("\"label\":\"%s\"", label);
	end();
}

void audit_login(const peer_t *peer, int status)
{
	int g;

	if (out == NULL) {
		return;
	}

	/* 실패했을 때 session_fields 의 "user" 는 그 전에 로그인해 있던 사용자다. 실패한 토큰이
	 * 누구의 것이라고 말했는지는 적지 않는다 — 서명이 맞지 않은 토큰의 이름은 아무나 쓸 수
	 * 있는 값이다. */
	begin("login");
	session_fields(peer);
	field("\"result\":\"%s\"", idp_status_name(status));
	if (status == LOGIN_OK) {
		field("\"expires\":%lld", (long long)peer->user.expires);
		field("\"groups\":[");
		for (g = 0; g < peer->user.n_groups; g++) {
			fprintf(out, "%s\"%s\"", g == 0 ? "" : ",", peer->user.groups[g]);
		}
		fputc(']', out);
	}
	end();
}

void audit_logout(const peer_t *peer, const char *reason)
{
	if (out == NULL) {
		return;
	}

	begin("logout");
	session_fields(peer);
	field("\"reason\":\"%s\"", reason);
	end();
}
