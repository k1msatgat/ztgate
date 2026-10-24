#include <stdlib.h>
#include <string.h>

#include "policy.h"

/* 모르는 단어는 무시하지 않고 실패시킨다. "firewal=on" 같은 오타가 조용히 지나가면
 * 관리자는 걸었다고 믿는 정책이 실제로는 걸리지 않는다. */
int posture_req_parse(const char *tok, posture_req_t *req)
{
	char *end;
	unsigned long v;

	if (strcmp(tok, "firewall=on") == 0) {
		req->need_firewall = 1;
		return 0;
	}
	if (strcmp(tok, "antivirus=on") == 0) {
		req->need_antivirus = 1;
		return 0;
	}
	if (strcmp(tok, "disk=on") == 0) {
		req->need_disk = 1;
		return 0;
	}
	if (strncmp(tok, "min-build=", 10) == 0 && tok[10] != '\0') {
		v = strtoul(tok + 10, &end, 10);
		if (*end != '\0' || v > 0xFFFFFFFFul) {
			return -1;
		}
		req->min_build = (uint32_t)v;
		return 0;
	}

	return -1;
}

/* "모름"은 통과가 아니다. 클라이언트가 값을 읽지 못해 POSTURE_STATE_UNKNOWN 을
 * 보냈을 때 통과시키면, 조회를 실패하게 만드는 것만으로 정책을 피할 수 있다.
 * os_build 도 읽지 못하면 0 이라 min-build 조건에 저절로 걸린다. */
int posture_req_ok(const posture_req_t *req, const posture_report_t *posture)
{
	if (req->need_firewall && posture->firewall != POSTURE_STATE_ON) {
		return 0;
	}
	if (req->need_antivirus && posture->antivirus != POSTURE_STATE_ON) {
		return 0;
	}
	if (req->need_disk && posture->disk != POSTURE_STATE_ON) {
		return 0;
	}
	if (posture->os_build < req->min_build) {
		return 0;
	}

	return 1;
}

int posture_req_empty(const posture_req_t *req)
{
	return !req->need_firewall && !req->need_antivirus && !req->need_disk && req->min_build == 0;
}

int user_name_valid(const char *name)
{
	size_t i, n = strlen(name);
	char c;

	if (n == 0 || n >= USER_NAME_MAX) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		c = name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
				c == '.' || c == '_' || c == '@' || c == '+' || c == '-' || c == '/')) {
			return 0;
		}
	}

	return 1;
}

int user_req_parse(const char *tok, user_req_t *req)
{
	const char *name;
	int is_group;

	if (strncmp(tok, "user=", 5) == 0) {
		name = tok + 5;
		is_group = 0;
	}
	else if (strncmp(tok, "group=", 6) == 0) {
		name = tok + 6;
		is_group = 1;
	}
	else {
		return 1;
	}

	if (!user_name_valid(name) || req->n >= USER_REQ_MAX) {
		return -1;
	}

	req->is_group[req->n] = (uint8_t)is_group;
	strcpy(req->who[req->n], name);
	req->n++;

	return 0;
}

/* 만료는 패킷마다 여기서 본다. keepalive(10초)에서만 보면 토큰이 끝난 뒤에도 최대 10초
 * 동안 그 사용자의 권한으로 패킷이 지나간다. 벽시계를 읽는 것(vDSO)은 조건이 걸린 규칙에
 * 닿았을 때만 하므로 조건 없는 정책의 데이터 경로에는 비용이 없다. */
int user_req_ok(const user_req_t *req, const user_identity_t *who, int64_t now)
{
	int i, g;

	if (req->n == 0) {
		return 1;
	}
	if (who == NULL || who->expires <= now) {
		return 0;
	}

	for (i = 0; i < req->n; i++) {
		if (!req->is_group[i]) {
			if (strcmp(req->who[i], who->name) == 0) {
				return 1;
			}
			continue;
		}
		for (g = 0; g < who->n_groups; g++) {
			if (strcmp(req->who[i], who->groups[g]) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

int user_req_empty(const user_req_t *req)
{
	return req->n == 0;
}

static int tag_name_valid(const char *s)
{
	size_t i, n = strlen(s);

	if (n == 0 || n > TAG_NAME_MAX) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-')) {
			return 0;
		}
	}

	return 1;
}

int tag_parse(const char *tok, tag_set_t *t)
{
	const char *name;
	int i;

	if (strncmp(tok, "tag=", 4) != 0) {
		return 1;
	}
	name = tok + 4;
	if (!tag_name_valid(name)) {
		return -1;
	}
	for (i = 0; i < t->n; i++) {
		if (strcmp(t->name[i], name) == 0) {
			return 0;
		}
	}
	if (t->n >= TAG_MAX) {
		return -1;
	}
	strcpy(t->name[t->n++], name);

	return 0;
}

int tag_match(const tag_set_t *want, const tag_set_t *have)
{
	int i, k;

	if (want->n == 0) {
		return 1;
	}
	if (have == NULL) {
		return 0;
	}
	for (i = 0; i < want->n; i++) {
		for (k = 0; k < have->n; k++) {
			if (strcmp(want->name[i], have->name[k]) == 0) {
				return 1;
			}
		}
	}

	return 0;
}
