#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "common.h"
#include "device.h"

static device_t devices[MAX_DEVICES];
static int ndevices;

/* 파일은 여기에 먼저 읽고, 끝까지 문제없을 때만 위의 표로 옮긴다. 서버가 도는 중에
 * 다시 읽다가 중간 줄에서 실패했을 때 쓰던 목록이 반쯤 바뀐 채 남으면 안 된다. */
static device_t staged[MAX_DEVICES];
static int nstaged;

/* 기기를 ID 와 터널 주소로 찾는 색인. 핸드셰이크, keepalive, 커넥터를 지나는 패킷마다
 * 기기를 찾으므로 목록을 훑지 않는다. 버킷마다 그 버킷에 든 자리를 next 로 잇는다
 * (-1 이 끝). 목록과 똑같이 읽는 동안에는 staged 쪽에 만들고, 끝까지 문제없을 때 옮긴다.
 * 읽는 동안의 색인은 같은 ID 나 같은 터널 주소가 두 번 나오는 것을 찾는 데도 쓴다. */
#define DEVICE_BUCKETS (MAX_DEVICES * 2)
_Static_assert((DEVICE_BUCKETS & (DEVICE_BUCKETS - 1)) == 0, "DEVICE_BUCKETS must be a power of two");

typedef struct device_index {
	int32_t id_head[DEVICE_BUCKETS], id_next[MAX_DEVICES];
	int32_t ip_head[DEVICE_BUCKETS], ip_next[MAX_DEVICES];
} device_index_t;

static device_index_t index_live, index_staged;

/* 커넥터인 기기의 자리. 클라이언트가 보낸 패킷마다 그 목적지를 맡은 커넥터를 찾는데,
 * 커넥터는 기기 중 몇 대뿐이다. */
static int32_t connectors[MAX_DEVICES];
static int nconnectors;

static uint32_t mix(uint32_t v)
{
	/* 터널 주소는 이어진 번호라 그대로 쓰면 아래 bit 만 다르다. 곱해서 섞는다 (Knuth). */
	return ((v * 2654435761u) >> 7) & (DEVICE_BUCKETS - 1);
}

static uint32_t id_bucket(const uint8_t id[DEVICE_ID_LEN])
{
	uint32_t v;

	memcpy(&v, id, sizeof(v));
	return mix(v);
}

static uint32_t ip_bucket(struct in_addr a)
{
	return mix(ntohl(a.s_addr));
}

static void index_clear(device_index_t *x)
{
	/* 0xff 바이트로 채우면 int32_t 가 모두 -1 (빈 사슬)이 된다. */
	memset(x, 0xff, sizeof(*x));
}

static int32_t index_find_id(const device_index_t *x, const device_t *table, const uint8_t id[DEVICE_ID_LEN])
{
	int32_t i;

	for (i = x->id_head[id_bucket(id)]; i >= 0; i = x->id_next[i]) {
		if (memcmp(table[i].id, id, DEVICE_ID_LEN) == 0) {
			return i;
		}
	}
	return -1;
}

static int32_t index_find_ip(const device_index_t *x, const device_t *table, struct in_addr ip)
{
	int32_t i;

	for (i = x->ip_head[ip_bucket(ip)]; i >= 0; i = x->ip_next[i]) {
		if (table[i].tun_ip.s_addr == ip.s_addr) {
			return i;
		}
	}
	return -1;
}

static void index_add(device_index_t *x, const device_t *table, int32_t slot)
{
	uint32_t b = id_bucket(table[slot].id);

	x->id_next[slot] = x->id_head[b];
	x->id_head[b] = slot;

	b = ip_bucket(table[slot].tun_ip);
	x->ip_next[slot] = x->ip_head[b];
	x->ip_head[b] = slot;
}

void device_init(void)
{
	memset(devices, 0, sizeof(devices));
	ndevices = 0;
	index_clear(&index_live);
	nconnectors = 0;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* 정확히 len 바이트 분량의 16진 문자열만 받는다. 짧거나 길면 실패. */
static int parse_hex(const char *s, uint8_t *out, size_t len)
{
	size_t i;
	int hi, lo;

	if (strlen(s) != len * 2) {
		return -1;
	}

	for (i = 0; i < len; i++) {
		hi = hex_val(s[i * 2]);
		lo = hex_val(s[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)(hi << 4 | lo);
	}

	return 0;
}

int device_posture_ok(const device_t *dev, const posture_report_t *posture)
{
	return posture_req_ok(&dev->require, posture);
}

const char *device_id_str(const uint8_t id[DEVICE_ID_LEN], char *dst)
{
	int i;

	for (i = 0; i < DEVICE_ID_LEN; i++) {
		sprintf(dst + i * 2, "%02x", id[i]);
	}

	return dst;
}

static uint32_t prefix_mask(uint8_t len)
{
	return len == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - len));
}

/* connector=a.b.c.d/n. /0 은 받지 않는다 — 모든 목적지를 한 커넥터로 보내라는 뜻이 되고,
 * 그건 인터넷으로 나가는 길을 커넥터에 맡기는 일이다. 주소의 호스트 부분이 0 이 아니면
 * 받지 않는다. 10.101.0.7/16 처럼 적은 사람이 무엇을 뜻했는지 짐작하지 않는다. */
static int parse_connector(const char *s, device_t *d)
{
	char buf[32];
	char *slash, *end;
	struct in_addr addr;
	long bits;

	if (strlen(s) >= sizeof(buf) || d->n_connector >= CONNECTOR_MAX_NETS) {
		return -1;
	}
	strcpy(buf, s);

	slash = strchr(buf, '/');
	if (slash == NULL) {
		return -1;
	}
	*slash = '\0';
	bits = strtol(slash + 1, &end, 10);
	if (*end != '\0' || bits < 1 || bits > 32 || inet_pton(AF_INET, buf, &addr) != 1) {
		return -1;
	}
	if ((addr.s_addr & ~prefix_mask((uint8_t)bits)) != 0) {
		return -1;
	}

	d->connector[d->n_connector].addr = addr.s_addr;
	d->connector[d->n_connector].prefix_len = (uint8_t)bits;
	d->n_connector++;

	return 0;
}

int device_token_parse(const char *tok, device_t *d)
{
	int r;

	if (strncmp(tok, "connector=", 10) == 0) {
		return parse_connector(tok + 10, d);
	}
	r = tag_parse(tok, &d->tags);
	if (r <= 0) {
		return r;
	}

	return posture_req_parse(tok, &d->require);
}

int device_connector_has(const device_t *dev, struct in_addr dst)
{
	int k;

	for (k = 0; k < dev->n_connector; k++) {
		if ((dst.s_addr & prefix_mask(dev->connector[k].prefix_len)) == dev->connector[k].addr) {
			return 1;
		}
	}

	return 0;
}

const device_t *device_connector_for(struct in_addr dst)
{
	const device_t *best = NULL;
	int best_len = -1;
	int i, k;

	for (i = 0; i < nconnectors; i++) {
		const device_t *d = &devices[connectors[i]];

		for (k = 0; k < d->n_connector; k++) {
			const net_route_t *r = &d->connector[k];

			if ((dst.s_addr & prefix_mask(r->prefix_len)) == r->addr && r->prefix_len > best_len) {
				best = d;
				best_len = r->prefix_len;
			}
		}
	}

	return best;
}

int device_load(const char *path)
{
	FILE *fp;
	struct stat st;
	char line[CONF_LINE_MAX];
	char s_id[80], s_key[80], s_ip[32];
	char *tok;
	int lineno = 0;
	int used;
	int i;

	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen device file");
		return -1;
	}

	/* 이 파일에는 모든 기기의 키가 평문으로 들어 있다. 다른 계정이 읽을 수 있게
	 * 돼 있으면 읽지 않는다. ssh 가 권한이 열린 개인키를 거부하는 것과 같은 이유다.
	 * 경로가 아니라 이미 연 파일에 fstat 을 한다 — 검사한 파일과 읽는 파일이
	 * 같다는 것이 보장된다. */
	if (fstat(fileno(fp), &st) < 0) {
		perror("fstat device file");
		fclose(fp);
		return -1;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		fprintf(stderr, "device: %s is accessible by group/others (mode %04o), run: chmod 600 %s\n",
				path, (unsigned)(st.st_mode & 07777), path);
		fclose(fp);
		return -1;
	}

	nstaged = 0;
	index_clear(&index_staged);

	while (fgets(line, sizeof(line), fp) != NULL) {
		device_t *d;
		char *hash;

		lineno++;
		if (!CONF_LINE_WHOLE(line, fp)) {
			fprintf(stderr, "device: line %d: longer than %d characters\n", lineno, CONF_LINE_MAX - 2);
			goto fail;
		}

		hash = strchr(line, '#');
		if (hash != NULL) {
			*hash = '\0';
		}

		/* 빈 줄과 주석만 있는 줄 */
		if (sscanf(line, "%79s", s_id) != 1) {
			continue;
		}

		if (sscanf(line, "%79s %79s %31s%n", s_id, s_key, s_ip, &used) != 3) {
			fprintf(stderr, "device: line %d: expected <id> <key> <tunnel-ip> [requirements]\n", lineno);
			goto fail;
		}

		if (nstaged >= MAX_DEVICES) {
			fprintf(stderr, "device: too many devices (max %d)\n", MAX_DEVICES);
			goto fail;
		}

		d = &staged[nstaged];
		memset(d, 0, sizeof(*d));

		/* 터널 IP 뒤에 남은 단어들이 포스처 조건과 커넥터의 대역이다. */
		for (tok = strtok(line + used, " \t\r\n"); tok != NULL; tok = strtok(NULL, " \t\r\n")) {
			if (device_token_parse(tok, d) < 0) {
				fprintf(stderr, "device: line %d: unknown requirement '%s'\n", lineno, tok);
				goto fail;
			}
		}

		if (parse_hex(s_id, d->id, DEVICE_ID_LEN) < 0) {
			fprintf(stderr, "device: line %d: id must be %d hex digits\n", lineno, DEVICE_ID_LEN * 2);
			goto fail;
		}
		if (parse_hex(s_key, d->key, AUTH_KEY_LEN) < 0) {
			fprintf(stderr, "device: line %d: key must be %d hex digits\n", lineno, AUTH_KEY_LEN * 2);
			goto fail;
		}
		if (inet_pton(AF_INET, s_ip, &d->tun_ip) != 1) {
			fprintf(stderr, "device: line %d: bad tunnel ip '%s'\n", lineno, s_ip);
			goto fail;
		}

		/* 같은 ID 가 두 번 나오면 어느 키가 맞는지 정할 수 없고, 같은 터널 IP 를 두
		 * 기기에 주면 서로의 세션을 밀어낸다. 조용히 한쪽을 고르지 않고 거부한다. */
		if (index_find_id(&index_staged, staged, d->id) >= 0) {
			fprintf(stderr, "device: line %d: duplicate id\n", lineno);
			goto fail;
		}
		if (index_find_ip(&index_staged, staged, d->tun_ip) >= 0) {
			fprintf(stderr, "device: line %d: tunnel ip %s already assigned\n", lineno, s_ip);
			goto fail;
		}

		index_add(&index_staged, staged, nstaged);
		nstaged++;
	}

	fclose(fp);

	memcpy(devices, staged, sizeof(devices));
	ndevices = nstaged;
	index_live = index_staged;

	nconnectors = 0;
	for (i = 0; i < ndevices; i++) {
		if (devices[i].n_connector != 0) {
			connectors[nconnectors++] = i;
		}
	}

	return ndevices;

fail:
	fclose(fp);
	return -1;
}

device_t *device_find(const uint8_t id[DEVICE_ID_LEN])
{
	int32_t i = index_find_id(&index_live, devices, id);

	return i < 0 ? NULL : &devices[i];
}

int device_count(void)
{
	return ndevices;
}

/* 키는 찍지 않는다. 로그는 설정 파일보다 넓게 읽힌다. */
void device_dump(void)
{
	char ids[DEVICE_ID_STRLEN];
	char ib[INET_ADDRSTRLEN];
	int i, k;

	printf("--- devices (%d) ---\n", ndevices);
	for (i = 0; i < ndevices; i++) {
		printf("[%d] %s -> %s  require: firewall=%s antivirus=%s min-build=%u", i,
				device_id_str(devices[i].id, ids), ip_str(devices[i].tun_ip, ib),
				devices[i].require.need_firewall ? "on" : "-",
				devices[i].require.need_antivirus ? "on" : "-",
				devices[i].require.min_build);
		for (k = 0; k < devices[i].n_connector; k++) {
			struct in_addr a = { .s_addr = devices[i].connector[k].addr };
			printf("%s%s/%u", k == 0 ? "  connector: " : " ", ip_str(a, ib),
					devices[i].connector[k].prefix_len);
		}
		for (k = 0; k < devices[i].tags.n; k++) {
			printf("%s%s", k == 0 ? "  tags: " : " ", devices[i].tags.name[k]);
		}
		printf("\n");
	}
}

/* 그 터널 주소를 가진 기기. 없으면 NULL. */
device_t *device_find_ip(struct in_addr tun_ip)
{
	int32_t i = index_find_ip(&index_live, devices, tun_ip);

	return i < 0 ? NULL : &devices[i];
}
