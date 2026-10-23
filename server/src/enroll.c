#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "crypt.h"
#include "enroll.h"
#include "secure.h"
#include "serverkey.h"

#define LABEL_MAX 32
#define REQS_MAX 256

typedef struct pending {
	device_t dev;			/* 맨 앞에 둔다. enroll_find 가 내준 포인터로 이 줄을 되찾는다 */
	time_t expires;			/* 벽시계. 관리자가 "10분 뒤"라고 정한 시각이다 */
	char reqs[REQS_MAX];		/* 포스처 조건을 적힌 그대로. 기기 목록에 옮겨 적는다 */
	char label[LABEL_MAX + 1];
} pending_t;

static pending_t table[MAX_PENDING];
static int count;

static pending_t staged[MAX_PENDING];
static int nstaged;

static char file_path[256];

void enroll_init(void)
{
	memset(table, 0, sizeof(table));
	count = 0;
}

int enroll_count(void)
{
	return count;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

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

static void hex_str(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = digits[in[i] >> 4];
		out[i * 2 + 1] = digits[in[i] & 0x0F];
	}
	out[len * 2] = '\0';
}

/* 이름은 기기 목록의 줄 끝 주석과 감사 로그에 그대로 들어간다. '#' 나 따옴표, 줄바꿈이
 * 섞이면 두 파일의 형식이 깨지므로 받는 글자를 정해 둔다. */
static int label_ok(const char *s)
{
	size_t n = strlen(s);
	size_t i;

	if (n > LABEL_MAX) {
		return 0;
	}

	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
					c == ' ' || c == '_' || c == '.' || c == '-')) {
			return 0;
		}
	}

	return 1;
}

static void trim(char *s)
{
	size_t n = strlen(s);
	char *p = s;

	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
		s[--n] = '\0';
	}
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	memmove(s, p, strlen(p) + 1);
}

int enroll_load(const char *path)
{
	FILE *fp;
	struct stat st;
	char line[CONF_LINE_MAX];
	char s_id[80], s_key[80], s_ip[32];
	char reqs_copy[REQS_MAX];
	long long expires;
	char *hash;
	char *tok;
	int lineno = 0;
	int used;
	int i;

	if (strlen(path) >= sizeof(file_path)) {
		fprintf(stderr, "enroll: path too long\n");
		return -1;
	}
	strcpy(file_path, path);

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			/* 코드를 만든 적이 없으면 파일도 없다. 틀린 것이 아니다. */
			enroll_init();
			return 0;
		}
		perror("fopen enroll file");
		return -1;
	}

	/* 여기 적힌 키로 등록용 세션을 열 수 있다. 기기 목록과 같은 기준으로 본다. */
	if (fstat(fileno(fp), &st) < 0 || (st.st_mode & (S_IRWXG | S_IRWXO))) {
		fprintf(stderr, "enroll: %s must not be accessible by group/others, run: chmod 600 %s\n",
				path, path);
		fclose(fp);
		return -1;
	}

	nstaged = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		pending_t *p;

		lineno++;
		if (!CONF_LINE_WHOLE(line, fp)) {
			fprintf(stderr, "enroll: line %d: longer than %d characters\n", lineno, CONF_LINE_MAX - 2);
			goto fail;
		}

		if (nstaged < MAX_PENDING) {
			memset(&staged[nstaged], 0, sizeof(staged[nstaged]));
		}

		hash = strchr(line, '#');
		if (hash != NULL) {
			*hash = '\0';
			trim(hash + 1);
		}

		if (sscanf(line, "%79s", s_id) != 1) {
			continue;
		}

		if (sscanf(line, "%79s %79s %31s %lld%n", s_id, s_key, s_ip, &expires, &used) != 4) {
			fprintf(stderr, "enroll: line %d: expected <id> <key> <tunnel-ip> <expires> [requirements]\n", lineno);
			goto fail;
		}

		if (nstaged >= MAX_PENDING) {
			fprintf(stderr, "enroll: too many pending enrollments (max %d)\n", MAX_PENDING);
			goto fail;
		}
		p = &staged[nstaged];

		if (hash != NULL) {
			if (!label_ok(hash + 1)) {
				fprintf(stderr, "enroll: line %d: label has characters that are not allowed\n", lineno);
				goto fail;
			}
			strcpy(p->label, hash + 1);
		}

		trim(line + used);
		if (strlen(line + used) >= REQS_MAX) {
			fprintf(stderr, "enroll: line %d: requirements too long\n", lineno);
			goto fail;
		}
		strcpy(p->reqs, line + used);

		/* 조건은 지금 검사해 둔다. 여기서 받아 준 오타는 등록이 끝난 뒤 기기 목록에
		 * 옮겨 적히고, 그때는 서버가 그 목록을 통째로 거부한다. */
		strcpy(reqs_copy, p->reqs);
		for (tok = strtok(reqs_copy, " \t"); tok != NULL; tok = strtok(NULL, " \t")) {
			if (device_token_parse(tok, &p->dev) < 0) {
				fprintf(stderr, "enroll: line %d: unknown requirement '%s'\n", lineno, tok);
				goto fail;
			}
		}

		if (parse_hex(s_id, p->dev.id, DEVICE_ID_LEN) < 0 ||
				parse_hex(s_key, p->dev.key, AUTH_KEY_LEN) < 0) {
			fprintf(stderr, "enroll: line %d: id must be %d and key %d hex digits\n",
					lineno, DEVICE_ID_LEN * 2, AUTH_KEY_LEN * 2);
			goto fail;
		}
		if (inet_pton(AF_INET, s_ip, &p->dev.tun_ip) != 1) {
			fprintf(stderr, "enroll: line %d: bad tunnel ip '%s'\n", lineno, s_ip);
			goto fail;
		}
		p->expires = (time_t)expires;

		for (i = 0; i < nstaged; i++) {
			if (memcmp(staged[i].dev.id, p->dev.id, DEVICE_ID_LEN) == 0 ||
					staged[i].dev.tun_ip.s_addr == p->dev.tun_ip.s_addr) {
				fprintf(stderr, "enroll: line %d: duplicate id or tunnel ip\n", lineno);
				goto fail;
			}
		}

		nstaged++;
	}

	fclose(fp);

	memcpy(table, staged, sizeof(table));
	count = nstaged;

	return count;

fail:
	fclose(fp);
	return -1;
}

device_t *enroll_find(const uint8_t id[DEVICE_ID_LEN])
{
	time_t now = time(NULL);
	int i;

	for (i = 0; i < count; i++) {
		if (memcmp(table[i].dev.id, id, DEVICE_ID_LEN) == 0) {
			return table[i].expires > now ? &table[i].dev : NULL;
		}
	}

	return NULL;
}

const char *enroll_label(const device_t *pending)
{
	return ((const pending_t *)pending)->label;
}

/* path 옆에 새 파일을 쓰고 이름을 바꾼다. 쓰다가 죽어도 반쯤 쓰인 파일이 남지 않고,
 * 그 사이에 다른 쪽이 읽어도 예전 것이나 새것 중 하나를 온전히 본다. */
static FILE *replace_begin(const char *path, char *tmp, size_t tmp_len)
{
	FILE *fp;
	int fd;

	if ((size_t)snprintf(tmp, tmp_len, "%s.tmp.%ld", path, (long)getpid()) >= tmp_len) {
		return NULL;
	}

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		perror(tmp);
		return NULL;
	}

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		unlink(tmp);
	}

	return fp;
}

static int replace_end(FILE *fp, const char *tmp, const char *path)
{
	/* 이름을 바꾸기 전에 디스크에 내린다. 순서가 반대면 전원이 나갔을 때 이름은 새
	 * 파일을 가리키는데 내용은 비어 있을 수 있다. */
	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
		fclose(fp);
		unlink(tmp);
		return -1;
	}
	fclose(fp);

	if (rename(tmp, path) != 0) {
		perror("rename");
		unlink(tmp);
		return -1;
	}

	return 0;
}

/* 기기 목록 끝에 한 줄을 더한다. 있던 내용은 그대로 옮긴다. */
static int device_file_append(const char *path, const char *entry)
{
	char tmp[300];
	char buf[4096];
	FILE *in;
	FILE *out;
	size_t n;
	int last = '\n';

	out = replace_begin(path, tmp, sizeof(tmp));
	if (out == NULL) {
		return -1;
	}

	in = fopen(path, "r");
	if (in != NULL) {
		while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
			fwrite(buf, 1, n, out);
			last = buf[n - 1];
		}
		fclose(in);
	}
	crypt_wipe(buf, sizeof(buf));	/* 다른 기기들의 키가 지나갔다 */

	if (last != '\n') {
		fputc('\n', out);
	}
	fputs(entry, out);

	return replace_end(out, tmp, path);
}

/* 등록 대기 파일에서 쓰인 코드(id)의 줄과 만료된 줄을 뺀다. 이 서버가 읽어 둔 표가 아니라
 * 지금의 파일에서 뺀다 — 마지막으로 다시 읽은 뒤에 관리 도구가 더한 코드가 있을 수 있고, 표로
 * 다시 쓰면 그 코드가 사라진다. 주석과 형식이 틀린 줄은 그대로 옮긴다 (판단은 다시 읽을 때). */
static int enroll_file_drop(const char *id_hex)
{
	char line[512], first[80];
	char tmp[300];
	time_t now = time(NULL);
	long long expires;
	FILE *in, *out;

	in = fopen(file_path, "r");
	if (in == NULL) {
		return errno == ENOENT ? 0 : -1;
	}

	out = replace_begin(file_path, tmp, sizeof(tmp));
	if (out == NULL) {
		fclose(in);
		return -1;
	}

	while (fgets(line, sizeof(line), in) != NULL) {
		if (sscanf(line, "%79s %*s %*s %lld", first, &expires) == 2 && first[0] != '#' &&
				(strcmp(first, id_hex) == 0 || expires <= now)) {
			continue;
		}
		fputs(line, out);
	}
	crypt_wipe(line, sizeof(line));	/* 다른 코드의 키가 지나갔다 */
	fclose(in);

	return replace_end(out, tmp, file_path);
}

/* ---- 서버와 관리 도구 사이의 잠금 --------------------------------------------
 *
 * 기기 목록과 등록 대기 목록은 서버와 관리 도구(ztgate_ctl)가 함께 고친다. 둘 다 읽고 →
 * 고치고 → 새 파일로 바꾸므로, 한쪽이 읽고 쓰는 사이에 다른 쪽이 끼면 먼저 쓴 쪽이 고친
 * 것이 사라진다 (등록된 기기가 목록에서 빠지거나, 방금 만든 코드가 지워진다). 두 쪽 모두
 * 기기 목록과 같은 디렉터리의 .ztgate.lock 에 flock 을 잡고 고친다. 관리 도구는 Node 에
 * flock 이 없어 flock(1) 로 같은 파일을 잡는다. 프로세스가 죽으면 커널이 풀어 준다.
 *
 * 서버는 패킷을 나르는 루프라 오래 기다리지 않는다. LOCK_WAIT_MSEC 안에 못 잡으면 이번
 * 등록은 실패로 답한다. 관리 도구가 잠그는 동안은 파일 하나를 읽고 쓰는 동안뿐이다. */
#define LOCK_WAIT_MSEC 200

static int config_lock(const char *device_path)
{
	char path[300];
	const char *slash = strrchr(device_path, '/');
	struct timespec pause = { 0, 5 * 1000 * 1000 };
	int fd;
	int i;

	if (slash == NULL) {
		snprintf(path, sizeof(path), ".ztgate.lock");
	}
	else if ((size_t)snprintf(path, sizeof(path), "%.*s/.ztgate.lock",
				(int)(slash - device_path), device_path) >= sizeof(path)) {
		return -1;
	}

	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		perror(path);
		return -1;
	}

	for (i = 0; i < LOCK_WAIT_MSEC / 5; i++) {
		if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
			return fd;
		}
		if (errno != EWOULDBLOCK && errno != EINTR) {
			break;
		}
		nanosleep(&pause, NULL);
	}

	fprintf(stderr, "enroll: %s is held by another writer\n", path);
	close(fd);
	return -1;
}

/* 닫으면 풀린다. */
static void config_unlock(int fd)
{
	close(fd);
}

int enroll_complete(device_t *pending, const uint8_t id[DEVICE_ID_LEN],
		const uint8_t pub[VPN_PUB_LEN_WIRE], const char *device_path)
{
	pending_t *p = (pending_t *)pending;
	char s_id[DEVICE_ID_LEN * 2 + 1], s_key[5 + VPN_PUB_LEN_WIRE * 2 + 1];
	uint8_t probe[AUTH_KEY_LEN];
	char ib[INET_ADDRSTRLEN];
	char entry[CONF_LINE_MAX];
	char code_id[DEVICE_ID_LEN * 2 + 1];
	struct in_addr tun_ip = p->dev.tun_ip;
	int idx = (int)(p - table);
	int lock;
	int ret;

	hex_str(id, DEVICE_ID_LEN, s_id);
	memcpy(s_key, "p256:", 5);
	hex_str(pub, VPN_PUB_LEN_WIRE, s_key + 5);
	hex_str(p->dev.id, DEVICE_ID_LEN, code_id);

	/* 곡선 위의 점이 아닌 공개키를 적으면 그 목록은 다음부터 읽히지 않는다 (device.c 가 거부한다).
	 * 코드를 가진 쪽이 아무 바이트나 보내 기기 목록 전체를 막지 못하게, 적기 전에 키를 뽑아 본다. */
	if (serverkey() == NULL ||
			secure_static_key(serverkey(), pub, pub, serverkey_pub(), probe) < 0) {
		crypt_wipe(probe, sizeof(probe));
		return -1;
	}
	crypt_wipe(probe, sizeof(probe));

	/* device.c 가 한 줄을 CONF_LINE_MAX 까지 읽는다. 넘치면 그 목록은 다음에 읽히지 않는다. */
	if ((size_t)snprintf(entry, sizeof(entry), "%s %s %s%s%s%s%s\n", s_id, s_key,
				ip_str(tun_ip, ib),
				p->reqs[0] ? " " : "", p->reqs,
				p->label[0] ? "  # " : "", p->label) >= sizeof(entry) - 1) {
		ret = -1;
		goto out;
	}

	lock = config_lock(device_path);
	if (lock < 0) {
		ret = -1;
		goto out;
	}

	/* 잠근 뒤에 지금의 기기 목록을 다시 읽고 겹치는지 본다. 이 서버가 마지막으로 읽은 뒤에
	 * 관리 도구가 같은 ID 나 같은 터널 주소의 기기를 올렸을 수 있다. 겹친 채로 더하면 그
	 * 목록은 다음부터 읽히지 않는다 (device_load 가 중복을 거부한다). */
	if (device_load(device_path) < 0) {
		ret = -1;
	}
	else if (device_find(id) != NULL || device_find_ip(tun_ip) != NULL) {
		ret = ENROLL_COMPLETE_CONFLICT;
	}
	else {
		ret = device_file_append(device_path, entry);
		if (ret == 0 && enroll_file_drop(code_id) < 0) {
			fprintf(stderr, "enroll: could not rewrite %s; the used code is still listed there\n", file_path);
		}
	}
	config_unlock(lock);

out:
	crypt_wipe(s_key, sizeof(s_key));
	crypt_wipe(entry, sizeof(entry));

	if (ret < 0) {
		return ret;
	}

	/* 기기는 목록에 올랐다. 이제 코드는 쓰인 것이다 — 표에서도 지운다. 위에서 파일의
	 * 줄을 지우지 못했어도 이 서버는 그 코드를 다시 받지 않는다. 파일에 줄이 남아 다음에
	 * 다시 읽히더라도, 같은 터널 주소가 이미 기기 목록에 있어 쓸 수 없다. */
	crypt_wipe(&table[idx], sizeof(table[idx]));
	memmove(&table[idx], &table[idx + 1], sizeof(table[0]) * (size_t)(count - idx - 1));
	count--;

	return 0;
}
