#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "crypt.h"
#include "identity.h"

/* id(32) + 공백 + key(64) + 줄바꿈. 서버 공개키가 있으면 줄바꿈 앞에 공백 + 128 이 더 붙는다. */
#define IDENTITY_LINE_LEN	(DEVICE_ID_LEN * 2 + 1 + AUTH_KEY_LEN * 2 + 1)
#define IDENTITY_PUB_OFF	(DEVICE_ID_LEN * 2 + 1 + AUTH_KEY_LEN * 2)
#define IDENTITY_LINE_MAX	(IDENTITY_LINE_LEN + 1 + VPN_PUB_LEN_WIRE * 2)
#define IDENTITY_DIR_MODE	0700
#define IDENTITY_FILE_MODE	0600

static int hex_decode(const char *s, uint8_t *out, size_t len)
{
	unsigned int v;
	size_t i;

	for (i = 0; i < len; i++) {
		if (sscanf(s + i * 2, "%2x", &v) != 1) {
			return -1;
		}
		out[i] = (uint8_t)v;
	}

	return 0;
}

static void hex_encode(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = digits[in[i] >> 4];
		out[i * 2 + 1] = digits[in[i] & 0x0F];
	}
}

int identity_load(const char *path, identity_t *out)
{
	char line[IDENTITY_LINE_MAX + 1];
	struct stat st;
	ssize_t n;
	int fd;
	int ret = IDENTITY_ERROR;

	/* 링크를 따라가지 않는다. root 로 도는 프로그램이 남이 걸어 둔 링크를 따라가면
	 * 그 사람이 정한 파일을 신원으로 읽는다. */
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT) {
			return IDENTITY_NOT_ENROLLED;
		}
		perror(path);
		return IDENTITY_ERROR;
	}

	/* 키가 들어 있다. 다른 사람이 읽을 수 있거나 다른 사람의 파일이면 쓰지 않는다 —
	 * 서버가 기기 목록을 다루는 방식과 같다. */
	if (fstat(fd, &st) < 0) {
		perror(path);
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
		fprintf(stderr, "%s: must be a regular file owned by this user with mode 600\n", path);
		goto out;
	}

	n = read(fd, line, sizeof(line) - 1);
	if (n < IDENTITY_LINE_LEN - 1) {
		fprintf(stderr, "%s: too short\n", path);
		goto out;
	}
	line[n] = '\0';

	if (line[DEVICE_ID_LEN * 2] != ' ' ||
			hex_decode(line, out->id, DEVICE_ID_LEN) < 0 ||
			hex_decode(line + DEVICE_ID_LEN * 2 + 1, out->key, AUTH_KEY_LEN) < 0) {
		fprintf(stderr, "%s: expected \"<id hex> <key hex>\"\n", path);
		goto out;
	}
	out->has_server_pub = 0;
	if (line[IDENTITY_PUB_OFF] == ' ') {
		if (n < IDENTITY_LINE_MAX - 1 ||
				hex_decode(line + IDENTITY_PUB_OFF + 1, out->server_pub, VPN_PUB_LEN_WIRE) < 0) {
			fprintf(stderr, "%s: the third field must be the server's public key (128 hex)\n", path);
			goto out;
		}
		out->has_server_pub = 1;
	}
	ret = IDENTITY_OK;

out:
	crypt_wipe(line, sizeof(line));
	close(fd);

	return ret;
}

int identity_generate(identity_t *out)
{
	if (crypt_random(out->id, sizeof(out->id)) < 0 ||
			crypt_random(out->key, sizeof(out->key)) < 0) {
		return IDENTITY_ERROR;
	}
	out->has_server_pub = 0;

	return IDENTITY_OK;
}

/* 디렉터리 항목(이름 바꾸기)까지 디스크에 내려 둔다. 안 하면 전원이 나갔을 때 새 파일의
 * 내용은 있는데 이름은 예전 것을 가리키는 상태가 될 수 있다. */
static int sync_dir(const char *dir)
{
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int ret;

	if (fd < 0) {
		return -1;
	}
	ret = fsync(fd);
	close(fd);

	return ret;
}

int identity_save(const char *path, const identity_t *dev)
{
	char line[IDENTITY_LINE_MAX];
	size_t len = IDENTITY_LINE_LEN;
	char tmp[PATH_MAX];
	char dir_buf[PATH_MAX];
	char *dir;
	int fd = -1;
	int ret = IDENTITY_ERROR;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp) ||
			snprintf(dir_buf, sizeof(dir_buf), "%s", path) >= (int)sizeof(dir_buf)) {
		fprintf(stderr, "%s: path too long\n", path);
		return IDENTITY_ERROR;
	}
	dir = dirname(dir_buf);

	/* 기본 경로(/var/lib/ztgate)는 처음에 없다. 한 단계만 만든다. */
	if (mkdir(dir, IDENTITY_DIR_MODE) < 0 && errno != EEXIST) {
		perror(dir);
		return IDENTITY_ERROR;
	}

	hex_encode(dev->id, DEVICE_ID_LEN, line);
	line[DEVICE_ID_LEN * 2] = ' ';
	hex_encode(dev->key, AUTH_KEY_LEN, line + DEVICE_ID_LEN * 2 + 1);
	if (dev->has_server_pub) {
		line[IDENTITY_PUB_OFF] = ' ';
		hex_encode(dev->server_pub, VPN_PUB_LEN_WIRE, line + IDENTITY_PUB_OFF + 1);
		len = IDENTITY_LINE_MAX;
	}
	line[len - 1] = '\n';

	/* 처음부터 0600 으로 만든다. 만든 뒤에 chmod 하면 그 사이에 다른 사람이 열어 둘 수 있다.
	 * 지난번에 쓰다 만 임시 파일은 지우고 새로 만든다. */
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, IDENTITY_FILE_MODE);
	if (fd < 0) {
		perror(tmp);
		goto out;
	}
	if (write(fd, line, len) != (ssize_t)len || fsync(fd) < 0) {
		perror(tmp);
		goto out;
	}
	close(fd);
	fd = -1;

	if (rename(tmp, path) < 0) {
		perror(path);
		goto out;
	}
	if (sync_dir(dir) < 0) {
		perror(dir);
	}
	ret = IDENTITY_OK;

out:
	if (fd >= 0) {
		close(fd);
	}
	if (ret != IDENTITY_OK) {
		unlink(tmp);
	}
	crypt_wipe(line, sizeof(line));

	return ret;
}
