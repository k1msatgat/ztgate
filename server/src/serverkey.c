#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "serverkey.h"

static crypt_ecdh_t *key;
static uint8_t key_pub[VPN_PUB_LEN];

static void hex(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = digits[in[i] >> 4];
		out[i * 2 + 1] = digits[in[i] & 0x0f];
	}
	out[len * 2] = '\0';
}

static int unhex(const char *s, uint8_t *out, size_t len)
{
	unsigned int v;
	size_t i;

	if (strlen(s) != len * 2) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		if (sscanf(s + i * 2, "%2x", &v) != 1) {
			return -1;
		}
		out[i] = (uint8_t)v;
	}
	return 0;
}

int serverkey_generate(const char *path)
{
	uint8_t priv[VPN_PRIV_LEN], pub[VPN_PUB_LEN];
	char line[VPN_PRIV_LEN * 2 + 1 + VPN_PUB_LEN * 2 + 2];
	crypt_ecdh_t *e;
	int fd;
	int ret = -1;

	e = crypt_ecdh_new(pub);
	if (e == NULL || crypt_ecdh_export(e, priv) < 0) {
		fprintf(stderr, "genkey: cannot make a key pair\n");
		goto out;
	}

	/* 있는 키를 덮으면 그 키로 등록된 기기가 모두 붙지 못한다. 처음부터 600 으로 만든다. */
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		fprintf(stderr, "genkey: %s: %s%s\n", path, strerror(errno),
				errno == EEXIST ? " (refusing to replace the server key)" : "");
		goto out;
	}
	hex(priv, sizeof(priv), line);
	line[VPN_PRIV_LEN * 2] = ' ';
	hex(pub, sizeof(pub), line + VPN_PRIV_LEN * 2 + 1);
	strcat(line, "\n");
	if (write(fd, line, strlen(line)) != (ssize_t)strlen(line) || fsync(fd) < 0) {
		fprintf(stderr, "genkey: cannot write %s\n", path);
		close(fd);
		unlink(path);
		goto out;
	}
	close(fd);

	hex(pub, sizeof(pub), line);
	printf("%s\n", line);
	ret = 0;

out:
	crypt_ecdh_free(e);
	crypt_wipe(priv, sizeof(priv));
	crypt_wipe(line, sizeof(line));
	return ret;
}

int serverkey_load(const char *path)
{
	char line[VPN_PRIV_LEN * 2 + 1 + VPN_PUB_LEN * 2 + 8];
	char s_priv[VPN_PRIV_LEN * 2 + 2], s_pub[VPN_PUB_LEN * 2 + 2];
	uint8_t priv[VPN_PRIV_LEN], pub[VPN_PUB_LEN];
	uint8_t check[VPN_PUB_LEN];
	crypt_ecdh_t *e = NULL, *probe = NULL;
	struct stat st;
	FILE *fp;
	int ret = -1;

	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "server key: %s: %s (make one with: vpn_server genkey %s)\n", path, strerror(errno), path);
		return -1;
	}
	if (fstat(fileno(fp), &st) < 0 || (st.st_mode & (S_IRWXG | S_IRWXO))) {
		fprintf(stderr, "server key: %s is accessible by group/others, run: chmod 600 %s\n", path, path);
		goto out;
	}
	if (fgets(line, sizeof(line), fp) == NULL ||
			sscanf(line, "%65s %129s", s_priv, s_pub) != 2 ||
			unhex(s_priv, priv, sizeof(priv)) < 0 || unhex(s_pub, pub, sizeof(pub)) < 0) {
		fprintf(stderr, "server key: %s: expected <private 64 hex> <public 128 hex>\n", path);
		goto out;
	}

	e = crypt_ecdh_import(priv, pub);
	if (e == NULL) {
		fprintf(stderr, "server key: %s: not a P-256 key pair\n", path);
		goto out;
	}

	/* 비밀 스칼라와 공개키가 같은 쌍인지 본다. 다른 쌍이면 이 서버가 내주는 공개키(등록 답)와
	 * 기기 키를 뽑는 비밀키가 어긋나, 등록은 되는데 아무도 붙지 못한다. 시험용 키 쌍 하나와
	 * 양쪽으로 합의해 보면 안다. */
	probe = crypt_ecdh_new(check);
	{
		uint8_t a[VPN_SECRET_LEN], b[VPN_SECRET_LEN];
		int same = probe != NULL &&
			crypt_ecdh_derive(e, check, a) == 0 &&
			crypt_ecdh_derive(probe, pub, b) == 0 &&
			crypt_equal(a, b, sizeof(a));

		crypt_wipe(a, sizeof(a));
		crypt_wipe(b, sizeof(b));
		if (!same) {
			fprintf(stderr, "server key: %s: the public key does not belong to the private key\n", path);
			goto out;
		}
	}

	crypt_ecdh_free(key);
	key = e;
	e = NULL;
	memcpy(key_pub, pub, sizeof(pub));
	ret = 0;

out:
	crypt_ecdh_free(e);
	crypt_ecdh_free(probe);
	crypt_wipe(priv, sizeof(priv));
	crypt_wipe(line, sizeof(line));
	crypt_wipe(s_priv, sizeof(s_priv));
	fclose(fp);
	return ret;
}

crypt_ecdh_t *serverkey(void)
{
	return key;
}

const uint8_t *serverkey_pub(void)
{
	return key != NULL ? key_pub : NULL;
}
