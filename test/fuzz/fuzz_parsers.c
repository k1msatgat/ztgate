/* 밖에서 들어오는 바이트를 읽는 파서들의 퍼저. 첫 바이트가 대상을 고르고, 나머지가 입력이다.
 *
 *   clang -fsanitize=fuzzer,address,undefined ...   libFuzzer 로 (CI 의 fuzz 작업)
 *   gcc -DFUZZ_STANDALONE -fsanitize=address ...    파일들을 한 번씩 돌린다 (재현용)
 *
 * 대상: 헤더 / 데이터 / 포스처 / 터널 설정 디코더, JSON 파서와 꺼내 쓰는 함수, devices.conf 와
 * acl.conf 한 줄. 서버가 인증 전에 읽는 것과 관리자가 고친 파일을 다시 읽는 것이다. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proto.h"
#include "json.h"
#include "policy.h"
#include "device.h"
#include "acl.h"

#define TOKENS 128

static void fuzz_json(const char *s, size_t n)
{
	json_tok_t t[TOKENS];
	char out[256];
	int64_t v;
	int count = json_parse(s, n, t, TOKENS);

	if (count <= 0) {
		return;
	}
	for (int i = 0; i < count; i++) {
		json_string(s, t, i, out, sizeof(out));
		json_int64(s, t, i, &v);
		json_eq(s, t, i, "ES256");
	}
	if (t[0].type == JSON_OBJECT) {
		json_get(s, t, 0, "kid");
		json_get(s, t, 0, "exp");
	}
}

/* 파일을 읽는 로더는 경로를 받으므로 입력을 임시 파일에 써서 넘긴다. */
static void fuzz_file(int (*load)(const char *), const uint8_t *data, size_t n)
{
	char path[] = "/tmp/ztgate-fuzz-XXXXXX";
	int fd = mkstemp(path);

	if (fd < 0) {
		return;
	}
	if (write(fd, data, n) == (ssize_t)n) {
		load(path);
	}
	close(fd);
	unlink(path);
}

static void fuzz_tokens(const char *line)
{
	posture_req_t pr;
	user_req_t ur;
	tag_set_t tags;
	device_t dev;

	memset(&dev, 0, sizeof(dev));
	posture_req_parse(line, &pr);
	user_req_parse(line, &ur);
	tag_parse(line, &tags);
	device_token_parse(line, &dev);
	user_name_valid(line);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct msg_header h;
	struct data_header d;
	struct posture_report p;
	net_config_t c;
	char *s;

	if (size < 1) {
		return 0;
	}
	const uint8_t *in = data + 1;
	size_t n = size - 1;

	switch (data[0] % 6) {
	case 0:
		msg_decode(in, n, &h);
		break;
	case 1:
		data_decode(in, n, &d);
		break;
	case 2:
		posture_decode(in, n, &p);
		break;
	case 3:
		net_config_decode(in, n, &c);
		break;
	case 4:
		/* 파서는 길이를 받지만, NUL 로 끝나지 않는 버퍼에서 더 읽지 않는지도 본다 */
		s = malloc(n ? n : 1);
		if (s != NULL) {
			memcpy(s, in, n);
			fuzz_json(s, n);
			free(s);
		}
		break;
	default:
		s = malloc(n + 1);
		if (s != NULL) {
			memcpy(s, in, n);
			s[n] = '\0';
			fuzz_tokens(s);
			free(s);
		}
		if (n > 0 && in[0] & 1) {
			acl_init();
			fuzz_file(acl_load, in, n);
		}
		else {
			device_init();
			fuzz_file(device_load, in, n);
		}
		break;
	}
	return 0;
}

#ifdef FUZZ_STANDALONE
/* 인자로 준 파일마다 한 번. 인자가 없으면 정해진 씨앗에서 만든 무작위 입력을 돈다. */
int main(int argc, char **argv)
{
	static uint8_t buf[1 << 16];

	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			FILE *f = fopen(argv[i], "rb");
			size_t n;

			if (f == NULL) {
				perror(argv[i]);
				return 1;
			}
			n = fread(buf, 1, sizeof(buf), f);
			fclose(f);
			LLVMFuzzerTestOneInput(buf, n);
		}
		return 0;
	}
	srand(1);
	for (int i = 0; i < 20000; i++) {
		size_t n = (size_t)(rand() % 600);

		for (size_t j = 0; j < n; j++) {
			buf[j] = (uint8_t)rand();
		}
		LLVMFuzzerTestOneInput(buf, n);
	}
	return 0;
}
#endif
