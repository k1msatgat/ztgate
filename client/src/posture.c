#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "posture.h"

#define KVER_PART_MAX	255	/* LINUX_VERSION_CODE 는 칸마다 8비트 */

/* 셸을 거치지 않고 절대 경로로 부른다. root 로 도는 프로그램이 PATH 를 따라가면 PATH 앞에
 * 놓인 가짜 nft 를 root 로 실행하게 된다. */
static const char *const NFT_PATHS[] = { "/usr/sbin/nft", "/sbin/nft" };

static uint32_t kernel_version(void)
{
	struct utsname u;
	unsigned int major = 0, minor = 0, patch = 0;

	if (uname(&u) < 0 || sscanf(u.release, "%u.%u.%u", &major, &minor, &patch) < 2) {
		return 0;
	}

	if (major > KVER_PART_MAX || minor > KVER_PART_MAX) {
		return 0;
	}
	if (patch > KVER_PART_MAX) {
		patch = KVER_PART_MAX;
	}

	return (uint32_t)(major << 16 | minor << 8 | patch);
}

const char *nft_path(void)
{
	size_t i;

	for (i = 0; i < sizeof(NFT_PATHS) / sizeof(NFT_PATHS[0]); i++) {
		if (access(NFT_PATHS[i], X_OK) == 0) {
			return NFT_PATHS[i];
		}
	}

	return NULL;
}

/* `nft list ruleset` 을 한 줄씩 읽어 posture.h 의 기준으로 판정한다. 규칙셋 문법을
 * 다 해석하지 않는다 — 체인 선언 줄은 "type filter hook input priority ...; policy drop;"
 * 처럼 한 줄에 나온다. */
static uint8_t collect_firewall(void)
{
	const char *nft = nft_path();
	char line[512];
	FILE *in;
	pid_t pid;
	int pipefd[2];
	int devnull;
	int status;
	int found = 0;

	if (nft == NULL || pipe(pipefd) < 0) {
		return POSTURE_STATE_UNKNOWN;
	}

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return POSTURE_STATE_UNKNOWN;
	}
	if (pid == 0) {
		/* 2초마다 부르므로 nft 의 오류 메시지는 버린다. 실패는 종료 코드로 안다. */
		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execl(nft, "nft", "list", "ruleset", (char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);

	in = fdopen(pipefd[0], "r");
	if (in == NULL) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return POSTURE_STATE_UNKNOWN;
	}

	/* 찾았어도 끝까지 읽는다. 중간에 닫으면 nft 가 SIGPIPE 로 끝나 성공 여부를 알 수 없다. */
	while (fgets(line, sizeof(line), in) != NULL) {
		if (strncmp(line, "table inet firewalld", strlen("table inet firewalld")) == 0 ||
				(strstr(line, "hook input") != NULL && strstr(line, "policy drop") != NULL)) {
			found = 1;
		}
	}
	fclose(in);

	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		return POSTURE_STATE_UNKNOWN;
	}

	return found ? POSTURE_STATE_ON : POSTURE_STATE_OFF;
}

#define DISK_DEPTH_MAX	8	/* dm 장치를 몇 겹까지 따라 내려가는가 (LUKS 위 LVM 위 RAID ...) */

/* /sys/dev/block/<maj:min> 또는 그 아래 slaves/<name> 인 dir 이 dm-crypt 이거나, 그 아래 어딘가에
 * dm-crypt 가 있으면 1. 없으면 0, 읽지 못했으면 -1. */
static int disk_crypt_under(const char *dir, int depth)
{
	char path[512], uuid[64];
	struct dirent *e;
	FILE *fp;
	DIR *d;
	int found = 0;

	if (depth > DISK_DEPTH_MAX) {
		return -1;
	}

	/* dm 장치만 dm/uuid 가 있다. 일반 파티션이면 없고, 그 아래 slaves 도 비어 있다. */
	snprintf(path, sizeof(path), "%s/dm/uuid", dir);
	fp = fopen(path, "r");
	if (fp != NULL) {
		if (fgets(uuid, sizeof(uuid), fp) != NULL && strncmp(uuid, "CRYPT-", 6) == 0) {
			fclose(fp);
			return 1;
		}
		fclose(fp);
	}

	snprintf(path, sizeof(path), "%s/slaves", dir);
	d = opendir(path);
	if (d == NULL) {
		return 0;	/* slaves 가 없는 장치 (파티션이면 그 위가 디스크다 — 암호화는 dm 에서만 본다) */
	}
	while (found == 0 && (e = readdir(d)) != NULL) {
		char sub[512];

		if (e->d_name[0] == '.') {
			continue;
		}
		snprintf(sub, sizeof(sub), "%s/slaves/%s", dir, e->d_name);
		found = disk_crypt_under(sub, depth + 1);
	}
	closedir(d);

	return found;
}

static uint8_t collect_disk(void)
{
	char dir[64];
	struct stat st;
	int r;

	/* / 의 st_dev 가 그 파일 시스템이 놓인 블록 장치다. major 0 은 블록 장치가 아닌 것(btrfs 의
	 * 부속 볼륨, overlay, tmpfs 등)이라 sysfs 에서 찾을 수 없다. */
	if (stat("/", &st) < 0 || major(st.st_dev) == 0) {
		return POSTURE_STATE_UNKNOWN;
	}
	snprintf(dir, sizeof(dir), "/sys/dev/block/%u:%u", major(st.st_dev), minor(st.st_dev));
	if (access(dir, F_OK) < 0) {
		return POSTURE_STATE_UNKNOWN;
	}

	r = disk_crypt_under(dir, 0);
	return r > 0 ? POSTURE_STATE_ON : r == 0 ? POSTURE_STATE_OFF : POSTURE_STATE_UNKNOWN;
}

void posture_collect(posture_report_t *out)
{
	memset(out, 0, sizeof(*out));
	out->os_build = kernel_version();
	out->firewall = collect_firewall();
	out->antivirus = POSTURE_STATE_UNKNOWN;
	out->disk = collect_disk();
}
