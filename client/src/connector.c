#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/wait.h>

#include "connector.h"
#include "posture.h"

#define IP_FORWARD	"/proc/sys/net/ipv4/ip_forward"
#define TABLE		"ztgate_connector"

static int active;
static char saved_forward = '0';

int connector_ifname_ok(const char *name)
{
	size_t i, n = strlen(name);

	if (n == 0 || n >= IFNAMSIZ) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		char c = name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
				c == '.' || c == '_' || c == '-')) {
			return 0;
		}
	}

	return 1;
}

/* nft -f - 에 규칙을 넣는다. 셸을 거치지 않는다 (posture.c 와 같은 이유). */
static int nft_apply(const char *rules)
{
	const char *nft = nft_path();
	int pipefd[2];
	int status;
	pid_t pid;
	size_t len = strlen(rules), off = 0;
	ssize_t w;

	if (nft == NULL) {
		fprintf(stderr, "[connector] nft not found\n");
		return -1;
	}
	if (pipe(pipefd) < 0) {
		perror("pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execl(nft, "nft", "-f", "-", (char *)NULL);
		_exit(127);
	}

	close(pipefd[0]);
	while (off < len) {
		w = write(pipefd[1], rules + off, len - off);
		if (w <= 0) {
			break;
		}
		off += (size_t)w;
	}
	close(pipefd[1]);

	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[connector] nft rejected the rules\n");
		return -1;
	}

	return 0;
}

static int write_forward(char v)
{
	int fd = open(IP_FORWARD, O_WRONLY | O_CLOEXEC);
	int ok;

	if (fd < 0) {
		return -1;
	}
	ok = write(fd, &v, 1) == 1;
	close(fd);

	return ok ? 0 : -1;
}

int connector_up(const char *tun_if, const char *lan_if, struct in_addr tun_net, int prefix)
{
	char rules[1024];
	char net[INET_ADDRSTRLEN];
	int fd;

	if (!connector_ifname_ok(tun_if) || !connector_ifname_ok(lan_if)) {
		fprintf(stderr, "[connector] bad interface name\n");
		return -1;
	}
	inet_ntop(AF_INET, &tun_net, net, sizeof(net));

	/* 앞의 두 줄은 지난번에 지우지 못하고 끝난 표가 있으면 지우는 관용구다 (없으면 만들고
	 * 지운다). 한 번에 넣으므로 중간 상태가 없다. */
	snprintf(rules, sizeof(rules),
		"table ip " TABLE "\n"
		"delete table ip " TABLE "\n"
		"table ip " TABLE " {\n"
		"	chain forward {\n"
		"		type filter hook forward priority 0; policy accept;\n"
		"		iifname \"%s\" oifname \"%s\" accept\n"
		"		iifname \"%s\" oifname \"%s\" ct state established,related accept\n"
		"		iifname \"%s\" oifname \"%s\" drop\n"
		"	}\n"
		"	chain postrouting {\n"
		"		type nat hook postrouting priority 100; policy accept;\n"
		"		ip saddr %s/%d oifname \"%s\" masquerade\n"
		"	}\n"
		"}\n",
		tun_if, lan_if, lan_if, tun_if, lan_if, tun_if, net, prefix, lan_if);

	/* 다시 부르면(터널 대역이 바뀌었을 때) 전달은 이미 1 이다. 그때 읽으면 끝날 때 되돌릴 값을 잃는다. */
	if (!active) {
		fd = open(IP_FORWARD, O_RDONLY | O_CLOEXEC);
		if (fd < 0 || read(fd, &saved_forward, 1) != 1) {
			saved_forward = '0';
		}
		if (fd >= 0) {
			close(fd);
		}
	}

	if (write_forward('1') < 0) {
		perror("[connector] " IP_FORWARD);
		return -1;
	}
	if (nft_apply(rules) < 0) {
		write_forward(saved_forward);
		return -1;
	}

	active = 1;
	printf("[connector] forwarding %s/%d -> %s (masquerade), replies only on the way back\n",
			net, prefix, lan_if);

	return 0;
}

void connector_down(void)
{
	if (!active) {
		return;
	}
	nft_apply("delete table ip " TABLE "\n");
	write_forward(saved_forward);
	active = 0;
}
