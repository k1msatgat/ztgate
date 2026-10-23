#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "dns.h"

/* 쓰는 것. 다시 읽다 실패하면 그대로 남는다. */
static net_config_t live;

int dns_load(const char *path)
{
	net_config_t staged;
	char line[256], word[32], value[160];
	struct in_addr addr;
	FILE *fp;
	int lineno = 0;
	int i;

	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen dns file");
		return -1;
	}

	memset(&staged, 0, sizeof(staged));

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *hash = strchr(line, '#');

		lineno++;
		if (hash != NULL) {
			*hash = '\0';
		}
		if (sscanf(line, "%31s", word) != 1) {
			continue;
		}
		if (sscanf(line, "%31s %159s", word, value) != 2) {
			fprintf(stderr, "dns: line %d: expected 'server <ip>' or 'domain <name>'\n", lineno);
			goto fail;
		}

		if (strcmp(word, "server") == 0) {
			if (inet_pton(AF_INET, value, &addr) != 1 || addr.s_addr == 0) {
				fprintf(stderr, "dns: line %d: bad server address '%s'\n", lineno, value);
				goto fail;
			}
			if (staged.n_dns >= NET_MAX_DNS) {
				fprintf(stderr, "dns: line %d: at most %d servers\n", lineno, NET_MAX_DNS);
				goto fail;
			}
			staged.dns[staged.n_dns++] = addr.s_addr;
		}
		else if (strcmp(word, "domain") == 0) {
			/* 사람은 대문자나 끝의 점(corp.example.)으로 적기도 한다. 뜻이 같으니 고쳐 받는다. */
			size_t len = strlen(value);

			for (i = 0; value[i] != '\0'; i++) {
				value[i] = (char)tolower((unsigned char)value[i]);
			}
			if (len > 1 && value[len - 1] == '.') {
				value[len - 1] = '\0';
			}
			if (!net_domain_ok(value)) {
				fprintf(stderr, "dns: line %d: bad domain '%s'\n", lineno, value);
				goto fail;
			}
			if (staged.n_domains >= NET_MAX_DOMAINS) {
				fprintf(stderr, "dns: line %d: at most %d domains\n", lineno, NET_MAX_DOMAINS);
				goto fail;
			}
			strcpy(staged.domains[staged.n_domains++], value);
		}
		else {
			fprintf(stderr, "dns: line %d: unknown word '%s'\n", lineno, word);
			goto fail;
		}
	}
	fclose(fp);

	if (staged.n_domains > 0 && staged.n_dns == 0) {
		fprintf(stderr, "dns: domains without a server\n");
		return -1;
	}

	live = staged;
	return live.n_domains;

fail:
	fclose(fp);
	return -1;
}

void dns_fill(net_config_t *cfg)
{
	int i;

	cfg->n_dns = 0;
	cfg->n_domains = 0;

	/* 물을 이름이 없으면 서버도 내려 주지 않는다 (dns.h). */
	if (live.n_domains == 0) {
		return;
	}

	cfg->n_dns = live.n_dns;
	memcpy(cfg->dns, live.dns, sizeof(cfg->dns));
	cfg->n_domains = live.n_domains;
	for (i = 0; i < live.n_domains; i++) {
		strcpy(cfg->domains[i], live.domains[i]);
	}
}
