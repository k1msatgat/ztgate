#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tunnel.h"
#include "posture.h"
#include "crypt.h"
#include "device.h"

static HANDLE stop_event;

static BOOL WINAPI on_console_ctrl(DWORD type)
{
	(void)type;
	SetEvent(stop_event);
	return TRUE;
}

static void on_log(void *ctx, const char *line)
{
	(void)ctx;
	printf("%s\n", line);
	fflush(stdout);
}

static const char *state_name(uint8_t state)
{
	switch (state) {
	case POSTURE_ON:	return "on";
	case POSTURE_OFF:	return "off";
	default:		return "unknown";
	}
}

/* 서버에 접속하지 않고 이 단말의 포스처만 읽어 찍는다. 어댑터를 만들지 않으므로
 * 관리자 권한이 필요 없다. */
static int print_posture(void)
{
	posture_t p;

	posture_collect(&p);

	if (p.os_build != 0) {
		printf("os         %u.%u.%u\n", p.os_major, p.os_minor, p.os_build);
	} else {
		printf("os         unknown\n");
	}
	printf("firewall   %s\n", state_name(p.firewall));
	printf("antivirus  %s\n", state_name(p.antivirus));
	printf("disk       %s (BitLocker on the system drive)\n", state_name(p.disk));

	return 0;
}

/* 서버는 OpenSSL, 여기는 CNG 로 서로 다른 구현을 쓴다. 양쪽이 같은 표준 벡터를 통과하는
 * 것이 "서로의 패킷을 열 수 있다"의 근거다. 벡터와 검사는 secure.c 에 하나만 있고
 * 서버의 `vpn_server selftest` 도 같은 것을 돌린다. */
static int selftest(void)
{
	return crypt_selftest();
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
	size_t i;

	printf("%s", label);
	for (i = 0; i < len; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

static int show_device(void)
{
	device_t dev;
	int ret;

	ret = device_load(&dev);
	if (ret == DEVICE_NOT_ENROLLED) {
		printf("not enrolled (run: vpn_client enroll)\n");
		return 1;
	}
	if (ret != DEVICE_OK) {
		fprintf(stderr, "device identity is unreadable\n");
		return 1;
	}

	/* 키는 등록할 때 한 번만 보여 준다. */
	print_hex("device id  ", dev.id, sizeof(dev.id));
	SecureZeroMemory(&dev, sizeof(dev));

	return 0;
}

/* 이 기기의 ID 와 키를 만들고 서버에 등록할 값을 찍는다. */
static int enroll(int force)
{
	device_t dev;

	if (!force && device_load(&dev) != DEVICE_NOT_ENROLLED) {
		SecureZeroMemory(&dev, sizeof(dev));
		fprintf(stderr, "already enrolled. a new key invalidates the one registered on the server.\n");
		fprintf(stderr, "to replace it anyway: vpn_client enroll --force\n");
		return 1;
	}

	if (device_enroll(&dev) != DEVICE_OK) {
		fprintf(stderr, "enroll failed: %lu\n", GetLastError());
		return 1;
	}

	printf("enrolled. register these on the server (the key is shown only once):\n");
	print_hex("device id  ", dev.id, sizeof(dev.id));
	print_hex("key        ", dev.key, sizeof(dev.key));
	SecureZeroMemory(&dev, sizeof(dev));

	return 0;
}

/* 관리자가 준 등록 코드로 서버에 이 기기를 올린다. ID 와 키를 손으로 옮기지 않는다.
 *
 * 신원은 서버가 받아 준 뒤에 저장한다. 먼저 저장하면 서버에 닿지 못했을 때 예전 신원은
 * 지워졌고 새 신원은 어디에도 등록되지 않은 채로 남는다. */
static int enroll_with_code(const char *server, const char *port, const char *code, int force)
{
	tunnel_config_t cfg;
	device_t dev;
	HANDLE stop;
	char *end;
	long port_num;
	int ret = 1;
	int r;

	if (!force && device_load(&dev) != DEVICE_NOT_ENROLLED) {
		SecureZeroMemory(&dev, sizeof(dev));
		fprintf(stderr, "already enrolled. a new key invalidates the one registered on the server.\n");
		fprintf(stderr, "to replace it anyway, add --force\n");
		return 1;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.on_log = on_log;

	if (inet_pton(AF_INET, server, &cfg.server_ip) != 1) {
		fprintf(stderr, "invalid server ip : %s\n", server);
		return 1;
	}
	port_num = strtol(port, &end, 10);
	if (*end != '\0' || port_num <= 0 || port_num > 65535) {
		fprintf(stderr, "invalid port : %s\n", port);
		return 1;
	}
	cfg.server_port = (uint16_t)port_num;

	if (device_generate(&dev) != DEVICE_OK) {
		fprintf(stderr, "could not create a device identity\n");
		return 1;
	}

	stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!stop) {
		SecureZeroMemory(&dev, sizeof(dev));
		return 1;
	}

	r = tunnel_enroll(&cfg, code, dev.id, dev.key, dev.server_pub, stop);
	dev.has_server_pub = r == TUNNEL_ENROLL_OK;
	CloseHandle(stop);

	switch (r) {
	case TUNNEL_ENROLL_OK:
		if (device_save(&dev) != DEVICE_OK) {
			/* 서버에는 올라갔는데 이 PC 에 남기지 못했다. 그 등록은 쓸 수 없다. */
			fprintf(stderr, "the server accepted the device but the identity could not be stored here.\n");
			fprintf(stderr, "ask the administrator to remove the device and issue a new code.\n");
			break;
		}
		printf("enrolled.\n");
		print_hex("device id  ", dev.id, sizeof(dev.id));
		ret = 0;
		break;
	case TUNNEL_ENROLL_BAD_CODE:
		fprintf(stderr, "that is not an enrollment code (25 letters and digits)\n");
		break;
	case TUNNEL_ENROLL_NO_RESPONSE:
		fprintf(stderr, "no answer from the server\n");
		break;
	case TUNNEL_ENROLL_REJECTED:
		fprintf(stderr, "the server does not accept this code: mistyped, expired or already used\n");
		break;
	case TUNNEL_ENROLL_CONFLICT:
		fprintf(stderr, "the server already has this device or the address reserved for it\n");
		break;
	case TUNNEL_ENROLL_SERVER_FAILED:
		fprintf(stderr, "the server could not save the device\n");
		break;
	default:
		fprintf(stderr, "enrollment failed\n");
		break;
	}

	SecureZeroMemory(&dev, sizeof(dev));

	return ret;
}

/* 저장된 기기 신원을 설정에 싣는다. 등록하지 않은 기기는 서버가 어차피 거절하므로
 * 패킷을 보내기 전에 여기서 멈추고 무엇을 해야 하는지 알려 준다. */
static int load_identity(tunnel_config_t *cfg)
{
	device_t dev;
	int ret;

	ret = device_load(&dev);
	if (ret == DEVICE_NOT_ENROLLED) {
		fprintf(stderr, "this device is not enrolled. run: vpn_client enroll\n");
		return -1;
	}
	if (ret != DEVICE_OK) {
		fprintf(stderr, "device identity is unreadable\n");
		return -1;
	}

	memcpy(cfg->device_id, dev.id, sizeof(cfg->device_id));
	memcpy(cfg->device_key, dev.key, sizeof(cfg->device_key));
	memcpy(cfg->server_pub, dev.server_pub, sizeof(cfg->server_pub));
	cfg->has_server_pub = dev.has_server_pub;
	SecureZeroMemory(&dev, sizeof(dev));

	return 0;
}

int main(int argc, char *argv[])
{
	tunnel_config_t cfg;
	WSADATA wsa;
	char *end;
	long server_port;
	int ret = 1;

	if (argc == 2 && strcmp(argv[1], "posture") == 0) {
		return print_posture();
	}
	if (argc == 2 && strcmp(argv[1], "selftest") == 0) {
		return selftest();
	}
	if (argc == 2 && strcmp(argv[1], "device") == 0) {
		return show_device();
	}
	if ((argc == 5 || argc == 6) && strcmp(argv[1], "enroll") == 0) {
		if (argc == 6 && strcmp(argv[5], "--force") != 0) {
			fprintf(stderr, "usage: %s enroll <server-ip> <port> <code> [--force]\n", argv[0]);
			return 1;
		}
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			fprintf(stderr, "WSAStartup failed\n");
			return 1;
		}
		ret = enroll_with_code(argv[2], argv[3], argv[4], argc == 6);
		WSACleanup();
		return ret;
	}
	if ((argc == 2 || argc == 3) && strcmp(argv[1], "enroll") == 0) {
		if (argc == 3 && strcmp(argv[2], "--force") != 0) {
			fprintf(stderr, "usage: %s enroll [--force]\n", argv[0]);
			return 1;
		}
		return enroll(argc == 3);
	}

	if (argc != 4) {
		fprintf(stderr, "usage: %s <adapter-name> <server-ip> <port>\n", argv[0]);
		fprintf(stderr, "       %s posture\n", argv[0]);
		fprintf(stderr, "       %s selftest\n", argv[0]);
		fprintf(stderr, "       %s enroll <server-ip> <port> <code> [--force]   enroll with a code from the administrator\n", argv[0]);
		fprintf(stderr, "       %s enroll [--force]                             print an id and key to register by hand\n", argv[0]);
		fprintf(stderr, "       %s device\n", argv[0]);
		fprintf(stderr, " e.g. %s ztgate 49.247.139.39 9000\n", argv[0]);
		fprintf(stderr, " the tunnel address and the routes come from the server\n");
		return 1;
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.log_packets = 1;
	cfg.on_log = on_log;

	if (MultiByteToWideChar(CP_ACP, 0, argv[1], -1, cfg.adapter_name, TUNNEL_ADAPTER_NAME_LEN) == 0) {
		fprintf(stderr, "invalid adapter name : %s\n", argv[1]);
		goto out;
	}

	{
		wchar_t list[256];

		/* 서버 여럿: 10.0.0.10,10.0.0.11 (tunnel.h 의 TUNNEL_ALT_SERVERS) */
		if (MultiByteToWideChar(CP_ACP, 0, argv[2], -1, list, 256) == 0 ||
				tunnel_parse_servers(list, &cfg.server_ip, cfg.alt_ips, &cfg.n_alt) < 0) {
			fprintf(stderr, "invalid server ip : %s\n", argv[2]);
			goto out;
		}
	}

	server_port = strtol(argv[3], &end, 10);
	if (*end != '\0' || server_port <= 0 || server_port > 65535) {
		fprintf(stderr, "invalid port : %s\n", argv[3]);
		goto out;
	}
	cfg.server_port = (uint16_t)server_port;

	if (load_identity(&cfg) < 0) {
		goto out;
	}

	/* tunnel_run()이 핸드셰이크 대기와 메인 루프 양쪽에서 보므로 manual-reset */
	stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!stop_event) {
		fprintf(stderr, "CreateEvent failed: %lu\n", GetLastError());
		goto out;
	}
	SetConsoleCtrlHandler(on_console_ctrl, TRUE);

	ret = tunnel_run(&cfg, stop_event);

	CloseHandle(stop_event);

out:
	WSACleanup();
	return ret;
}
