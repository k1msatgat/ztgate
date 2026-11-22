#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include "common.h"

const char *ip_str(struct in_addr a, char *dist)
{
	return inet_ntop(AF_INET, &a, dist, INET_ADDRSTRLEN);
}

time_t mono_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0){
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (*dev){
		strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	}

	err = ioctl(fd, TUNSETIFF, (void*)&ifr);
	if (err < 0){
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}
