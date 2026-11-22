#ifndef COMMON_H
#define COMMON_H

#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#include "proto.h"

int tun_alloc(char *dev);
const char *ip_str(struct in_addr a, char *dst);

/* 뒤로 가지 않는 시계의 초. 벽시계(time)는 관리자가 시간을 고치거나 NTP 가 맞추면
 * 뛴다. nonce 의 수명이나 세션 만료처럼 "몇 초가 지났는가"만 필요한 곳에 쓴다. */
time_t mono_now(void);

#endif

