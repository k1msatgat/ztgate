#include <pthread.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "proto.h"
#include "flow.h"

/* 흐름 하나. 클라이언트 쪽(c)과 상대 쪽(r)으로 적는다. ICMP echo 는 id 를 두 포트 자리에 둔다. */
typedef struct flow {
	uint32_t c_ip, r_ip;
	uint16_t c_port, r_port;
	uint8_t proto;
	uint8_t used;
	time_t seen;		/* CLOCK_MONOTONIC 초 */
} flow_t;

/* 버킷 하나에 자리 넷. 해시가 같은 흐름이 다섯째로 오면 넷 중 가장 오래된 것을 지운다. */
#define WAYS		4
#define BUCKETS		(FLOW_MAX / WAYS)
#define STRIPES		64

_Static_assert((BUCKETS & (BUCKETS - 1)) == 0, "BUCKETS must be a power of two");

static flow_t table[BUCKETS][WAYS];
static pthread_mutex_t stripe[STRIPES];
static int enabled;
static int count;

#define TCP_TTL		300
#define UDP_TTL		60
#define ICMP_TTL	30

static time_t ttl(uint8_t proto)
{
	return proto == 6 ? TCP_TTL : proto == 17 ? UDP_TTL : ICMP_TTL;
}

void flow_enable(void)
{
	int i;

	for (i = 0; i < STRIPES; i++) {
		pthread_mutex_init(&stripe[i], NULL);
	}
	enabled = 1;
}

int flow_enabled(void)
{
	return enabled;
}

int flow_count(void)
{
	return __atomic_load_n(&count, __ATOMIC_RELAXED);
}

/* 패킷의 흐름 열쇠. src_is_client 면 출발지가 클라이언트 쪽이다. 열쇠를 뽑을 수 없으면(짧다,
 * 조각의 뒷부분) 0. */
static int key(const uint8_t *ip, int len, int src_is_client, flow_t *k)
{
	int ihl = IP_IHL(ip);
	uint32_t src, dst;
	uint16_t sp = 0, dp = 0;
	uint8_t proto = ip[IP_PROTO_OFF];

	if (len < IP_MIN_HDR || ihl < IP_MIN_HDR || len < ihl || ((ip[6] & 0x1f) | ip[7]) != 0) {
		return 0;
	}
	memcpy(&src, ip + IP_SRC_OFF, 4);
	memcpy(&dst, ip + IP_DST_OFF, 4);

	if (proto == 6 || proto == 17) {
		if (len < ihl + 4) {
			return 0;
		}
		sp = (uint16_t)(ip[ihl] << 8 | ip[ihl + 1]);
		dp = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);
	}
	else if (proto == 1) {
		/* echo 와 그 답만 흐름으로 친다. 둘은 id(4..5 바이트)가 같다. */
		if (len < ihl + 8 || (ip[ihl] != 8 && ip[ihl] != 0)) {
			return 0;
		}
		sp = dp = (uint16_t)(ip[ihl + 4] << 8 | ip[ihl + 5]);
	}

	memset(k, 0, sizeof(*k));
	k->proto = proto;
	if (src_is_client) {
		k->c_ip = src; k->r_ip = dst; k->c_port = sp; k->r_port = dp;
	}
	else {
		k->c_ip = dst; k->r_ip = src; k->c_port = dp; k->r_port = sp;
	}
	return 1;
}

static uint32_t bucket_of(const flow_t *k)
{
	uint32_t h = k->c_ip * 2654435761u;

	h ^= k->r_ip * 2246822519u;
	h ^= ((uint32_t)k->c_port << 16 | k->r_port) * 3266489917u;
	h ^= k->proto * 668265263u;
	h ^= h >> 15;
	return h & (BUCKETS - 1);
}

static int same(const flow_t *a, const flow_t *b)
{
	return a->c_ip == b->c_ip && a->r_ip == b->r_ip && a->c_port == b->c_port &&
		a->r_port == b->r_port && a->proto == b->proto;
}

void flow_outbound(const uint8_t *ip, int len)
{
	flow_t k;
	flow_t *slot, *oldest;
	uint32_t b;
	time_t now;
	int i;

	if (!enabled || !key(ip, len, 1, &k)) {
		return;
	}
	b = bucket_of(&k);
	now = mono_now();

	pthread_mutex_lock(&stripe[b % STRIPES]);
	oldest = &table[b][0];
	for (i = 0; i < WAYS; i++) {
		slot = &table[b][i];
		if (slot->used && same(slot, &k)) {
			slot->seen = now;
			pthread_mutex_unlock(&stripe[b % STRIPES]);
			return;
		}
		/* 빈 자리 > 수명이 다한 자리 > 가장 오래 안 쓴 자리 */
		if (!slot->used || (oldest->used && slot->seen < oldest->seen)) {
			oldest = slot;
		}
	}
	if (!oldest->used) {
		__atomic_fetch_add(&count, 1, __ATOMIC_RELAXED);
	}
	*oldest = k;
	oldest->used = 1;
	oldest->seen = now;
	pthread_mutex_unlock(&stripe[b % STRIPES]);
}

static int lookup(const flow_t *k)
{
	uint32_t b = bucket_of(k);
	time_t now = mono_now();
	int i, ok = 0;

	pthread_mutex_lock(&stripe[b % STRIPES]);
	for (i = 0; i < WAYS; i++) {
		flow_t *slot = &table[b][i];

		if (slot->used && same(slot, k)) {
			if (now - slot->seen <= ttl(k->proto)) {
				slot->seen = now;
				ok = 1;
			}
			else {
				slot->used = 0;
				__atomic_fetch_sub(&count, 1, __ATOMIC_RELAXED);
			}
			break;
		}
	}
	pthread_mutex_unlock(&stripe[b % STRIPES]);
	return ok;
}

int flow_inbound_ok(const uint8_t *ip, int len)
{
	flow_t k;
	int ihl;

	if (!enabled) {
		return 1;
	}
	if (len < IP_MIN_HDR) {
		return 0;
	}
	ihl = IP_IHL(ip);

	/* ICMP 오류: 안에 담긴 원래 패킷은 클라이언트가 보낸 것이다 (출발지가 클라이언트). */
	if (ip[IP_PROTO_OFF] == 1 && len >= ihl + 8 + IP_MIN_HDR &&
			(ip[ihl] == 3 || ip[ihl] == 11 || ip[ihl] == 12)) {
		const uint8_t *inner = ip + ihl + 8;
		int inner_len = len - ihl - 8;
		int inner_ihl = IP_IHL(inner);

		/* 담긴 패킷은 앞부분만 있다. 포트까지(8바이트) 있으면 된다 — key 가 길이를 본다. */
		if (inner_ihl >= IP_MIN_HDR && inner_len >= inner_ihl + 8) {
			uint8_t copy[60 + 8];
			int n = inner_ihl + 8;

			memcpy(copy, inner, (size_t)n);
			/* 조각 표시는 담긴 그대로 둔다. key 는 첫 조각만 받는다. */
			return key(copy, n, 1, &k) && lookup(&k);
		}
		return 0;
	}

	return key(ip, len, 0, &k) && lookup(&k);
}
