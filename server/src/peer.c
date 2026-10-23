#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "common.h"
#include "peer.h"
#include "audit.h"

static peer_t peers[MAX_PEERS];

/* 세션을 터널 주소와 기기 ID 로 찾는 색인. tun 에서 읽은 패킷마다 목적지 주소로 세션을
 * 찾으므로, 표를 처음부터 훑으면 세션 수만큼 느려진다. 버킷마다 그 버킷에 든 자리를
 * next 로 잇는다 (-1 이 끝). 버킷을 자리의 두 배로 두어 사슬이 거의 한 칸에서 끝난다.
 *
 * 색인에 들어가는 값은 인증을 마친 세션의 것뿐이다 (터널 주소는 기기 목록이 정하고, 기기
 * ID 는 서명이 맞은 기기의 것이다). 밖에서 같은 버킷으로 몰리는 값을 골라 넣을 수 없다. */
#define PEER_BUCKETS (MAX_PEERS * 2)
_Static_assert((PEER_BUCKETS & (PEER_BUCKETS - 1)) == 0, "PEER_BUCKETS must be a power of two");

static int32_t ip_head[PEER_BUCKETS], ip_next[MAX_PEERS];
static int32_t id_head[PEER_BUCKETS], id_next[MAX_PEERS];

static uint32_t mix(uint32_t v)
{
	/* 터널 주소는 이어진 번호라 그대로 쓰면 아래 bit 만 다르다. 곱해서 섞는다 (Knuth). */
	return (v * 2654435761u) >> 7;
}

static uint32_t ip_bucket(struct in_addr a)
{
	return mix(ntohl(a.s_addr)) & (PEER_BUCKETS - 1);
}

static uint32_t id_bucket(const uint8_t id[DEVICE_ID_LEN])
{
	uint32_t v;

	memcpy(&v, id, sizeof(v));
	return mix(v) & (PEER_BUCKETS - 1);
}

static void chain_del(int32_t *head, int32_t *next, uint32_t b, int32_t slot)
{
	int32_t *at = &head[b];

	while (*at >= 0) {
		if (*at == slot) {
			*at = next[slot];
			return;
		}
		at = &next[*at];
	}
}

static void index_add(int32_t slot)
{
	uint32_t b = ip_bucket(peers[slot].inner);

	ip_next[slot] = ip_head[b];
	ip_head[b] = slot;

	b = id_bucket(peers[slot].device_id);
	id_next[slot] = id_head[b];
	id_head[b] = slot;
}

static void index_del(int32_t slot)
{
	chain_del(ip_head, ip_next, ip_bucket(peers[slot].inner), slot);
	chain_del(id_head, id_next, id_bucket(peers[slot].device_id), slot);
}

/* 자리를 비운다. 색인에서 먼저 빼고, 세션 키를 놓는다. */
static void release(int32_t slot)
{
	index_del(slot);
	secure_session_close(&peers[slot].secure);
	peers[slot].used = 0;
}

static const char *ip4(struct in_addr a, char *dst)
{
	return inet_ntop(AF_INET, &a, dst, INET_ADDRSTRLEN);
}

static uint32_t make_idx(int32_t slot)
{
	uint32_t random;
	uint32_t idx;

	do {
		if (getrandom(&random, sizeof(random), 0) != sizeof(random)) {
			return 0;
		}

		idx = (random & ~IDX_SLOT_MASK) | (uint32_t)slot;

	} while(idx == 0);
	return idx;
}

void peer_touch(peer_t *peer, const struct sockaddr_in *outer, socklen_t len) {
	char ib[INET_ADDRSTRLEN];
	char ob[INET6_ADDRSTRLEN];
	char nb[INET6_ADDRSTRLEN];

	if (peer->outer.sin_addr.s_addr != outer->sin_addr.s_addr || peer->outer.sin_port != outer->sin_port) {
		printf("[peer] rebind %s: %s:%d -> %s:%d\n",
				ip4(peer->inner, ib),
				ip4(peer->outer.sin_addr, ob), ntohs(peer->outer.sin_port),
				ip4(outer->sin_addr, nb),   ntohs(outer->sin_port));
		peer->outer = *outer;
		peer->outer_len = len;
	}

	peer->last_seen = mono_now();
}

peer_t *peer_find_idx(uint32_t idx)
{
	uint32_t slot = idx & IDX_SLOT_MASK;

	if (slot >= MAX_PEERS){
		return NULL;
	}

	if (!peers[slot].used || peers[slot].session_idx != idx){
		return NULL;
	}

	return &peers[slot];
}

void peer_check_expired(void) {
	static time_t checked_at = -1;
	int i;
	time_t now = mono_now();
	char dst[INET_ADDRSTRLEN];

	/* 이벤트 루프는 패킷이 올 때마다 돈다. 만료는 초 단위라 1초에 한 번만 표를 훑는다 —
	 * 표가 크면 패킷마다 훑는 비용이 패킷을 나르는 비용보다 커진다. */
	if (now == checked_at) {
		return;
	}
	checked_at = now;

	for (i = 0; i < MAX_PEERS; i++){
		if(peers[i].used){
			if (now - peers[i].last_seen > SESSION_TIMEOUT_SEC){
				audit_session_close(&peers[i], "expired");
				printf("[peer] expire inner ip[%s] idx=%08x\n",ip4(peers[i].inner, dst), peers[i].session_idx);
				release(i);
			}
		}
	}
}

peer_t *peer_register(struct in_addr inner, const uint8_t id[DEVICE_ID_LEN],
		const struct sockaddr_in *outer, socklen_t len)
{
	char ib[INET_ADDRSTRLEN];
	char ob[INET_ADDRSTRLEN];
	peer_t *peer;
	uint32_t idx;
	int32_t i;
	int32_t slot = -1;
	int32_t victim = 0;

	peer = peer_lookup(inner);
	if (peer) {
		if(peer->outer.sin_addr.s_addr == outer->sin_addr.s_addr && peer->outer.sin_port == outer->sin_port &&
				memcmp(peer->device_id, id, DEVICE_ID_LEN) == 0){
			peer->last_seen = mono_now();
			return peer;
		}
		slot = (int32_t)(peer - peers);
	} else {
		for (i = 0; i < MAX_PEERS; i++){
			if (!peers[i].used) {
				slot = i;
				break;
			}
			if (peers[i].last_seen < peers[victim].last_seen) {
				victim = i;
			}
		}

		if (slot < 0) {
			printf("[peer] table full evicting %s\n", ip4(peers[victim].inner, ib));
			slot = victim;
		}
	}

	idx = make_idx(slot);
	if (idx == 0) {
		return NULL;
	}

	peer = &peers[slot];
	/* 이 자리에 아직 세션이 있었다면 밀려나는 것이다: 표가 가득 차 가장 오래된 것이
	 * 나가거나, 같은 터널 주소가 다른 외부 주소에서 다시 등록됐다. */
	if (peer->used) {
		audit_session_close(peer, peer->inner.s_addr == inner.s_addr ? "replaced" : "evicted");
		/* 이 자리에 있던 세션의 키를 먼저 놓는다. 그냥 덮으면 키 객체가 샌다. */
		release(slot);
	}
	memset(peer, 0, sizeof(*peer));
	peer->used = 1;
	peer->session_idx = idx;
	peer->inner = inner;
	memcpy(peer->device_id, id, DEVICE_ID_LEN);
	peer->outer = *outer;
	peer->outer_len = len;
	peer->last_seen = mono_now();
	peer->established_at = peer->last_seen;
	index_add(slot);

	printf("[peer] register %s <- %s:%d idx=%08x\n",
			ip4(inner, ib), ip4(outer->sin_addr, ob),
			ntohs(outer->sin_port), idx);

	return peer;
}

/* 만료를 기다리지 않고 세션을 바로 내린다. 포스처가 정책에 못 미치게 됐거나 기기가
 * 목록에서 지워졌을 때 쓴다. 이후 이 idx 로 오는 패킷은 unknown session 으로 버려진다. */
void peer_drop(peer_t *peer, const char *reason)
{
	char ib[INET_ADDRSTRLEN];

	printf("[peer] drop %s idx=%08x\n", ip4(peer->inner, ib), peer->session_idx);
	audit_session_close(peer, reason);
	release((int32_t)(peer - peers));
}

void peer_drop_all(void (*before)(peer_t *peer, void *arg), void *arg, const char *reason)
{
	int32_t i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (peers[i].used) {
			before(&peers[i], arg);
			peer_drop(&peers[i], reason);
		}
	}
}

void peer_init(void)
{
	memset(peers, 0, sizeof(peers));
	/* 0xff 바이트로 채우면 int32_t 가 모두 -1 (빈 사슬)이 된다. */
	memset(ip_head, 0xff, sizeof(ip_head));
	memset(id_head, 0xff, sizeof(id_head));
}

peer_t *peer_lookup(struct in_addr inner)
{
	int32_t i;

	for (i = ip_head[ip_bucket(inner)]; i >= 0; i = ip_next[i]) {
		if (peers[i].inner.s_addr == inner.s_addr) {
			return &peers[i];
		}
	}
	return NULL;
}

const peer_t *peer_at(int i)
{
	if (i < 0 || i >= MAX_PEERS || !peers[i].used) {
		return NULL;
	}

	return &peers[i];
}

void peer_dump(void)
{
	char ib[INET_ADDRSTRLEN], ob[INET_ADDRSTRLEN];
	int i;

	printf("--- peer table ---\n");
	for (i = 0; i < MAX_PEERS; i++) {
		if (!peers[i].used) continue;
		printf("  [%d] %-12s idx=%08x <- %s:%d  (age %lds)\n", i,
				ip4(peers[i].inner, ib), peers[i].session_idx,
				ip4(peers[i].outer.sin_addr, ob),
				ntohs(peers[i].outer.sin_port),
				(long)(mono_now() - peers[i].last_seen));
	}
	printf("------------------\n");
}


/* 이 기기가 열어 둔 세션. 없으면 NULL. 세션은 터널 주소로 찾는 것이 보통이지만, 관리자가
 * 기기의 주소를 바꾼 뒤에는 같은 기기의 세션이 예전 주소 아래에 남아 있다. */
peer_t *peer_find_device(const uint8_t id[DEVICE_ID_LEN])
{
	int32_t i;

	for (i = id_head[id_bucket(id)]; i >= 0; i = id_next[i]) {
		if (memcmp(peers[i].device_id, id, DEVICE_ID_LEN) == 0) {
			return &peers[i];
		}
	}

	return NULL;
}
