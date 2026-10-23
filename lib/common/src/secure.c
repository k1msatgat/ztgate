#include <stdio.h>
#include <string.h>

#include "secure.h"

static const char SESSION_LABEL[] = "ztgate v6 session";
static const char DENY_LABEL[] = "ztgate deny";

/* ---- HKDF (RFC 5869) --------------------------------------------------------
 * 합의한 값은 그대로 키로 쓰기에는 고르지 않고, 키는 여러 개가 필요하다. HMAC 을
 * 두 번 거쳐 고른 값 하나를 만들고(extract) 필요한 만큼 늘린다(expand). */
static int hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
		uint8_t prk[VPN_HASH_LEN])
{
	return crypt_hmac(salt, salt_len, ikm, ikm_len, prk);
}

static int hkdf_expand(const uint8_t prk[VPN_HASH_LEN], const uint8_t *info, size_t info_len,
		uint8_t *out, size_t out_len)
{
	uint8_t block[VPN_HASH_LEN + 96 + 1];
	uint8_t t[VPN_HASH_LEN];
	size_t t_len = 0;
	size_t done = 0;
	size_t n;
	uint8_t i = 1;
	int ret = -1;

	if (info_len > 96 || out_len > 255 * VPN_HASH_LEN) {
		return -1;
	}

	while (done < out_len) {
		memcpy(block, t, t_len);
		memcpy(block + t_len, info, info_len);
		block[t_len + info_len] = i++;

		if (crypt_hmac(prk, VPN_HASH_LEN, block, t_len + info_len + 1, t) < 0) {
			goto out;
		}
		t_len = VPN_HASH_LEN;

		n = out_len - done < VPN_HASH_LEN ? out_len - done : VPN_HASH_LEN;
		memcpy(out + done, t, n);
		done += n;
	}
	ret = 0;

out:
	crypt_wipe(block, sizeof(block));
	crypt_wipe(t, sizeof(t));

	return ret;
}

int secure_derive(const uint8_t device_key[AUTH_KEY_LEN],
		const uint8_t secret[VPN_SECRET_LEN],
		const uint8_t *auth_pkt, const uint8_t *res_head,
		secure_keys_t *keys)
{
	uint8_t seen[AUTH_PACKET_LEN + RES_HS_HEAD_LEN];
	uint8_t info[sizeof(SESSION_LABEL) - 1 + VPN_HASH_LEN];
	uint8_t prk[VPN_HASH_LEN];
	int ret = -1;

	memcpy(seen, auth_pkt, AUTH_PACKET_LEN);
	memcpy(seen + AUTH_PACKET_LEN, res_head, RES_HS_HEAD_LEN);

	memcpy(info, SESSION_LABEL, sizeof(SESSION_LABEL) - 1);
	if (crypt_sha256(seen, sizeof(seen), info + sizeof(SESSION_LABEL) - 1) < 0) {
		goto out;
	}

	if (hkdf_extract(device_key, AUTH_KEY_LEN, secret, VPN_SECRET_LEN, prk) < 0 ||
			hkdf_expand(prk, info, sizeof(info), (uint8_t *)keys, sizeof(*keys)) < 0) {
		goto out;
	}
	ret = 0;

out:
	crypt_wipe(prk, sizeof(prk));

	return ret;
}

PROTO_STATIC_ASSERT(sizeof(secure_keys_t) == 3 * VPN_KEY_LEN, "secure_keys has no padding");

/* RES_HANDSHAKE 는 세션에 한 통뿐이고 자기만의 키를 쓰므로 nonce 는 0 이면 된다. */
int secure_res_seal(const uint8_t key[VPN_KEY_LEN], uint8_t *pkt, size_t cap, size_t payload_len)
{
	static const uint8_t nonce[VPN_NONCE_LEN] = { 0 };
	crypt_aead_t *a;
	int ret;

	if (cap < RES_HS_MIN_LEN || payload_len > cap - RES_HS_MIN_LEN) {
		return -1;
	}

	a = crypt_aead_new(key);
	if (a == NULL) {
		return -1;
	}

	ret = crypt_aead_seal(a, nonce, pkt, RES_HS_HEAD_LEN,
			pkt + RES_HS_HEAD_LEN, payload_len, pkt + RES_HS_HEAD_LEN + payload_len);
	crypt_aead_free(a);

	return ret < 0 ? -1 : (int)(RES_HS_MIN_LEN + payload_len);
}

int secure_res_open(const uint8_t key[VPN_KEY_LEN], uint8_t *pkt, size_t len)
{
	static const uint8_t nonce[VPN_NONCE_LEN] = { 0 };
	crypt_aead_t *a;
	size_t payload_len;
	int ret;

	if (len < RES_HS_MIN_LEN) {
		return -1;
	}
	payload_len = len - RES_HS_MIN_LEN;

	a = crypt_aead_new(key);
	if (a == NULL) {
		return -1;
	}

	ret = crypt_aead_open(a, nonce, pkt, RES_HS_HEAD_LEN,
			pkt + RES_HS_HEAD_LEN, payload_len, pkt + RES_HS_HEAD_LEN + payload_len);
	crypt_aead_free(a);

	return ret < 0 ? -1 : (int)payload_len;
}

/* AUTH 의 mac 을 넣어 이번 핸드셰이크에 묶는다. 넣지 않으면 한 번 엿들은 "포스처 미달"
 * 거절을 그 기기가 연결을 시도할 때마다 다시 보내 영영 막을 수 있다. */
int secure_deny_mac(const uint8_t device_key[AUTH_KEY_LEN], uint8_t reason,
		const uint8_t auth_mac[AUTH_MAC_LEN], uint8_t out[AUTH_MAC_LEN])
{
	uint8_t msg[sizeof(DENY_LABEL) - 1 + 1 + AUTH_MAC_LEN];
	size_t off = sizeof(DENY_LABEL) - 1;

	memcpy(msg, DENY_LABEL, off);
	msg[off++] = reason;
	memcpy(msg + off, auth_mac, AUTH_MAC_LEN);

	return crypt_hmac(device_key, AUTH_KEY_LEN, msg, sizeof(msg), out);
}

/* ---- 등록 코드 --------------------------------------------------------------
 * 코드에서 등록용 임시 신원을 뽑는다. ID 는 서버가 "어느 코드인가"를 찾는 이름표이고
 * 키는 그 코드를 아는 쪽만 만들 수 있는 비밀이다. 둘을 다른 라벨로 뽑아서, 와이어에
 * 그대로 실리는 ID 를 본 사람이 키에 대해 알게 되는 것이 없다.
 *
 * 사람이 옮겨 적는 값이라 너그럽게 읽는다. 소문자, 끊는 줄표와 공백, 0 과 O / 1 과 I, L
 * 을 섞어 적어도 같은 코드다. */
static const char ENROLL_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const char ENROLL_ID_LABEL[] = "ztgate enroll id";
static const char ENROLL_KEY_LABEL[] = "ztgate enroll key";
static const char STATIC_LABEL[] = "ztgate v8 static";

int secure_static_key(crypt_ecdh_t *mine, const uint8_t peer_pub[VPN_PUB_LEN],
		const uint8_t client_pub[VPN_PUB_LEN], const uint8_t server_pub[VPN_PUB_LEN],
		uint8_t key[AUTH_KEY_LEN])
{
	uint8_t secret[VPN_SECRET_LEN];
	uint8_t msg[sizeof(STATIC_LABEL) - 1 + 2 * VPN_PUB_LEN];
	int ret = -1;

	if (crypt_ecdh_derive(mine, peer_pub, secret) < 0) {
		goto out;
	}
	memcpy(msg, STATIC_LABEL, sizeof(STATIC_LABEL) - 1);
	memcpy(msg + sizeof(STATIC_LABEL) - 1, client_pub, VPN_PUB_LEN);
	memcpy(msg + sizeof(STATIC_LABEL) - 1 + VPN_PUB_LEN, server_pub, VPN_PUB_LEN);
	ret = crypt_hmac(secret, sizeof(secret), msg, sizeof(msg), key);

out:
	crypt_wipe(secret, sizeof(secret));
	return ret;
}

int secure_enroll_identity(const char *code, uint8_t id[DEVICE_ID_LEN], uint8_t key[AUTH_KEY_LEN])
{
	char norm[ENROLL_CODE_LEN];
	uint8_t mac[VPN_HASH_LEN];
	size_t n = 0;
	char c;
	int ret = -1;

	for (; *code != '\0'; code++) {
		c = *code;

		if (c == '-' || c == ' ') {
			continue;
		}
		if (c >= 'a' && c <= 'z') {
			c = (char)(c - 'a' + 'A');
		}
		if (c == 'O') {
			c = '0';
		}
		if (c == 'I' || c == 'L') {
			c = '1';
		}

		if (n == sizeof(norm) || strchr(ENROLL_ALPHABET, c) == NULL) {
			goto out;
		}
		norm[n++] = c;
	}
	if (n != sizeof(norm)) {
		goto out;
	}

	if (crypt_hmac((const uint8_t *)ENROLL_ID_LABEL, sizeof(ENROLL_ID_LABEL) - 1,
				(const uint8_t *)norm, sizeof(norm), mac) < 0) {
		goto out;
	}
	memcpy(id, mac, DEVICE_ID_LEN);

	ret = crypt_hmac((const uint8_t *)ENROLL_KEY_LABEL, sizeof(ENROLL_KEY_LABEL) - 1,
			(const uint8_t *)norm, sizeof(norm), key);

out:
	crypt_wipe(norm, sizeof(norm));
	crypt_wipe(mac, sizeof(mac));

	return ret;
}

/* ---- 열린 세션 -------------------------------------------------------------- */

int secure_session_open(secure_session_t *s, const uint8_t tx_key[VPN_KEY_LEN],
		const uint8_t rx_key[VPN_KEY_LEN])
{
	crypt_aead_t *tx = crypt_aead_new(tx_key);
	crypt_aead_t *rx = crypt_aead_new(rx_key);

	if (tx == NULL || rx == NULL) {
		crypt_aead_free(tx);
		crypt_aead_free(rx);
		return -1;
	}

	secure_session_close(s);
	s->tx = tx;
	s->rx = rx;

	return 0;
}

void secure_session_close(secure_session_t *s)
{
	crypt_aead_free(s->tx);
	crypt_aead_free(s->rx);
	memset(s, 0, sizeof(*s));
}

int secure_session_ready(const secure_session_t *s)
{
	return s->tx != NULL && s->rx != NULL;
}

/* counter 는 와이어에 빅엔디언 8B 로 실려 있다. 그 8B 앞에 0 네 개를 붙인 것이 nonce 다.
 * 방향마다 키가 다르므로 방향을 nonce 에 넣을 필요가 없다. */
static void nonce_from_wire(uint8_t nonce[VPN_NONCE_LEN], const uint8_t *counter_be)
{
	memset(nonce, 0, VPN_NONCE_LEN - sizeof(data_header_t));
	memcpy(nonce + VPN_NONCE_LEN - sizeof(data_header_t), counter_be, sizeof(data_header_t));
}

int secure_seal(secure_session_t *s, uint8_t type, uint32_t session_idx,
		uint8_t *pkt, size_t cap, size_t payload_len)
{
	uint8_t nonce[VPN_NONCE_LEN];
	msg_header_t h;
	data_header_t d;
	int off;

	if (!secure_session_ready(s) || cap < PKT_OVERHEAD || payload_len > cap - PKT_OVERHEAD) {
		return -1;
	}
	/* 이 키로 감쌀 수 있는 양을 다 썼다. 새 핸드셰이크로 새 키를 받아야 한다 (proto.h). */
	if (s->tx_counter >= SECURE_COUNTER_LIMIT) {
		return -1;
	}

	memset(&h, 0, sizeof(h));
	h.version = PROTOCOL_VERSION;
	h.type = type;
	h.session_idx = session_idx;
	d.counter = s->tx_counter++;

	off = msg_encode(pkt, cap, &h);
	off += data_encode(pkt + off, cap - (size_t)off, &d);

	nonce_from_wire(nonce, pkt + sizeof(msg_header_t));

	if (crypt_aead_seal(s->tx, nonce, pkt, PKT_HDR_LEN,
				pkt + PKT_HDR_LEN, payload_len, pkt + PKT_HDR_LEN + payload_len) < 0) {
		return -1;
	}

	return (int)(payload_len + PKT_OVERHEAD);
}

/* 받아도 되는 counter 인가. 창 밖으로 오래된 값은 받은 적이 있는지 알 수 없으므로 버린다. */
static int window_fresh(const secure_session_t *s, uint64_t counter)
{
	uint64_t back;

	if (!s->rx_any || counter > s->rx_max) {
		return 1;
	}

	back = s->rx_max - counter;

	return back < SECURE_WINDOW && !(s->rx_seen & ((uint64_t)1 << back));
}

static void window_mark(secure_session_t *s, uint64_t counter)
{
	uint64_t ahead;

	if (!s->rx_any) {
		s->rx_any = 1;
		s->rx_max = counter;
		s->rx_seen = 1;
		return;
	}

	if (counter > s->rx_max) {
		ahead = counter - s->rx_max;
		s->rx_seen = ahead < SECURE_WINDOW ? s->rx_seen << ahead : 0;
		s->rx_seen |= 1;
		s->rx_max = counter;
		return;
	}

	s->rx_seen |= (uint64_t)1 << (s->rx_max - counter);
}

int secure_open(secure_session_t *s, uint8_t *pkt, size_t len, uint64_t *counter)
{
	uint8_t nonce[VPN_NONCE_LEN];
	data_header_t d;
	size_t payload_len;

	if (!secure_session_ready(s) || len < PKT_OVERHEAD) {
		return SECURE_BAD;
	}
	payload_len = len - PKT_OVERHEAD;

	data_decode(pkt + sizeof(msg_header_t), sizeof(data_header_t), &d);

	/* 싼 검사를 먼저 한다. 다만 창에 표시하는 것은 tag 가 맞은 뒤다. 순서가 반대면
	 * 아무 counter 나 적은 위조 패킷이 그 값을 "받은 것"으로 만들어 진짜 패킷을 막는다. */
	if (d.counter >= SECURE_COUNTER_LIMIT) {
		return SECURE_BAD;
	}
	if (!window_fresh(s, d.counter)) {
		return SECURE_REPLAY;
	}

	nonce_from_wire(nonce, pkt + sizeof(msg_header_t));

	if (crypt_aead_open(s->rx, nonce, pkt, PKT_HDR_LEN,
				pkt + PKT_HDR_LEN, payload_len, pkt + PKT_HDR_LEN + payload_len) < 0) {
		return SECURE_BAD;
	}

	window_mark(s, d.counter);
	if (counter != NULL) {
		*counter = d.counter;
	}

	return (int)payload_len;
}

/* ---- selftest ---------------------------------------------------------------
 * 서버는 OpenSSL, 클라이언트는 CNG 로 서로 다른 구현을 쓴다. 양쪽이 같은 표준 벡터를
 * 통과하는 것이 "서로의 패킷을 열 수 있다"의 근거다. */

static int unhex(const char *hex, uint8_t *out, size_t cap)
{
	size_t n = 0;
	unsigned int v;

	for (; hex[0] != '\0' && hex[1] != '\0'; hex += 2) {
		if (n == cap || sscanf(hex, "%2x", &v) != 1) {
			return -1;
		}
		out[n++] = (uint8_t)v;
	}

	return (int)n;
}

static int report(const char *name, int ok)
{
	printf("%-28s %s\n", name, ok ? "ok" : "FAIL");

	return !ok;
}

static int test_sha256(void)
{
	/* FIPS 180-4 의 예 */
	uint8_t want[VPN_HASH_LEN], got[VPN_HASH_LEN];

	unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, sizeof(want));

	return report("sha256 fips180 \"abc\"",
			crypt_sha256((const uint8_t *)"abc", 3, got) == 0 &&
			crypt_equal(got, want, sizeof(want)));
}

static int test_hmac(void)
{
	static const struct {
		const char *name;
		const char *key;
		const char *msg;
		const char *want;
	} cases[] = {
		{ "hmac-sha256 rfc4231 case 1",
		  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		  "Hi There",
		  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
		{ "hmac-sha256 rfc4231 case 2",
		  "4a656665",
		  "what do ya want for nothing?",
		  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
	};
	uint8_t key[32], want[VPN_HASH_LEN], got[VPN_HASH_LEN];
	int failed = 0;
	int key_len;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		key_len = unhex(cases[i].key, key, sizeof(key));
		unhex(cases[i].want, want, sizeof(want));

		failed |= report(cases[i].name,
				crypt_hmac(key, (size_t)key_len, (const uint8_t *)cases[i].msg,
					strlen(cases[i].msg), got) == 0 &&
				crypt_equal(got, want, sizeof(want)));
	}

	return failed;
}

static int test_hkdf(void)
{
	uint8_t ikm[22], salt[13], info[10], want[42], got[42], prk[VPN_HASH_LEN];

	unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof(ikm));
	unhex("000102030405060708090a0b0c", salt, sizeof(salt));
	unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
	unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
	      "34007208d5b887185865", want, sizeof(want));

	return report("hkdf-sha256 rfc5869 case 1",
			hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk) == 0 &&
			hkdf_expand(prk, info, sizeof(info), got, sizeof(got)) == 0 &&
			crypt_equal(got, want, sizeof(want)));
}

static int test_aead(void)
{
	/* GCM 명세(McGrew & Viega)의 test case 16: AES-256, aad 있음 */
	uint8_t key[VPN_KEY_LEN], nonce[VPN_NONCE_LEN], aad[20];
	uint8_t pt[60], ct[60], buf[60];
	uint8_t tag[VPN_TAG_LEN], want_tag[VPN_TAG_LEN];
	crypt_aead_t *a;
	int failed = 0;
	int ok;

	unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key, sizeof(key));
	unhex("cafebabefacedbaddecaf888", nonce, sizeof(nonce));
	unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof(aad));
	unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
	      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt, sizeof(pt));
	unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
	      "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", ct, sizeof(ct));
	unhex("76fc6ece0f4e1768cddf8853bb2d551b", want_tag, sizeof(want_tag));

	a = crypt_aead_new(key);
	if (a == NULL) {
		return report("aes-256-gcm test case 16", 0);
	}

	memcpy(buf, pt, sizeof(pt));
	ok = crypt_aead_seal(a, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) == 0 &&
		crypt_equal(buf, ct, sizeof(ct)) && crypt_equal(tag, want_tag, sizeof(tag));
	failed |= report("aes-256-gcm test case 16", ok);

	ok = crypt_aead_open(a, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) == 0 &&
		crypt_equal(buf, pt, sizeof(pt));
	failed |= report("aes-256-gcm open", ok);

	/* 암호문, aad, tag 중 어느 것이 한 비트 바뀌어도 열리지 않아야 한다. */
	memcpy(buf, ct, sizeof(ct));
	buf[7] ^= 0x01;
	ok = crypt_aead_open(a, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) < 0;
	memcpy(buf, ct, sizeof(ct));
	aad[3] ^= 0x01;
	ok = ok && crypt_aead_open(a, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) < 0;
	aad[3] ^= 0x01;
	memcpy(buf, ct, sizeof(ct));
	tag[15] ^= 0x80;
	ok = ok && crypt_aead_open(a, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) < 0;
	failed |= report("aes-256-gcm rejects changes", ok);

	/* 서버가 보내는 keepalive 처럼 암호문이 없는 패킷 */
	ok = crypt_aead_seal(a, nonce, aad, sizeof(aad), buf, 0, tag) == 0 &&
		crypt_aead_open(a, nonce, aad, sizeof(aad), buf, 0, tag) == 0;
	tag[0] ^= 0x01;
	ok = ok && crypt_aead_open(a, nonce, aad, sizeof(aad), buf, 0, tag) < 0;
	failed |= report("aes-256-gcm empty payload", ok);

	crypt_aead_free(a);

	return failed;
}

static int test_ecdh(void)
{
	/* RFC 5903 8.1 의 256비트 예: 개인키 i 와 상대의 공개키 g^r, 공유점의 X 좌표 */
	uint8_t priv[VPN_PRIV_LEN], pub[VPN_PUB_LEN], peer[VPN_PUB_LEN];
	uint8_t x[32], want[VPN_SECRET_LEN], got[VPN_SECRET_LEN], other[VPN_SECRET_LEN];
	uint8_t pub_a[VPN_PUB_LEN], pub_b[VPN_PUB_LEN];
	crypt_ecdh_t *e, *a, *b;
	int failed = 0;
	int ok;

	unhex("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433", priv, sizeof(priv));
	unhex("dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180"
	      "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3", pub, sizeof(pub));
	unhex("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"
	      "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab", peer, sizeof(peer));
	unhex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de", x, sizeof(x));
	crypt_sha256(x, sizeof(x), want);

	e = crypt_ecdh_import(priv, pub);
	ok = e != NULL && crypt_ecdh_derive(e, peer, got) == 0 && crypt_equal(got, want, sizeof(want));
	failed |= report("ecdh p-256 rfc5903", ok);

	/* 곡선 위에 있지 않은 점을 공개키로 받으면 계산하지 않는다. 받아 주면 상대가 고른
	 * 엉뚱한 점으로 개인키의 정보를 조금씩 캐낼 수 있다. */
	peer[VPN_PUB_LEN - 1] ^= 0x01;
	ok = e != NULL && crypt_ecdh_derive(e, peer, got) < 0;
	failed |= report("ecdh rejects an off-curve point", ok);
	crypt_ecdh_free(e);

	a = crypt_ecdh_new(pub_a);
	b = crypt_ecdh_new(pub_b);
	ok = a != NULL && b != NULL &&
		crypt_ecdh_derive(a, pub_b, got) == 0 && crypt_ecdh_derive(b, pub_a, other) == 0 &&
		crypt_equal(got, other, sizeof(got)) && !crypt_equal(pub_a, pub_b, sizeof(pub_a));
	failed |= report("ecdh fresh key pairs agree", ok);
	crypt_ecdh_free(a);
	crypt_ecdh_free(b);

	return failed;
}

/* 세션 한 쌍을 열어 패킷을 주고받는다. 표준 벡터는 없고, 여기서 보는 것은 우리가 정한
 * 규칙이다 — 방향이 섞이지 않는가, 다시 보낸 패킷과 고친 패킷이 걸러지는가. */
static int test_session(void)
{
	uint8_t key_a[VPN_KEY_LEN], key_b[VPN_KEY_LEN];
	uint8_t pkt[64], copy[64], late[64];
	secure_session_t client, server;
	uint64_t counter = 99;
	int failed = 0;
	int n, late_n, i;
	int ok;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	memset(key_a, 0x11, sizeof(key_a));
	memset(key_b, 0x22, sizeof(key_b));

	if (secure_session_open(&client, key_a, key_b) < 0 ||
			secure_session_open(&server, key_b, key_a) < 0) {
		return report("session", 0);
	}

	memcpy(pkt + PKT_HDR_LEN, "ping", 4);
	n = secure_seal(&client, MSG_TYPE_DATA, 0x1234, pkt, sizeof(pkt), 4);
	memcpy(copy, pkt, sizeof(pkt));

	ok = n == 4 + (int)PKT_OVERHEAD && memcmp(pkt + PKT_HDR_LEN, "ping", 4) != 0 &&
		secure_open(&server, pkt, (size_t)n, &counter) == 4 &&
		memcmp(pkt + PKT_HDR_LEN, "ping", 4) == 0 && counter == 0;
	failed |= report("session seal / open", ok);

	memcpy(pkt, copy, sizeof(pkt));
	ok = secure_open(&server, pkt, (size_t)n, NULL) == SECURE_REPLAY;
	failed |= report("session rejects a replay", ok);

	/* 보낸 쪽에게 되돌려 보낸 패킷 */
	memcpy(pkt, copy, sizeof(pkt));
	ok = secure_open(&client, pkt, (size_t)n, NULL) == SECURE_BAD;
	failed |= report("session rejects a reflection", ok);

	/* 헤더는 암호화하지 않지만 tag 가 덮는다. 종류를 DATA 에서 KEEPALIVE 로 고쳐 본다. */
	memcpy(pkt + PKT_HDR_LEN, "ping", 4);
	n = secure_seal(&client, MSG_TYPE_DATA, 0x1234, pkt, sizeof(pkt), 4);
	memcpy(copy, pkt, sizeof(pkt));
	pkt[1] = MSG_TYPE_KEEPALIVE;
	ok = secure_open(&server, pkt, (size_t)n, NULL) == SECURE_BAD;
	/* 열지 못한 패킷은 창에 남지 않는다. 고치기 전의 것은 그대로 받아들여진다. */
	memcpy(pkt, copy, sizeof(pkt));
	ok = ok && secure_open(&server, pkt, (size_t)n, &counter) == 4 && counter == 1;
	failed |= report("session covers the header", ok);

	/* 순서가 바뀌어 늦게 온 패킷은 받고, 창(64) 밖으로 밀려난 것은 버린다. */
	late_n = secure_seal(&client, MSG_TYPE_DATA, 0x1234, late, sizeof(late), 4);	/* counter 2 */
	n = secure_seal(&client, MSG_TYPE_DATA, 0x1234, pkt, sizeof(pkt), 4);		/* counter 3 */
	memcpy(copy, late, sizeof(late));
	ok = secure_open(&server, pkt, (size_t)n, NULL) == 4 &&
		secure_open(&server, late, (size_t)late_n, &counter) == 4 && counter == 2;
	failed |= report("session accepts reordering", ok);

	for (i = 0; i < SECURE_WINDOW + 4; i++) {
		n = secure_seal(&client, MSG_TYPE_DATA, 0x1234, pkt, sizeof(pkt), 4);
		if (i == 0) {
			memcpy(late, pkt, sizeof(pkt));		/* counter 4, 보내지 않고 쥐고 있는다 */
			late_n = n;
			continue;
		}
		if (secure_open(&server, pkt, (size_t)n, NULL) != 4) {
			break;
		}
	}
	ok = i == SECURE_WINDOW + 4 &&
		secure_open(&server, late, (size_t)late_n, NULL) == SECURE_REPLAY &&
		secure_open(&server, copy, (size_t)late_n, NULL) == SECURE_REPLAY;
	failed |= report("session window slides", ok);

	secure_session_close(&client);
	secure_session_close(&server);

	return failed;
}

/* 등록 코드는 사람이 옮겨 적는다. 적는 방식이 달라도 같은 신원이 나와야 하고, 한 글자가
 * 다르면 다른 신원이 나와야 한다. */
static int test_enroll_code(void)
{
	uint8_t id[DEVICE_ID_LEN], key[AUTH_KEY_LEN];
	uint8_t id2[DEVICE_ID_LEN], key2[AUTH_KEY_LEN];
	uint8_t want[DEVICE_ID_LEN];
	int failed = 0;
	int ok;

	/* HMAC-SHA256("ztgate enroll id", "0123456789ABCDEFGHJKMNPQR") 의 앞 16B.
	 * 서버의 관리 도구(mcp/ctl.cjs)와 검사 스크립트가 같은 값을 내야 한다. */
	unhex("1fff58721da8863917ba05e6d47ce662", want, sizeof(want));

	ok = secure_enroll_identity("0123456789ABCDEFGHJKMNPQR", id, key) == 0 &&
		crypt_equal(id, want, sizeof(want));
	failed |= report("enroll code -> identity", ok);

	ok = secure_enroll_identity("oL234-56789-abcde-fghjk-mnpqr", id2, key2) == 0 &&
		crypt_equal(id, id2, sizeof(id)) && crypt_equal(key, key2, sizeof(key)) &&
		secure_enroll_identity(" 01234 56789 ABCDE FGHJK MNPQR ", id2, key2) == 0 &&
		crypt_equal(id, id2, sizeof(id));
	failed |= report("enroll code is read leniently", ok);

	ok = secure_enroll_identity("0123456789ABCDEFGHJKMNPQS", id2, key2) == 0 &&
		!crypt_equal(id, id2, sizeof(id)) && !crypt_equal(key, key2, sizeof(key)) &&
		secure_enroll_identity("0123456789ABCDEFGHJKMNPQ", id2, key2) < 0 &&
		secure_enroll_identity("0123456789ABCDEFGHJKMNPQRS", id2, key2) < 0 &&
		secure_enroll_identity("0123456789ABCDEFGHJKMNPQU", id2, key2) < 0 &&
		secure_enroll_identity("", id2, key2) < 0;
	failed |= report("enroll code rejects other input", ok);

	return failed;
}

int crypt_selftest(void)
{
	int failed = 0;

	failed |= test_sha256();
	failed |= test_hmac();
	failed |= test_hkdf();
	failed |= test_aead();
	failed |= test_ecdh();
	failed |= test_session();
	failed |= test_enroll_code();

	return failed;
}
