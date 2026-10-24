#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "idp.h"
#include "json.h"
#include "proto.h"

#define IDP_MAX_KEYS	8
#define IDP_KID_MAX	128
#define IDP_URL_MAX	256
#define IDP_CLAIM_MAX	64

#define JWKS_FILE_MAX	(64 * 1024)
#define JWKS_TOKENS	2048

/* 토큰의 각 부분을 풀었을 때의 상한. 토큰 전체가 UDP 패킷 하나(LOGIN_TOKEN_MAX)라
 * 이보다 클 수 없다. */
#define JWT_PART_MAX	LOGIN_TOKEN_MAX
#define JWT_TOKENS	512

enum key_alg { ALG_RS256 = 1, ALG_ES256 };

typedef struct idp_key {
	char kid[IDP_KID_MAX];
	int alg;
	EVP_PKEY *pkey;
} idp_key_t;

typedef struct idp_conf {
	char issuer[IDP_URL_MAX];
	char audience[IDP_URL_MAX];
	char jwks[IDP_URL_MAX];
	char user_claim[IDP_CLAIM_MAX];
	char groups_claim[IDP_CLAIM_MAX];
	int64_t leeway;
	int dpop_required;
	idp_key_t keys[IDP_MAX_KEYS];
	int n_keys;
} idp_conf_t;

static idp_conf_t conf;
static int loaded;

/* ---- base64url ---------------------------------------------------------------- */

static int b64url_value(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '-') return 62;
	if (c == '_') return 63;
	return -1;
}

/* 패딩 없는 base64url (RFC 7515 2절). 쓴 길이, 틀린 글자가 있거나 자리가 모자라면 -1.
 * 마지막 글자의 남는 비트가 0 이 아니면 받지 않는다 — 같은 바이트를 두 가지로 적을 수
 * 있으면 "같은 토큰인가"를 원문으로 비교할 수 없다. */
static int b64url_decode(const char *in, size_t len, uint8_t *out, size_t cap)
{
	uint32_t acc = 0;
	size_t o = 0, i;
	int bits = 0, v;

	if (len % 4 == 1) {
		return -1;
	}

	for (i = 0; i < len; i++) {
		v = b64url_value((unsigned char)in[i]);
		if (v < 0) {
			return -1;
		}
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= cap) {
				return -1;
			}
			out[o++] = (uint8_t)(acc >> bits);
		}
	}
	if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) {
		return -1;
	}

	return (int)o;
}

/* ---- 키 -------------------------------------------------------------------------- */

/* JSON 의 base64url 문자열 값 하나를 바이트로. */
static int json_b64(const char *s, const json_tok_t *t, int i, uint8_t *out, size_t cap)
{
	if (i < 0 || t[i].type != JSON_STRING) {
		return -1;
	}

	return b64url_decode(s + t[i].start, (size_t)(t[i].end - t[i].start), out, cap);
}

static EVP_PKEY *rsa_key(const uint8_t *n, int nlen, const uint8_t *e, int elen)
{
	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *bn_n = BN_bin2bn(n, nlen, NULL);
	BIGNUM *bn_e = BN_bin2bn(e, elen, NULL);

	if (bld == NULL || bn_n == NULL || bn_e == NULL ||
			!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
			!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) ||
			(params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
			(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL ||
			EVP_PKEY_fromdata_init(ctx) <= 0 ||
			EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_n);
	BN_free(bn_e);

	/* 2048 비트보다 짧은 RSA 키로 한 서명은 믿지 않는다. */
	if (pkey != NULL && EVP_PKEY_get_bits(pkey) < 2048) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return pkey;
}

/* 곡선 위에 없는 점이면 fromdata 가 실패한다. */
static EVP_PKEY *p256_key(const uint8_t x[32], const uint8_t y[32])
{
	uint8_t point[65];
	char group[] = "prime256v1";
	OSSL_PARAM params[3];
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;

	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point));
	params[2] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx != NULL) {
		if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
				EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
			pkey = NULL;
		}
		EVP_PKEY_CTX_free(ctx);
	}

	return pkey;
}

/* JWKS 의 키 하나. 서명용 RS256 / ES256 키가 아니면 0 (건너뛴다), 쓸 수 있으면 1,
 * 서명용이라고 적혀 있는데 값이 틀렸으면 -1.
 *
 * IdP 는 서명 키 말고도 암호화용 키(use=enc, RSA-OAEP)를 같은 묶음에 싣는다. 그런 키는
 * 실패가 아니라 우리와 상관없는 키다. */
static int parse_jwk(const char *s, const json_tok_t *t, int obj, idp_key_t *k)
{
	static uint8_t n[1024], e[16], x[64], y[64];
	int kty, alg, use, kid, crv;
	int nl, el, xl, yl;

	kty = json_get(s, t, obj, "kty");
	alg = json_get(s, t, obj, "alg");
	use = json_get(s, t, obj, "use");
	kid = json_get(s, t, obj, "kid");

	if (use >= 0 && !json_eq(s, t, use, "sig")) {
		return 0;
	}

	if (kty >= 0 && json_eq(s, t, kty, "RSA")) {
		if (alg >= 0 && !json_eq(s, t, alg, "RS256")) {
			return 0;
		}
		k->alg = ALG_RS256;
	}
	else if (kty >= 0 && json_eq(s, t, kty, "EC")) {
		crv = json_get(s, t, obj, "crv");
		if ((alg >= 0 && !json_eq(s, t, alg, "ES256")) || crv < 0 || !json_eq(s, t, crv, "P-256")) {
			return 0;
		}
		k->alg = ALG_ES256;
	}
	else {
		return 0;
	}

	/* 토큰은 kid 로 키를 고른다. 이름 없는 키는 고를 방법이 없다. */
	if (kid < 0 || json_string(s, t, kid, k->kid, sizeof(k->kid)) <= 0) {
		fprintf(stderr, "idp: a signing key without a usable kid\n");
		return -1;
	}

	if (k->alg == ALG_RS256) {
		nl = json_b64(s, t, json_get(s, t, obj, "n"), n, sizeof(n));
		el = json_b64(s, t, json_get(s, t, obj, "e"), e, sizeof(e));
		k->pkey = nl > 0 && el > 0 ? rsa_key(n, nl, e, el) : NULL;
	}
	else {
		xl = json_b64(s, t, json_get(s, t, obj, "x"), x, sizeof(x));
		yl = json_b64(s, t, json_get(s, t, obj, "y"), y, sizeof(y));
		k->pkey = xl == 32 && yl == 32 ? p256_key(x, y) : NULL;
	}

	if (k->pkey == NULL) {
		fprintf(stderr, "idp: key %s: unusable public key\n", k->kid);
		return -1;
	}

	return 1;
}

static void free_keys(idp_conf_t *c)
{
	int i;

	for (i = 0; i < c->n_keys; i++) {
		EVP_PKEY_free(c->keys[i].pkey);
	}
	c->n_keys = 0;
}

static char *read_file(const char *path, size_t max, size_t *len)
{
	FILE *fp = fopen(path, "rb");
	char *buf;
	size_t n;

	if (fp == NULL) {
		perror(path);
		return NULL;
	}

	buf = malloc(max + 1);
	if (buf == NULL) {
		fclose(fp);
		return NULL;
	}

	n = fread(buf, 1, max + 1, fp);
	fclose(fp);
	if (n > max) {
		fprintf(stderr, "%s: larger than %zu bytes\n", path, max);
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	*len = n;

	return buf;
}

static int load_jwks(const char *path, idp_conf_t *c)
{
	static json_tok_t t[JWKS_TOKENS];
	char *s;
	size_t len;
	int keys, i, k, r;
	int ret = -1;

	s = read_file(path, JWKS_FILE_MAX, &len);
	if (s == NULL) {
		return -1;
	}

	if (json_parse(s, len, t, JWKS_TOKENS) < 0 ||
			(keys = json_get(s, t, 0, "keys")) < 0 || t[keys].type != JSON_ARRAY) {
		fprintf(stderr, "idp: %s: not a JWKS ({\"keys\": [...]})\n", path);
		goto out;
	}

	for (k = 0, i = keys + 1; k < t[keys].size; k++, i = t[i].next) {
		if (t[i].type != JSON_OBJECT) {
			fprintf(stderr, "idp: %s: keys[%d] is not an object\n", path, k);
			goto out;
		}
		if (c->n_keys >= IDP_MAX_KEYS) {
			fprintf(stderr, "idp: %s: more than %d signing keys\n", path, IDP_MAX_KEYS);
			goto out;
		}

		memset(&c->keys[c->n_keys], 0, sizeof(c->keys[0]));
		r = parse_jwk(s, t, i, &c->keys[c->n_keys]);
		if (r < 0) {
			goto out;
		}
		c->n_keys += r;
	}

	/* 같은 kid 가 둘이면 토큰이 어느 키로 확인될지가 순서에 달린다. */
	for (i = 0; i < c->n_keys; i++) {
		for (k = i + 1; k < c->n_keys; k++) {
			if (strcmp(c->keys[i].kid, c->keys[k].kid) == 0) {
				fprintf(stderr, "idp: %s: duplicate kid %s\n", path, c->keys[i].kid);
				goto out;
			}
		}
	}

	if (c->n_keys == 0) {
		fprintf(stderr, "idp: %s: no RS256 / ES256 signing key\n", path);
		goto out;
	}
	ret = c->n_keys;

out:
	free(s);
	return ret;
}

/* ---- 설정 ----------------------------------------------------------------------- */

static int set_str(char *dst, size_t cap, const char *v, const char *what, int lineno)
{
	if (strlen(v) >= cap) {
		fprintf(stderr, "idp: line %d: %s too long\n", lineno, what);
		return -1;
	}
	strcpy(dst, v);

	return 0;
}

int idp_load(const char *path)
{
	static idp_conf_t staged;
	char line[512], key[32], val[IDP_URL_MAX + 1], extra[2];
	const char *slash;
	size_t dir_len;
	FILE *fp;
	int lineno = 0, nf;
	char *hash, *end;

	memset(&staged, 0, sizeof(staged));
	strcpy(staged.user_claim, "sub");
	strcpy(staged.groups_claim, "groups");
	staged.leeway = 30;

	fp = fopen(path, "r");
	if (fp == NULL) {
		perror(path);
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineno++;
		hash = strchr(line, '#');
		if (hash != NULL) {
			*hash = '\0';
		}

		nf = sscanf(line, "%31s %256s %1s", key, val, extra);
		if (nf <= 0) {
			continue;
		}
		if (nf != 2) {
			fprintf(stderr, "idp: line %d: expected <key> <value>\n", lineno);
			goto fail;
		}

		if (strcmp(key, "issuer") == 0) {
			if (set_str(staged.issuer, sizeof(staged.issuer), val, key, lineno) < 0) goto fail;
		}
		else if (strcmp(key, "audience") == 0) {
			if (set_str(staged.audience, sizeof(staged.audience), val, key, lineno) < 0) goto fail;
		}
		else if (strcmp(key, "jwks") == 0) {
			/* 상대 경로는 설정 파일이 있는 곳 기준이다. 서버를 어느 디렉터리에서 띄우든
			 * 같은 파일을 읽는다. */
			slash = strrchr(path, '/');
			if (val[0] != '/' && slash != NULL) {
				dir_len = (size_t)(slash - path) + 1;
				if (dir_len + strlen(val) >= sizeof(staged.jwks)) {
					fprintf(stderr, "idp: line %d: jwks path too long\n", lineno);
					goto fail;
				}
				memcpy(staged.jwks, path, dir_len);
				strcpy(staged.jwks + dir_len, val);
			}
			else if (set_str(staged.jwks, sizeof(staged.jwks), val, key, lineno) < 0) {
				goto fail;
			}
		}
		else if (strcmp(key, "user-claim") == 0) {
			if (set_str(staged.user_claim, sizeof(staged.user_claim), val, key, lineno) < 0) goto fail;
		}
		else if (strcmp(key, "groups-claim") == 0) {
			if (set_str(staged.groups_claim, sizeof(staged.groups_claim), val, key, lineno) < 0) goto fail;
		}
		else if (strcmp(key, "dpop") == 0) {
			if (strcmp(val, "required") != 0 && strcmp(val, "optional") != 0) {
				fprintf(stderr, "idp: line %d: dpop must be required or optional\n", lineno);
				goto fail;
			}
			staged.dpop_required = strcmp(val, "required") == 0;
		}
		else if (strcmp(key, "leeway") == 0) {
			staged.leeway = strtol(val, &end, 10);
			if (*end != '\0' || staged.leeway < 0 || staged.leeway > 300) {
				fprintf(stderr, "idp: line %d: leeway must be 0..300 seconds\n", lineno);
				goto fail;
			}
		}
		else {
			fprintf(stderr, "idp: line %d: unknown key '%s'\n", lineno, key);
			goto fail;
		}
	}
	fclose(fp);
	fp = NULL;

	/* issuer 와 audience 를 비워 두면 "아무 IdP 가 아무 서비스에 준 토큰"도 받게 된다.
	 * 같은 IdP 가 다른 앱에 준 토큰으로 VPN 에 들어오는 것을 aud 가 막는다. */
	if (staged.issuer[0] == '\0' || staged.audience[0] == '\0' || staged.jwks[0] == '\0') {
		fprintf(stderr, "idp: %s: issuer, audience and jwks are required\n", path);
		goto fail;
	}

	if (load_jwks(staged.jwks, &staged) < 0) {
		free_keys(&staged);
		goto fail;
	}

	free_keys(&conf);
	conf = staged;
	loaded = 1;

	return conf.n_keys;

fail:
	if (fp != NULL) {
		fclose(fp);
	}
	return -1;
}

int idp_enabled(void)
{
	return loaded;
}

void idp_dump(void)
{
	int i;

	if (!loaded) {
		return;
	}
	printf("--- idp ---\n");
	printf("issuer=%s audience=%s user-claim=%s groups-claim=%s leeway=%llds\n",
			conf.issuer, conf.audience, conf.user_claim, conf.groups_claim,
			(long long)conf.leeway);
	for (i = 0; i < conf.n_keys; i++) {
		printf("key %s %s\n", conf.keys[i].kid,
				conf.keys[i].alg == ALG_RS256 ? "RS256" : "ES256");
	}
}

const char *idp_status_name(int status)
{
	switch (status) {
		case LOGIN_OK:		return "ok";
		case LOGIN_NO_IDP:	return "no_idp";
		case LOGIN_MALFORMED:	return "malformed";
		case LOGIN_UNTRUSTED:	return "untrusted";
		case LOGIN_WRONG_TOKEN:	return "wrong_token";
		case LOGIN_EXPIRED:	return "expired";
		case LOGIN_BAD_USER:	return "bad_user";
		case LOGIN_DPOP:	return "dpop";
		default:		return "other";
	}
}

/* ---- 검증 ----------------------------------------------------------------------- */

/* JWS 의 ES256 서명은 r | s 를 32 바이트씩 붙인 것이고, OpenSSL 은 DER(ECDSA-Sig-Value)을
 * 받는다. */
static int es256_der(const uint8_t *raw, size_t len, uint8_t *der, size_t cap)
{
	ECDSA_SIG *sig;
	BIGNUM *r, *s;
	unsigned char *p = der;
	int n;

	if (len != 64 || cap < 80) {
		return -1;
	}

	sig = ECDSA_SIG_new();
	r = BN_bin2bn(raw, 32, NULL);
	s = BN_bin2bn(raw + 32, 32, NULL);
	if (sig == NULL || r == NULL || s == NULL || !ECDSA_SIG_set0(sig, r, s)) {
		BN_free(r);
		BN_free(s);
		ECDSA_SIG_free(sig);
		return -1;
	}

	n = i2d_ECDSA_SIG(sig, &p);
	ECDSA_SIG_free(sig);

	return n;
}

static int signature_ok(const idp_key_t *k, const char *signed_part, size_t signed_len,
		const uint8_t *sig, size_t sig_len)
{
	uint8_t der[80];
	EVP_MD_CTX *md;
	int n, ok = 0;

	if (k->alg == ALG_ES256) {
		n = es256_der(sig, sig_len, der, sizeof(der));
		if (n < 0) {
			return 0;
		}
		sig = der;
		sig_len = (size_t)n;
	}

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		return 0;
	}
	if (EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k->pkey) == 1 &&
			EVP_DigestVerify(md, sig, sig_len, (const uint8_t *)signed_part, signed_len) == 1) {
		ok = 1;
	}
	EVP_MD_CTX_free(md);

	return ok;
}

static int audience_ok(const char *s, const json_tok_t *t, int aud)
{
	int i, k;

	if (aud < 0) {
		return 0;
	}
	if (t[aud].type == JSON_STRING) {
		return json_eq(s, t, aud, conf.audience);
	}
	if (t[aud].type != JSON_ARRAY) {
		return 0;
	}
	for (k = 0, i = aud + 1; k < t[aud].size; k++, i = t[i].next) {
		if (json_eq(s, t, i, conf.audience)) {
			return 1;
		}
	}

	return 0;
}

/* 그룹 클레임은 없어도 된다 (그룹 없는 사용자). 있는데 배열이 아니면 토큰을 받지 않는다.
 * 쓸 수 없는 글자가 든 그룹 이름이나 넘치는 그룹은 건너뛴다 — 그룹은 권한을 더해 주기만
 * 하므로, 빠지면 덜 허용될 뿐 더 허용되지 않는다. */
static int read_groups(const char *s, const json_tok_t *t, int obj, user_identity_t *out)
{
	char name[USER_NAME_MAX];
	int g, i, k;

	g = json_get(s, t, obj, conf.groups_claim);
	if (g < 0) {
		return 0;
	}
	if (t[g].type != JSON_ARRAY) {
		return -1;
	}

	for (k = 0, i = g + 1; k < t[g].size; k++, i = t[i].next) {
		if (out->n_groups >= USER_GROUPS_MAX) {
			break;
		}
		if (json_string(s, t, i, name, sizeof(name)) <= 0 || !user_name_valid(name)) {
			continue;
		}
		strcpy(out->groups[out->n_groups++], name);
	}

	return 0;
}

/* ---- DPoP (proto.h) ---------------------------------------------------------- */

static void b64url_encode(const uint8_t *in, size_t len, char *out)
{
	static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i, o = 0;

	for (i = 0; i + 2 < len; i += 3) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4 | in[i + 1] >> 4];
		out[o++] = a[(in[i + 1] & 15) << 2 | in[i + 2] >> 6];
		out[o++] = a[in[i + 2] & 63];
	}
	if (len - i == 1) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4];
	}
	else if (len - i == 2) {
		out[o++] = a[in[i] >> 2];
		out[o++] = a[(in[i] & 3) << 4 | in[i + 1] >> 4];
		out[o++] = a[(in[i + 1] & 15) << 2];
	}
	out[o] = '\0';
}

static int sha256_b64(const void *data, size_t len, char out[44])
{
	uint8_t h[32];
	unsigned int hl = 0;

	if (EVP_Digest(data, len, h, &hl, EVP_sha256(), NULL) != 1 || hl != 32) {
		return -1;
	}
	b64url_encode(h, sizeof(h), out);
	return 0;
}

/* 최근에 받은 증명의 jti. 같은 증명을 두 번 받지 않는다 (DPOP_IAT_WINDOW 안에서만 기억하면 된다). */
#define JTI_RING	512
static struct { char h[44]; int64_t at; } jti_seen[JTI_RING];
static int jti_next;

static int jti_fresh(const char *jti, int64_t now)
{
	char h[44];
	int i;

	if (sha256_b64(jti, strlen(jti), h) < 0) {
		return 0;
	}
	for (i = 0; i < JTI_RING; i++) {
		if (jti_seen[i].at != 0 && now - jti_seen[i].at <= 2 * DPOP_IAT_WINDOW && strcmp(jti_seen[i].h, h) == 0) {
			return 0;
		}
	}
	strcpy(jti_seen[jti_next].h, h);
	jti_seen[jti_next].at = now;
	jti_next = (jti_next + 1) % JTI_RING;
	return 1;
}

/* 증명이 이 토큰(ath)과 이 키(jkt)의 것이고 지금 만든 것인가. */
static int dpop_ok(const char *proof, size_t len, const char *token, size_t token_len, const char *jkt, int64_t now)
{
	static uint8_t header[2048], payload[2048], sig[128];
	static json_tok_t t[64];
	char x[64], y[64], thumb_in[200], thumb[44], ath[44], s[256];
	uint8_t xb[64], yb[64];
	const char *dot1, *dot2;
	idp_key_t k;
	int64_t iat;
	int hl, pl, sl, jwk, v, ok = 0;

	dot1 = memchr(proof, '.', len);
	dot2 = dot1 != NULL ? memchr(dot1 + 1, '.', len - (size_t)(dot1 + 1 - proof)) : NULL;
	if (dot1 == NULL || dot2 == NULL) {
		return 0;
	}
	hl = b64url_decode(proof, (size_t)(dot1 - proof), header, sizeof(header) - 1);
	pl = b64url_decode(dot1 + 1, (size_t)(dot2 - dot1 - 1), payload, sizeof(payload) - 1);
	sl = b64url_decode(dot2 + 1, len - (size_t)(dot2 + 1 - proof), sig, sizeof(sig));
	if (hl <= 0 || pl <= 0 || sl != 64) {
		return 0;
	}

	/* 헤더: typ, alg, 그리고 증명한 키 그 자체. */
	if (json_parse((const char *)header, (size_t)hl, t, 64) < 0 || t[0].type != JSON_OBJECT ||
			(v = json_get((const char *)header, t, 0, "typ")) < 0 || !json_eq((const char *)header, t, v, "dpop+jwt") ||
			(v = json_get((const char *)header, t, 0, "alg")) < 0 || !json_eq((const char *)header, t, v, "ES256") ||
			(jwk = json_get((const char *)header, t, 0, "jwk")) < 0 || t[jwk].type != JSON_OBJECT ||
			(v = json_get((const char *)header, t, jwk, "kty")) < 0 || !json_eq((const char *)header, t, v, "EC") ||
			(v = json_get((const char *)header, t, jwk, "crv")) < 0 || !json_eq((const char *)header, t, v, "P-256") ||
			json_b64((const char *)header, t, json_get((const char *)header, t, jwk, "x"), xb, sizeof(xb)) != 32 ||
			json_b64((const char *)header, t, json_get((const char *)header, t, jwk, "y"), yb, sizeof(yb)) != 32) {
		return 0;
	}

	/* 지문은 키의 값으로 다시 만든다 (RFC 7638: 정해진 순서와 모양의 JSON 의 SHA-256). 적혀 온 글자를
	 * 그대로 쓰면 같은 키의 다른 표기가 다른 지문이 된다. */
	b64url_encode(xb, 32, x);
	b64url_encode(yb, 32, y);
	snprintf(thumb_in, sizeof(thumb_in), "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", x, y);
	if (sha256_b64(thumb_in, strlen(thumb_in), thumb) < 0 || strcmp(thumb, jkt) != 0) {
		return 0;
	}

	k.alg = ALG_ES256;
	k.pkey = p256_key(xb, yb);
	if (k.pkey == NULL) {
		return 0;
	}
	if (!signature_ok(&k, proof, (size_t)(dot2 - proof), sig, (size_t)sl)) {
		goto out;
	}

	/* 본문: 무엇에 대한 증명인가, 언제 만든 것인가. */
	if (json_parse((const char *)payload, (size_t)pl, t, 64) < 0 || t[0].type != JSON_OBJECT ||
			(v = json_get((const char *)payload, t, 0, "htm")) < 0 || !json_eq((const char *)payload, t, v, DPOP_HTM) ||
			(v = json_get((const char *)payload, t, 0, "htu")) < 0 || !json_eq((const char *)payload, t, v, DPOP_HTU) ||
			(v = json_get((const char *)payload, t, 0, "iat")) < 0 || json_int64((const char *)payload, t, v, &iat) < 0 ||
			iat > now + DPOP_IAT_WINDOW || iat < now - DPOP_IAT_WINDOW ||
			(v = json_get((const char *)payload, t, 0, "ath")) < 0 || json_string((const char *)payload, t, v, s, sizeof(s)) <= 0 ||
			sha256_b64(token, token_len, ath) < 0 || strcmp(s, ath) != 0 ||
			(v = json_get((const char *)payload, t, 0, "jti")) < 0 || json_string((const char *)payload, t, v, s, sizeof(s)) <= 0) {
		goto out;
	}
	ok = jti_fresh(s, now);

out:
	EVP_PKEY_free(k.pkey);
	return ok;
}

int idp_verify(const char *token, size_t len, const char *proof, size_t proof_len, int64_t now,
		user_identity_t *out)
{
	static uint8_t header[JWT_PART_MAX], payload[JWT_PART_MAX], sig[JWT_PART_MAX];
	static json_tok_t t[JWT_TOKENS];
	const char *dot1, *dot2;
	const idp_key_t *key = NULL;
	char kid[IDP_KID_MAX];
	int64_t exp, nbf;
	int hl, pl, sl, alg_want, i, v;
	int alg, kidt, iss, aud;

	if (!loaded) {
		return LOGIN_NO_IDP;
	}
	memset(out, 0, sizeof(*out));

	if (len == 0 || len > LOGIN_TOKEN_MAX) {
		return LOGIN_MALFORMED;
	}

	/* header.payload.signature — 점은 정확히 둘. 토큰을 다른 형식(JWE 의 다섯 부분)과
	 * 헷갈리지 않는다. */
	dot1 = memchr(token, '.', len);
	dot2 = dot1 != NULL ? memchr(dot1 + 1, '.', len - (size_t)(dot1 + 1 - token)) : NULL;
	if (dot1 == NULL || dot2 == NULL ||
			memchr(dot2 + 1, '.', len - (size_t)(dot2 + 1 - token)) != NULL) {
		return LOGIN_MALFORMED;
	}

	hl = b64url_decode(token, (size_t)(dot1 - token), header, sizeof(header));
	pl = b64url_decode(dot1 + 1, (size_t)(dot2 - dot1 - 1), payload, sizeof(payload));
	sl = b64url_decode(dot2 + 1, len - (size_t)(dot2 + 1 - token), sig, sizeof(sig));
	if (hl <= 0 || pl <= 0 || sl <= 0) {
		return LOGIN_MALFORMED;
	}

	/* 헤더: 어떤 키로 어떤 알고리즘인가. 여기서 정한 것은 아직 아무도 보증하지 않는다 —
	 * 그래서 알고리즘은 우리가 받는 목록에서만 고르고, 키는 우리가 가진 것에서만 찾는다. */
	if (json_parse((const char *)header, (size_t)hl, t, JWT_TOKENS) < 0 || t[0].type != JSON_OBJECT) {
		return LOGIN_MALFORMED;
	}
	alg = json_get((const char *)header, t, 0, "alg");
	kidt = json_get((const char *)header, t, 0, "kid");
	if (alg < 0 || kidt < 0) {
		return LOGIN_MALFORMED;
	}
	if (json_get((const char *)header, t, 0, "crit") >= 0) {
		return LOGIN_UNTRUSTED;
	}
	if (json_eq((const char *)header, t, alg, "RS256")) {
		alg_want = ALG_RS256;
	}
	else if (json_eq((const char *)header, t, alg, "ES256")) {
		alg_want = ALG_ES256;
	}
	else {
		return LOGIN_UNTRUSTED;
	}
	if (json_string((const char *)header, t, kidt, kid, sizeof(kid)) <= 0) {
		return LOGIN_MALFORMED;
	}

	for (i = 0; i < conf.n_keys; i++) {
		if (strcmp(conf.keys[i].kid, kid) == 0) {
			key = &conf.keys[i];
			break;
		}
	}
	if (key == NULL || key->alg != alg_want) {
		return LOGIN_UNTRUSTED;
	}

	/* 서명은 base64url 로 적힌 그대로의 "header.payload" 에 대한 것이다. */
	if (!signature_ok(key, token, (size_t)(dot2 - token), sig, (size_t)sl)) {
		return LOGIN_UNTRUSTED;
	}

	/* 여기부터는 IdP 가 서명한 내용이다. 그래도 그 토큰이 우리에게 준 것인지, 지금 쓸 수
	 * 있는 것인지는 따로 본다. */
	if (json_parse((const char *)payload, (size_t)pl, t, JWT_TOKENS) < 0 || t[0].type != JSON_OBJECT) {
		return LOGIN_MALFORMED;
	}

	iss = json_get((const char *)payload, t, 0, "iss");
	aud = json_get((const char *)payload, t, 0, "aud");
	if (iss < 0 || !json_eq((const char *)payload, t, iss, conf.issuer) ||
			!audience_ok((const char *)payload, t, aud)) {
		return LOGIN_WRONG_TOKEN;
	}

	v = json_get((const char *)payload, t, 0, "exp");
	if (v < 0 || json_int64((const char *)payload, t, v, &exp) < 0) {
		return LOGIN_MALFORMED;
	}
	if (now >= exp + conf.leeway) {
		return LOGIN_EXPIRED;
	}
	v = json_get((const char *)payload, t, 0, "nbf");
	if (v >= 0) {
		if (json_int64((const char *)payload, t, v, &nbf) < 0) {
			return LOGIN_MALFORMED;
		}
		if (now + conf.leeway < nbf) {
			return LOGIN_EXPIRED;
		}
	}

	v = json_get((const char *)payload, t, 0, conf.user_claim);
	if (v < 0 || json_string((const char *)payload, t, v, out->name, sizeof(out->name)) <= 0 ||
			!user_name_valid(out->name)) {
		memset(out, 0, sizeof(*out));
		return LOGIN_BAD_USER;
	}

	if (read_groups((const char *)payload, t, 0, out) < 0) {
		memset(out, 0, sizeof(*out));
		return LOGIN_MALFORMED;
	}

	/* 기기에 묶인 토큰이면 그 키의 증명이 있어야 한다. 묶이지 않은 토큰은 설정에 따라. */
	v = json_get((const char *)payload, t, 0, "cnf");
	{
		char jkt[64] = "";
		int j = v >= 0 && t[v].type == JSON_OBJECT ? json_get((const char *)payload, t, v, "jkt") : -1;

		if (v >= 0 && (j < 0 || json_string((const char *)payload, t, j, jkt, sizeof(jkt)) <= 0)) {
			memset(out, 0, sizeof(*out));
			return LOGIN_MALFORMED;
		}
		if (jkt[0] != '\0' ? proof == NULL || !dpop_ok(proof, proof_len, token, len, jkt, now) : conf.dpop_required) {
			memset(out, 0, sizeof(*out));
			return LOGIN_DPOP;
		}
	}

	/* 봐주는 시간은 받을 때만 쓴다. 세션에 붙여 둔 사용자는 토큰에 적힌 그 순간에 끝난다. */
	out->expires = exp;

	return LOGIN_OK;
}
