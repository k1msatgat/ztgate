#ifndef UPDATE_H
#define UPDATE_H

/* 자동 업데이트 (정책의 UpdateUrl, policy.h). 서비스(SYSTEM)만 부른다.
 *
 * 관리자가 정한 HTTPS 주소에서 서명한 매니페스트를 받는다 (tools/update/ztgate_update_sign.py 가 만든다):
 *
 *   { "version": "0.9.1", "msi": "https://updates.example.com/ztgate-0.9.1.msi",
 *     "sha256": "<MSI 의 SHA-256, 64 hex>", "sig": "<ECDSA P-256 의 r | s, 128 hex>" }
 *
 * sig 는 "ztgate update v1\n" + version + "\n" + sha256 (적힌 그대로)에 대한 것이고, 정책 UpdatePublicKey 의
 * 공개키 가운데 하나로 맞아야 한다. 공개키가 없으면 업데이트하지 않는다. 서명이 맞고 지금 실행 파일보다
 * 높은 버전이면 MSI 를 받아 SHA-256 을 맞춰 보고, 관리자만 쓸 수 있는 폴더(%ProgramData%\ztgate\update)에
 * 둔 뒤 msiexec 로 조용히 설치한다. MSI 의 업그레이드가 이 서비스를 멈추고 새 것으로 다시 띄운다.
 *
 * 무엇을 믿는가: 설치할 MSI 를 정하는 것은 서명 키를 가진 쪽이다. 업데이트 서버(와 그 TLS 인증서)를
 * 차지해도 서명 키가 없으면 아무것도 설치시키지 못한다 — 서명 키는 업데이트 서버에 두지 않는다. 예전에
 * 서명한 매니페스트를 다시 내놓는 것은 지금보다 낮은 버전이라 아무 일도 하지 않는다. 업데이트를
 * 내놓지 않는 것(멈춰 두기)은 막지 못한다. MSI 에 코드 서명은 아직 없다.
 *
 * 같은 버전의 설치가 실패했으면 하루 동안 다시 하지 않는다 (설치 → 실패 → 설치를 되풀이하지 않게). */

#include <wchar.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UPDATE_PUB_LEN	64	/* P-256 공개키 X | Y */
#define UPDATE_KEYS_MAX	2	/* 키를 바꾸는 동안 옛 키와 새 키를 함께 둔다 */

typedef void (*update_log_fn)(const char *fmt, ...);

/* 한 번 확인하고, 새 버전이면 설치를 시작한다 (msiexec 를 띄우고 돌아온다). 블로킹. allow_http 는
 * 시험용 (정책의 UpdateAllowHttp) — 평문 HTTP 를 받는다. 1 설치를 시작했다, 0 할 일 없음, -1 실패. */
int update_check(const wchar_t *manifest_url, int allow_http, const uint8_t (*keys)[UPDATE_PUB_LEN], int n_keys,
		update_log_fn log);

/* 매니페스트의 세 값이 keys 가운데 하나로 서명됐는가. 1 / 0. */
int update_verify(const char *version, const char *sha_hex, const char *sig_hex,
		const uint8_t (*keys)[UPDATE_PUB_LEN], int n_keys);

/* 서명 도구가 만든 고정 벡터로 update_verify 를 본다. 실패한 수. */
int update_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
