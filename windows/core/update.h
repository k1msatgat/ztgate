#ifndef UPDATE_H
#define UPDATE_H

/* 자동 업데이트 (정책의 UpdateUrl, policy.h). 서비스(SYSTEM)만 부른다.
 *
 * 관리자가 정한 HTTPS 주소에서 매니페스트를 받는다:
 *
 *   { "version": "0.9.1", "msi": "https://updates.example.com/ztgate-0.9.1.msi",
 *     "sha256": "<MSI 의 SHA-256, 64 hex>" }
 *
 * 지금 실행 파일보다 높은 버전이면 MSI 를 받아 SHA-256 을 맞춰 보고, 관리자만 쓸 수 있는 폴더
 * (%ProgramData%\ztgate\update)에 둔 뒤 msiexec 로 조용히 설치한다. MSI 의 업그레이드가 이 서비스를
 * 멈추고 새 것으로 다시 띄운다. 무엇을 믿는가: 매니페스트와 MSI 를 TLS 로 받으므로(인증서 검증은
 * WinHTTP) 그 주소의 주인이 내놓은 것이고, MSI 는 매니페스트의 해시와 같은 것이다. 그 주소는 관리자만
 * 정할 수 있다 (HKLM 정책). MSI 에 코드 서명은 아직 없다.
 *
 * 같은 버전의 설치가 실패했으면 하루 동안 다시 하지 않는다 (설치 → 실패 → 설치를 되풀이하지 않게). */

#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*update_log_fn)(const char *fmt, ...);

/* 한 번 확인하고, 새 버전이면 설치를 시작한다 (msiexec 를 띄우고 돌아온다). 블로킹. allow_http 는
 * 시험용 (정책의 UpdateAllowHttp) — 평문 HTTP 를 받는다. 1 설치를 시작했다, 0 할 일 없음, -1 실패. */
int update_check(const wchar_t *manifest_url, int allow_http, update_log_fn log);

#ifdef __cplusplus
}
#endif

#endif
