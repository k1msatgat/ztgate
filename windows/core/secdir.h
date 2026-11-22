#ifndef WIN_SECDIR_H
#define WIN_SECDIR_H

/* 서비스(SYSTEM)가 %ProgramData%\ztgate 아래에 쓰는 폴더.
 *
 * ProgramData 는 일반 사용자에게 폴더를 만들 권한을 준다. 서비스가 처음 뜨기 전에 사용자가 같은 이름의
 * 폴더를 만들어 두면 그 사용자가 소유자로 남아 언제든 DACL 을 다시 바꿀 수 있고, 정션을 두면 SYSTEM 이
 * 쓰고 지우는 파일이 다른 곳으로 간다. 그래서 만들거나 이미 있던 폴더를 연 핸들에 소유자(SDDL 의 O:)와
 * 보호된 DACL 을 함께 다시 건다. 재분석 지점(정션, 심볼릭 링크)이면 링크만 지우고 새로 만든다. */

#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/* %ProgramData%\ztgate 와 logs, dumps. SYSTEM 과 관리자는 모두, 사용자는 읽기만. P 는 위
 * 폴더(ProgramData)의 권한을 물려받지 않는다는 뜻 — 물려받으면 누구나 그 안에 파일을 만들 수 있다. */
#define SECDIR_BASE_SDDL L"O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

/* sddl 은 소유자와 보호된 DACL 을 함께 적는다 (예: L"O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").
 * path 가 그 소유자와 DACL 을 가진 진짜 폴더가 되면 0, 아니면 -1 (그때는 그 폴더에 쓰지 않는다). */
int secdir_make(const wchar_t *path, const wchar_t *sddl);

#ifdef __cplusplus
}
#endif

#endif
