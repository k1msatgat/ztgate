#ifndef FILELOG_H
#define FILELOG_H

/* 서비스의 로그를 파일로도 남긴다. 서비스의 로그는 메모리의 고리(GUI 의 진단 창이 읽는다)에만
 * 있어서, 서비스가 죽거나 PC 를 다시 켜면 "무슨 일이 있었나"를 볼 곳이 없었다.
 *
 *   %ProgramData%\ztgate\logs\service.log      지금 것. 1MB 를 넘으면 service.1.log ... 로 돌린다
 *   %ProgramData%\ztgate\dumps\*.dmp           서비스가 처리되지 않은 예외로 죽을 때의 덤프
 *
 * 폴더는 SYSTEM 과 관리자만 쓰고 사용자는 읽기만 한다 — 로그를 지우거나 고쳐 흔적을 덮지 못하게,
 * 그리고 덤프(메모리의 사본, 세션 키가 들어 있을 수 있다)는 관리자만 읽게 한다. */

#ifdef __cplusplus
extern "C" {
#endif

/* 폴더를 만들고 로그 파일을 연다. 실패해도 서비스는 돈다 (그때는 메모리의 고리에만 남는다). */
void filelog_open(void);

/* 한 줄을 시각과 함께 적는다. 여러 스레드에서 불러도 된다. */
void filelog_write(const char *line);

void filelog_close(void);

/* 처리되지 않은 예외가 나면 덤프를 남기게 한다. 덤프를 쓰고 나면 프로세스는 그대로 죽고, 서비스
 * 관리자가 설치 파일에 적힌 대로 다시 올린다. */
void filelog_install_crash_handler(void);

#ifdef __cplusplus
}
#endif

#endif
