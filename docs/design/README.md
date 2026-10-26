# UX 고도화 — 기능 단위 지도

2026-10-26 사용자 승인. 색과 글꼴은 [tokens.md](tokens.md), 모듈마다 무엇을 바꿨는지는 git 기록에 있다.

| 모듈 | 하는 일 | 먼저 있어야 하는 것 |
|---|---|---|
| `design-tokens` | 네이비 + 청록 색 토큰, 다크 모드, 상태색, 글꼴, 간격, 로고 ([tokens.md](tokens.md)) | — |
| `web-console` | 콘솔 재디자인: 사이드바, 대시보드, 상태 배지, ACL 편집, 감사 로그, 다크 모드 | design-tokens |
| `windows-gui` | `windows/gui/ui_theme.cpp` 색을 토큰으로, 연결 상태 표시 강화 | design-tokens |
| `cli-output` | 운영자 명령 `ztgate`(tools/cli, `ztgate_ctl` 의 답을 표와 색으로)와 Linux 클라이언트 터미널 출력의 색 (터미널일 때만, `NO_COLOR` 존중) | design-tokens |
| `readme-visuals` | 히어로 배너, SVG 그림, 스크린샷, 배지 색 통일 | web-console, windows-gui |

만드는 순서: design-tokens → web-console → windows-gui, cli-output → readme-visuals

공통 전제

- 기능은 바꾸지 않는다. 겉모습과 쓰는 흐름만 바꾼다.
- 웹 콘솔은 표준 라이브러리만 쓰는 Python 파일 하나로 남는다 (외부 파일, 글꼴, CDN 없음).
- 운영 서버 배포는 따로 묻는다.
