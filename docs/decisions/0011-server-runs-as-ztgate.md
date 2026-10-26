# 0011. 서버는 root 가 아닌 ztgate 계정으로 돈다

- 상태: 채택
- 날짜: 2026-10-27

## 맥락

`ztgate.service` 는 `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict` 로 묶여 있었지만 uid 0 이었다. 패킷을 다루는 C 코드에 메모리 버그가 하나 있으면, 그 프로세스는 `/etc/ztgate` 의 모든 파일(서버 키, ACL, 콘솔의 관리자 계정과 토큰)을 고칠 수 있었다. 상용화 검토에서 높음으로 나왔다.

## 결정

- 서버는 시스템 계정 `ztgate` 로 돈다 (`User=ztgate`). 받는 힘은 tun 을 여는 `CAP_NET_ADMIN` 과 낮은 TCP 포트(`-t 443`)를 여는 `CAP_NET_BIND_SERVICE` 뿐이다 (`AmbientCapabilities`). 소켓 종류도 IPv4 / IPv6 / UNIX / netlink 로 묶는다.
- tun 에 주소를 붙이고 전달 규칙(nft)을 넣는 일은 root 로 따로 한다 (`ExecStartPost=+`, `ExecStopPost=+`).
- `/etc/ztgate` 는 `ztgate` 소유다. 서버가 등록 코드로 온 기기를 `devices.conf` 에 직접 쓰기(rename) 때문이다. 관리자가 root 로 고친 파일도 읽히도록, 서비스를 띄우고 다시 읽기 직전에 `packaging/ztgate-user.sh` 가 소유를 맞춘다 (`ExecStartPre=+`, `ExecReload=+`). `ztgate_ctl` 도 쓴 파일을 `ztgate` 소유로 바꾼다.
- 콘솔의 토큰과 계정은 `/etc/ztgate-console` (root, 700) 으로 옮긴다. 서버가 쓸 수 있는 폴더 안에 두면 서버를 차지한 쪽이 관리자 계정을 바꿔 넣을 수 있다. 예전 자리에 있으면 같은 스크립트가 옮긴다.
- 지표 내보내기(`ztgate-exporter`)도 `ztgate` 로 돈다 (상태 소켓이 `ztgate` 소유 `/run/ztgate` 안에 있다).

## 검토한 다른 길

- **서버가 쓰는 파일만 따로 폴더(`/var/lib/ztgate`)로** — 서버 키와 기기 목록을 옮기면 `ztgate_ctl`, 시험, 문서, 운영 중인 서버의 경로가 모두 바뀐다. 지금은 폴더의 소유만 바꾸고 콘솔 파일을 밖으로 빼는 쪽이 바뀌는 곳이 적다.
- **특권 분리(root 부모 + 권한 없는 자식)** — 설정 쓰기를 부모가 맡으면 가장 단단하지만, 프로세스 둘과 그 사이의 약속이 생긴다. systemd 의 `+` 실행으로 root 일이 시작 / 종료 때뿐이므로 지금은 필요하지 않다.
- **seccomp (`SystemCallFilter`)** — 아직 systemd 아래에서 실제 트래픽을 흘리는 시험이 없어, 막힌 시스템 호출로 서버가 조용히 죽는 것을 CI 가 잡지 못한다. 그 시험이 생기면 더한다.

## 결과

- 서버를 차지해도 서버 키와 정책 파일은 고칠 수 있지만, 콘솔 계정, 다른 시스템 파일, root 권한에는 닿지 못한다.
- 관리자가 `/etc/ztgate` 의 파일을 root 로 고친 뒤 `systemctl reload ztgate` 를 하면 소유가 맞춰진다. `kill -HUP` 를 직접 보내면 그렇지 않다.
- 콘솔 파일의 자리가 바뀌었다 (`/etc/ztgate-console`). 백업(`ztgate-backup`)은 두 폴더를 함께 묶는다.
- CI 의 deb 작업이 설치한 서비스에서 `vpn_server` 의 사용자가 `ztgate` 인지, 서버 키가 `ztgate:600` 인지, 콘솔 폴더가 `root:700` 인지 본다.
