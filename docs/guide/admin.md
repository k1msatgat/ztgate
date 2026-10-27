# ztgate 운영자 안내서

ztgate 서버를 설치하고, 기기를 들이고, 정책을 정하고, 매일 돌보는 사람을 위한 안내서입니다. 각 기능이 어떻게 동작하는지, 그리고 모든 옵션은 [README](../../README.md)에 있습니다. 여기에는 할 일의 순서만 적습니다.

## 1. 준비

| 항목 | 내용 |
|---|---|
| 서버 | Ubuntu 22.04 / 24.04 또는 Rocky / RHEL 9, x86_64. 공인 주소나 포트 포워딩 |
| 포트 | UDP 9000 (기본, `PORT`). UDP 가 막힌 곳의 PC 를 받으려면 TCP 도 열고 `TCP_PORT` 를 적습니다 (443 같은 낮은 번호도 됩니다) |
| 이름 | `vpn.example.com` 같은 DNS 이름을 권합니다. PC 는 연결할 때마다 이름을 다시 풀어, 서버 주소를 바꿔도 PC 를 다시 설정하지 않아도 됩니다 |
| 함께 쓰는 것 | Node.js (관리 도구 `ztgate_ctl`), nftables (서버 뒤 네트워크로 내보낼 때), rsync (서버 두 대) |

## 2. 설치

```bash
sudo apt install ./ztgate-server_<버전>_amd64.deb      # Ubuntu
sudo dnf install ./ztgate-server-<버전>-1.x86_64.rpm   # Rocky / RHEL
```

설치하면 서버 키(`/etc/ztgate/server.key`)와 기본 설정(`/etc/ztgate/server.env`)이 처음 한 번 만들어집니다. 서버 키는 서버가 지키는 단 하나의 비밀입니다. **바로 백업하세요** (6절).

`/etc/ztgate/server.env` 에서 바꿀 만한 것은 다음과 같습니다.

```bash
PORT=9000
TUN_IP=10.0.0.1                  # 터널 안의 서버 주소. 기기들은 같은 대역(/24)의 주소를 받습니다
PUBLIC_ADDRESS=vpn.example.com   # PC 가 밖에서 서버에 닿는 이름. 있으면 초대 링크가 만들어집니다
# TCP_PORT=443                   # UDP 가 막힌 네트워크용
# FORWARD_OUT=eth0               # 터널에서 서버 뒤의 사내망으로 내보낼 인터페이스
```

```bash
sudo systemctl enable --now ztgate
sudo ztgate status               # 세션 0 개, 서버가 떠 있는지
```

서버는 root 가 아닌 `ztgate` 계정으로 돕니다. `/etc/ztgate` 의 파일을 손으로 고쳤으면 `sudo systemctl reload ztgate` 로 다시 읽게 합니다 (`kill -HUP` 이 아니라 reload 여야 파일 소유가 맞춰집니다).

## 3. 웹 관리 콘솔

```bash
sudo systemctl enable --now ztgate-console
sudo /opt/ztgate/tools/ztgate_console.py user add admin --role admin --totp   # 비밀번호를 묻고, TOTP 키를 보여 줍니다
```

콘솔은 서버 안(127.0.0.1:9470)에서만 듣습니다. 관리자 PC 에서 `ssh -L 9470:127.0.0.1:9470 <서버>` 로 연 뒤 브라우저로 `http://127.0.0.1:9470/` 에 들어갑니다. 보기만 할 사람에게는 `--role viewer` 로 계정을 줍니다. 콘솔에서 한 일은 누가 했는지와 함께 감사 로그에 남습니다.

## 4. 기기 들이기

1. 콘솔의 **등록 코드**에서 이름, 태그, 접속 조건(방화벽, 백신, 디스크 암호화), 유효 시간을 정해 코드를 만듭니다. 터널 주소는 비워 두면 알아서 정해집니다.
2. `PUBLIC_ADDRESS` 를 적어 두었으면 **초대 링크**(`ztgate://enroll?...`)가 함께 나옵니다. 링크를 그 사람에게 메일이나 메신저로 보냅니다. 받은 사람은 Windows 에서 링크를 누르기만 하면 됩니다 ([사용자 안내서](user.md)).
3. 링크가 없으면 코드와 서버 이름, 포트를 함께 알려 줍니다.

코드와 링크는 **한 번만 쓰이고 정한 시간이 지나면 끝납니다.** 코드는 비밀번호처럼 그 사람에게만 보냅니다. 쓰지 않은 코드는 콘솔에서 거둡니다.

기기를 빼려면 콘솔의 **기기**에서 지웁니다. 붙어 있던 기기는 10초 안에 끊깁니다.

## 5. 정책

- **기기마다의 조건**은 코드를 만들 때 정하고, 콘솔의 기기 편집에서 바꿉니다. 조건에 못 미치는 PC 는 터널에 들어오지 못하고, 사용자 화면에는 무엇을 고치면 되는지가 나옵니다 ("Windows 방화벽이 꺼져 있습니다" 등).
- **어디에 닿을 수 있는가**는 ACL 입니다. 콘솔의 **ACL** 에서 한 줄에 규칙 하나로 적고, 위에서부터 처음 맞는 규칙을 따릅니다. 맞는 규칙이 없으면 거부합니다.

  ```
  10.0.0.0/24   10.10.0.0/16  tcp  443  allow  tag=eng firewall=on
  10.0.0.0/24   10.10.5.20    tcp  22   allow  group=ops
  ```

  `tag=` 는 기기의 역할, `user=` / `group=` 은 로그인한 사용자(IdP 를 붙였을 때), `firewall=on` 같은 것은 그 순간의 PC 상태입니다. 처음 ACL 을 켤 때만 서버를 다시 시작합니다. 그 뒤로 고치는 것은 바로 반영됩니다.
- **사용자 로그인(SSO)** 은 IdP(Keycloak, Entra ID 등)를 `/etc/ztgate/idp.conf` 에 적어 켭니다. 방법은 README 의 "사용자 로그인" 절에 있습니다.

## 6. 백업과 되살리기

```bash
sudo systemctl enable --now ztgate-backup.timer   # 하루 한 번, /var/backups/ztgate 에 최근 14개
sudo ztgate-backup                                # 지금 한 번
sudo ztgate-backup restore <파일>                 # 지금 설정을 백업한 뒤 되살리고 서버를 다시 올립니다
```

백업에는 서버 키와 콘솔 계정이 들어 있습니다. 서버 밖으로 옮길 때는 암호화합니다. **서버 키를 잃으면 모든 기기가 다시 등록해야 합니다.**

## 7. 서버 두 대 (장애 조치)

1. 두 번째 서버를 같은 방법으로 설치합니다. `server.env` 의 `TUN_IP` 는 같게 둡니다.
2. 첫 서버(주)에 `/etc/ztgate/sync.conf` 를 만듭니다. 그다음 두 번째 서버(부)의 동기화 계정에 주 서버의 키를 등록하고, 그 계정에 `sudo rsync` 와 `sudo systemctl reload ztgate` 만 허락합니다.

   ```bash
   PEERS="sync@10.0.0.11"
   SSH_KEY=/etc/ztgate/sync.key
   ```

3. 주 서버에서 `sudo ztgate-sync` 로 한 번 보내 보고, `sudo systemctl enable --now ztgate-sync.path ztgate-sync.timer` 로 켭니다. 그 뒤로는 기기 목록과 ACL 이 바뀔 때마다 부 서버에 갑니다.
4. PC 에는 두 서버를 모두 적습니다. `PUBLIC_ADDRESS=vpn1.example.com,vpn2.example.com` 이면 초대 링크에 둘 다 들어가고, Windows 정책이라면 `Servers` 에 쉼표로 적습니다. **첫 번째는 주 서버여야 합니다** — 기기는 첫 서버에 등록합니다.

설정은 주 서버에서만 고칩니다. 부 서버의 관리 도구는 설정을 고치는 명령을 거절합니다. 주 서버가 죽어도 부 서버는 마지막 설정으로 계속 받지만, 그동안 새 등록과 정책 변경은 멈춥니다.

## 8. Windows PC 에 배포하기

- MSI(`ztgate.msi`)를 Intune, SCCM, GPO 소프트웨어 설치로 배포합니다. VC++ 재배포 패키지는 필요 없습니다.
- 그룹 정책 템플릿 `ztgate.admx` / `ztgate.adml` 로 서버(`Servers`, `Port`), 늘 연결(`AlwaysOn`), 끊긴 동안 사내망 차단(`BlockWhenDown`), 로그인 IdP, 자동 업데이트(`UpdateUrl`, `UpdatePublicKey`)를 정합니다. 정책으로 정한 값은 사용자가 바꿀 수 없습니다.
- 자동 업데이트를 쓰려면 서명 키를 한 번 만들고(`tools/update/ztgate_update_sign.py genkey`), 새 버전마다 매니페스트에 서명해 업데이트 서버에 올립니다. 서명 키는 업데이트 서버에 두지 않습니다.

## 9. 업그레이드

1. **서버를 먼저 올립니다.** 새 패키지를 설치하면 서버가 스스로 다시 올라오고, 붙어 있던 PC 는 바로 다시 붙습니다. 서버가 두 대면 부 서버, 주 서버 순서로 올립니다.
2. 그다음 PC 를 올립니다 (자동 업데이트나 배포 도구로).
3. 버전이 맞지 않는 PC 가 있으면 서버가 그 PC 에게 버전이 다르다고 알려 줍니다. PC 화면에는 "업데이트가 필요합니다"가 나오고, 자동 업데이트를 쓰면 바로 업데이트를 확인합니다. 아직 올라오지 않은 PC 의 수는 지표 `version_mismatch` 로 봅니다.

## 10. 매일 보는 것

| 보고 싶은 것 | 명령 |
|---|---|
| 지금 붙어 있는 PC 와 그 상태 | `sudo ztgate status`, 콘솔의 개요 |
| 누가 언제 무엇을 했나 | `sudo ztgate audit`, 콘솔의 감사 로그 (`/var/log/ztgate/audit.log`, 12주) |
| 서버 로그 | `journalctl -u ztgate` |
| 지표 (Prometheus) | `sudo systemctl enable --now ztgate-exporter` → `127.0.0.1:9469/metrics` |

## 11. 문제 해결

| 증상 | 확인할 것 |
|---|---|
| PC 가 "서버가 답하지 않습니다" | 서버가 떠 있는지(`systemctl status ztgate`), 서버와 클라우드의 방화벽에서 UDP 포트가 열렸는지. UDP 가 막힌 곳이면 `TCP_PORT` |
| PC 가 "서버에 이 기기가 없습니다" | 콘솔의 기기 목록에 있는지. 지웠다면 새 코드로 다시 등록합니다 |
| PC 가 "회사 보안 정책에 맞지 않습니다" | 그 기기의 조건과 PC 의 상태. 감사 로그의 `auth_denied` 에 사유가 있습니다 |
| 붙었는데 어떤 서버에만 못 닿음 | ACL 에 그 목적지의 `allow` 가 있는지, 조건(태그, 사용자, 포스처)이 맞는지. 감사 로그의 `access` 줄에 판정이 남습니다 |
| PC 가 "서버가 이 프로그램보다 새 버전입니다" | PC 를 올립니다 (9절) |
| 초대 링크가 나오지 않음 | `server.env` 에 `PUBLIC_ADDRESS` 가 있는지 |
| 부 서버에서 설정을 고칠 수 없음 | 정상입니다. 주 서버에서 고칩니다 (7절) |

## 12. 지금 할 수 없는 것

- **서버 키 바꾸기.** 서버 키를 바꾸면 모든 기기가 다시 등록해야 합니다. 기기를 다시 등록하지 않고 바꾸는 방법은 설계 중입니다 ([ADR 0013](../decisions/0013-server-key-rotation.md)). 서버 키가 샜다고 의심되면 새 키를 만들고 모든 기기를 다시 등록합니다.
- 서버 사이의 세션 넘겨주기. 다른 서버로 넘어간 PC 는 새로 연결하고, 그사이의 몇 초 동안 패킷을 잃습니다.
- macOS, iOS, Android 클라이언트.
