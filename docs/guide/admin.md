# ztgate 서버 운영하기

이 안내서는 ztgate 서버를 설치하고 기기를 들이는 순서를 적습니다. 서버 요건, 매일 쓰는 명령, 문제 해결은 [운영 참고](admin-reference.md)에 있습니다. 모든 옵션과 동작 원리는 [README](../../README.md)에 있습니다.

## 서버 설치하기

1. 서버에 패키지를 설치합니다. Ubuntu 에서는 deb, Rocky Linux 와 RHEL 에서는 rpm 입니다.

   ```bash
   sudo apt install ./ztgate-server_<버전>_amd64.deb
   sudo dnf install ./ztgate-server-<버전>-1.x86_64.rpm
   ```

   설치는 서버 키(`/etc/ztgate/server.key`)와 기본 설정(`/etc/ztgate/server.env`)을 처음 한 번 만듭니다.

2. 서버 키를 바로 백업합니다 ([설정 백업하기](#설정-백업하기)). 서버 키를 잃으면 모든 기기가 다시 등록해야 합니다.

3. `/etc/ztgate/server.env` 를 고칩니다. 자주 바꾸는 값은 아래와 같습니다.

   ```bash
   PORT=9000                        # 기기가 붙는 UDP 포트
   TUN_IP=10.0.0.1                  # 터널 안의 서버 주소. 기기는 같은 /24 대역의 주소를 받습니다
   PUBLIC_ADDRESS=vpn.example.com   # 기기가 밖에서 서버에 닿는 이름. 적으면 초대 링크가 만들어집니다
   # TCP_PORT=443                   # UDP 를 막는 네트워크에 있는 기기를 받으려면
   # FORWARD_OUT=eth0               # 터널에서 서버 뒤의 사내망으로 내보내려면 그 인터페이스
   ```

4. 서버를 켜고 상태를 봅니다.

   ```bash
   sudo systemctl enable --now ztgate
   sudo ztgate status
   ```

서버는 root 가 아닌 `ztgate` 계정으로 돕니다. `/etc/ztgate` 의 파일을 손으로 고쳤으면 `sudo systemctl reload ztgate` 를 실행합니다. `kill -HUP` 로 보내면 파일 소유가 맞춰지지 않아 서버가 그 파일을 읽지 못합니다.

## 웹 관리 콘솔 켜기

1. 콘솔을 켜고 관리자 계정을 만듭니다. 계정을 만들 때 비밀번호를 묻고, `--totp` 를 붙이면 인증 앱에 넣을 키를 보여 줍니다.

   ```bash
   sudo systemctl enable --now ztgate-console
   sudo /opt/ztgate/tools/ztgate_console.py user add admin --role admin --totp
   ```

2. 관리자 PC 에서 서버로 터널을 엽니다. 콘솔은 서버 안의 `127.0.0.1:9470` 에서만 듣습니다.

   ```bash
   ssh -L 9470:127.0.0.1:9470 <서버>
   ```

3. 브라우저로 `http://127.0.0.1:9470/` 에 들어갑니다.

보기만 할 사람에게는 `--role viewer` 로 계정을 줍니다. 콘솔에서 한 일은 그 계정 이름과 함께 감사 로그에 남습니다.

## 기기 들이기

1. 콘솔의 **등록 코드**에서 이름, 태그, 접속 조건(방화벽, 백신, 디스크 암호화), 유효 시간을 정하고 **코드 만들기**를 누릅니다. 터널 주소는 비워 두면 서버가 정합니다.
2. 그 사람에게 초대 링크를 보냅니다. 초대 링크(`ztgate://enroll?...`)는 `server.env` 에 `PUBLIC_ADDRESS` 를 적었을 때 코드 옆에 나옵니다. Windows 에서 링크를 누르면 등록 창이 열립니다 ([사용자 안내서](user.md)).
3. 링크가 없으면 코드와 서버 이름, 포트를 함께 보냅니다.

코드와 링크는 한 번만 쓰이고, 정한 시간이 지나면 쓸 수 없습니다. 코드는 비밀번호처럼 그 사람에게만 보냅니다. 쓰지 않은 코드는 콘솔에서 거둡니다.

기기를 빼려면 콘솔의 **기기**에서 그 기기를 지웁니다. 붙어 있던 기기는 10초 안에 끊깁니다.

## 접근 정책 정하기

기기마다의 조건은 코드를 만들 때 정합니다. 나중에 바꾸려면 콘솔에서 그 기기를 편집합니다. 조건에 못 미치는 PC 는 터널에 들어오지 못합니다. 그 PC 의 화면에는 무엇을 고치면 되는지가 나옵니다.

기기가 어디에 닿을 수 있는지는 ACL 이 정합니다. 콘솔의 **ACL** 에서 한 줄에 규칙 하나를 적습니다. 서버는 위에서부터 처음 맞는 규칙을 따르고, 맞는 규칙이 없으면 거부합니다.

```
10.0.0.0/24   10.10.0.0/16  tcp  443  allow  tag=eng firewall=on
10.0.0.0/24   10.10.5.20    tcp  22   allow  group=ops
```

- `tag=` 는 기기의 역할입니다.
- `user=` 와 `group=` 은 로그인한 사용자입니다. IdP 를 붙였을 때만 씁니다.
- `firewall=on` 같은 조건은 그 순간의 PC 상태입니다.

ACL 을 처음 켤 때는 서버를 다시 시작합니다. 그 뒤에 고친 규칙은 다시 시작하지 않아도 바로 적용됩니다.

사용자 로그인(SSO)을 켜려면 Keycloak 이나 Entra ID 같은 IdP 를 `/etc/ztgate/idp.conf` 에 적습니다. 방법은 README 의 "사용자 로그인" 절에 있습니다.

## 설정 백업하기

```bash
sudo systemctl enable --now ztgate-backup.timer   # 하루 한 번, /var/backups/ztgate 에 최근 14개를 둡니다
sudo ztgate-backup                                # 지금 한 번 백업합니다
sudo ztgate-backup restore <파일>                 # 지금 설정을 백업한 뒤 되살리고 서버를 다시 올립니다
```

백업에는 서버 키와 콘솔 계정이 들어 있습니다. 서버 밖으로 옮길 때는 암호화합니다.

## 서버 두 대로 장애에 대비하기

1. 두 번째 서버를 같은 방법으로 설치합니다. `server.env` 의 `TUN_IP` 는 첫 서버와 같게 둡니다.
2. 두 번째 서버(부 서버)에 동기화 계정을 만듭니다. 그 계정에는 첫 서버(주 서버)의 공개키를 등록하고, `sudo rsync` 와 `sudo systemctl reload ztgate` 만 허락합니다.
3. 주 서버에 `/etc/ztgate/sync.conf` 를 만듭니다.

   ```bash
   PEERS="sync@10.0.0.11"
   SSH_KEY=/etc/ztgate/sync.key
   ```

4. 주 서버에서 한 번 보내 보고, 자동 동기화를 켭니다. 그 뒤로는 기기 목록이나 ACL 이 바뀔 때마다 부 서버로 갑니다.

   ```bash
   sudo ztgate-sync
   sudo systemctl enable --now ztgate-sync.path ztgate-sync.timer
   ```

5. PC 에 두 서버를 모두 적습니다. 주 서버를 첫 번째로 적습니다. 기기는 첫 번째 서버에 등록하기 때문입니다.
   - 초대 링크를 쓰면 `PUBLIC_ADDRESS=vpn1.example.com,vpn2.example.com` 처럼 적습니다.
   - Windows 정책을 쓰면 `Servers` 에 쉼표로 이어 적습니다.

설정은 주 서버에서만 고칩니다. 부 서버의 관리 도구는 설정을 고치는 명령을 거절합니다. 주 서버가 꺼져 있는 동안 부 서버는 마지막으로 받은 설정으로 기기를 계속 받습니다. 그동안에는 새 기기를 등록하거나 정책을 바꿀 수 없습니다.

## Windows PC 에 배포하기

1. `ztgate.msi` 를 Intune, SCCM, 그룹 정책 소프트웨어 설치 가운데 하나로 배포합니다. VC++ 재배포 패키지는 필요 없습니다.
2. 그룹 정책 템플릿(`ztgate.admx`, `ztgate.adml`)으로 정책을 정합니다. 정책으로 정한 값은 사용자가 바꿀 수 없습니다.
   - 서버: `Servers`, `Port`
   - 늘 연결: `AlwaysOn`
   - 끊긴 동안 사내망 차단: `BlockWhenDown`
   - 로그인 IdP: `Issuer`, `ClientId`
   - 자동 업데이트: `UpdateUrl`, `UpdatePublicKey`
3. 자동 업데이트를 쓰려면 서명 키를 한 번 만듭니다(`tools/update/ztgate_update_sign.py genkey`). 새 버전을 낼 때마다 매니페스트에 서명해 업데이트 서버에 올립니다. 서명 키는 업데이트 서버에 두지 않습니다.

## 새 버전으로 올리기

1. 서버를 먼저 올립니다. 새 패키지를 설치하면 서버가 스스로 다시 올라오고, 붙어 있던 PC 는 바로 다시 붙습니다. 서버가 두 대면 부 서버를 먼저, 주 서버를 나중에 올립니다.
2. 그다음 PC 를 자동 업데이트나 배포 도구로 올립니다.

PC 와 서버의 버전이 맞지 않으면 서버가 그 PC 에게 알려 줍니다. 그 PC 의 화면에는 업데이트가 필요하다는 안내가 나오고, 자동 업데이트를 쓰는 PC 는 업데이트를 바로 확인합니다. 아직 올라오지 않은 PC 의 수는 지표 `version_mismatch` 로 봅니다.
