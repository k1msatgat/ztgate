#!/bin/sh
# 부 서버: 관리자 안내서의 2단계(동기화 계정, 주 서버의 공개키, rsync 와 다시 읽기 / 다시 띄우기만
# 허락) 뒤에 서버를 띄운다. systemd 가 없어 다시 읽기는 SIGHUP, 다시 띄우기는 TERM 으로 대신한다.
# Debian 에는 sync 라는 시스템 계정이 이미 있어 ztsync 로 만든다.
set -e
id ztsync > /dev/null 2>&1 || useradd -m -s /bin/sh ztsync
install -d -m 700 -o ztsync -g ztsync /home/ztsync/.ssh
install -m 600 -o ztsync -g ztsync /ha/keys/sync.key.pub /home/ztsync/.ssh/authorized_keys
printf 'ztsync ALL=(root) NOPASSWD: /usr/bin/rsync, /usr/bin/pkill -HUP -x vpn_server, /usr/bin/pkill -TERM -x vpn_server\n' > /etc/sudoers.d/ztsync
chmod 440 /etc/sudoers.d/ztsync
install -m 600 /ha/keys/host_ed25519 /etc/ssh/ssh_host_ed25519_key
mkdir -p /run/sshd
/usr/sbin/sshd -o HostKey=/etc/ssh/ssh_host_ed25519_key -o PasswordAuthentication=no
exec entrypoint.sh server
