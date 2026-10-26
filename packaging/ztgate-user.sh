#!/bin/sh
# 서버를 root 가 아닌 ztgate 계정으로 돌리기 위한 계정과 파일 소유. 여러 번 돌려도 결과가 같다.
# packaging/postinst.sh 와 mcp/install.sh 가 부른다.
#
#   /etc/ztgate            ztgate 소유 (700). 서버가 등록 코드로 온 기기를 devices.conf 에 직접 쓴다
#   /etc/ztgate-console    root 소유 (700). 콘솔의 토큰과 계정 — 서버가 뚫려도 관리자 계정을 바꾸지 못하게
#                          서버가 쓰는 폴더 밖에 둔다. 예전 자리(/etc/ztgate/console.*)에 있으면 옮긴다
set -e

ETC=${ZTGATE_ETC:-/etc/ztgate}
CONSOLE=${ZTGATE_CONSOLE_ETC:-/etc/ztgate-console}

if ! getent passwd ztgate > /dev/null 2>&1; then
	useradd -r -M -d /nonexistent -s /usr/sbin/nologin -c "ztgate server" ztgate
fi

install -d -m 700 "$CONSOLE"
for f in console.token console.users; do
	if [ -e "$ETC/$f" ] && [ ! -e "$CONSOLE/$f" ]; then
		mv "$ETC/$f" "$CONSOLE/$f"
	fi
done
chown -R root:root "$CONSOLE"

install -d -m 700 "$ETC"
chown -R ztgate:ztgate "$ETC"
if [ -d /var/log/ztgate ]; then
	chown -R ztgate:ztgate /var/log/ztgate
fi
