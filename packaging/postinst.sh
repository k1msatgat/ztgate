#!/bin/sh
# 패키지를 설치하거나 올린 뒤 한 번 (DEB 의 postinst, RPM 의 %post 가 부른다). mcp/install.sh 의 설정
# 만들기와 같다. 있는 것은 건드리지 않는다 — 업그레이드해도 기기 목록과 서버 키가 그대로다.
# 서비스를 켜지는 않는다. 설정을 본 뒤 관리자가 systemctl enable --now ztgate 한다.
set -e

ETC=/etc/ztgate
install -d -m 700 "$ETC"
if [ ! -e "$ETC/server.env" ]; then
	printf 'PORT=9000\nTUN_IP=10.0.0.1\nPREFIX=24\nMTU=1400\n# FORWARD_OUT=eth0\n# SESSION_LIFETIME=3600\n# TCP_PORT=9000\n# WORKERS=1\n# STATEFUL=1\n' > "$ETC/server.env"
	chmod 600 "$ETC/server.env"
fi
if [ ! -e "$ETC/devices.conf" ]; then
	printf '# id (32 hex)  key (64 hex 또는 p256:<공개키>)  tunnel-ip  requirements  # label\n' > "$ETC/devices.conf"
	chmod 600 "$ETC/devices.conf"
fi
# 서버 키. 처음 한 번만 — 바꾸면 등록 코드로 올라온 기기가 모두 다시 등록해야 한다.
if [ ! -e "$ETC/server.key" ]; then
	/opt/ztgate/server/bin/vpn_server genkey "$ETC/server.key" > /dev/null
fi

if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	# 돌고 있던 서버는 새 실행 파일로 다시 올린다. 세션은 DISCONNECT 를 받고 바로 다시 붙는다.
	if systemctl is-active --quiet ztgate.service; then
		systemctl restart ztgate.service || true
	fi
fi
