#!/bin/sh
# 커넥터 패키지를 설치하거나 올린 뒤 한 번 (DEB 의 postinst, RPM 의 %post). 있는 것은 건드리지 않는다.
# 등록하지 않은 장비에서는 서비스를 켜지 않는다. ztgate-connector enroll 이 켠다.
set -e

install -d -m 755 /etc/ztgate-connector
install -d -m 700 /var/lib/ztgate-connector

if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	# 돌고 있던 커넥터만 새 실행 파일로 다시 올린다. 세션은 바로 다시 붙는다.
	systemctl try-restart ztgate-connector.service || true
fi
