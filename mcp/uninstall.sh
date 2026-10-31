#!/usr/bin/env bash
# mcp/install.sh 가 설치한 것(MCP 서버, 배포기, sudoers)을 지운다. 서버 패키지는 건드리지 않는다 — 서버를 지우려면
# sudo dnf remove ztgate-server 나 sudo apt purge ztgate-server (/etc/ztgate 는 어느 쪽도 남긴다).
#
#   mcp/uninstall.sh            보관 패키지와 작업 기록(/var/lib/ztgate-deploy), deploy.conf 는 남긴다
#   mcp/uninstall.sh --purge    그것까지 지운다
#
# install.sh 가 만든 계정은 지우지 않는다.

set -eu

if systemctl is-active --quiet ztgate-deploy.service; then
	echo "[uninstall] ERROR: a deploy job is running (systemctl status ztgate-deploy); wait for it" >&2
	exit 1
fi
sudo rm -f /etc/sudoers.d/ztgate_mcp /usr/local/bin/ztgate_mcp
sudo rm -rf /opt/ztgate-mcp

if [ "${1:-}" = --purge ]; then
	sudo rm -rf /var/lib/ztgate-deploy /etc/ztgate-deploy
	echo "[uninstall] removed, including /var/lib/ztgate-deploy and /etc/ztgate-deploy"
else
	echo "[uninstall] removed; /var/lib/ztgate-deploy (kept packages) and /etc/ztgate-deploy are kept (--purge deletes them)"
fi
