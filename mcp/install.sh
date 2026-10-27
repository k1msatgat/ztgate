#!/usr/bin/env bash
# 서버 장비에서 실행. vpn_server 를 systemd 서비스로, MCP 서버를 /opt/ztgate 에 설치한다.
# 소스를 고친 뒤 다시 실행하면 갱신된다 (설정과 기기 목록은 건드리지 않는다).
#
#   mcp/install.sh [mcp-user]     mcp-user: MCP 서버를 돌릴 계정 (기본: 지금 계정).
#                                 없는 계정이면 만든다.
#
# 설치되는 것은 전부 root 소유다. 서비스와 헬퍼는 root 로 도는데, 일반 계정이 고칠 수
# 있는 파일을 실행하면 그 계정이 곧 root 가 된다. 그래서 저장소의 파일을 직접 가리키지
# 않고 복사해 둔다.

set -eu

MCP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(dirname "$MCP_DIR")
MCP_USER=${1:-$(id -un)}

OPT=/opt/ztgate
ETC=/etc/ztgate
CTL=/usr/local/sbin/ztgate_ctl

say() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

# 빌드는 일반 사용자로 한다 (bin/ 과 node_modules 가 root 소유가 되지 않도록).
[ "$(id -u)" -ne 0 ] || die "run as a normal user; the script calls sudo itself"

make -C "$ROOT_DIR" --no-print-directory server
(cd "$MCP_DIR" && npm ci --omit=dev --no-audit --no-fund)

if ! id "$MCP_USER" > /dev/null 2>&1; then
	sudo useradd --system --create-home --shell /bin/bash "$MCP_USER"
	say "created account $MCP_USER (add the AI client's key to ~$MCP_USER/.ssh/authorized_keys)"
fi

sudo install -d -m 755 "$OPT/server/bin" "$OPT/test" "$OPT/libexec" "$OPT/mcp"
sudo install -m 755 "$ROOT_DIR/server/bin/vpn_server" "$OPT/server/bin/vpn_server"
sudo install -m 644 "$ROOT_DIR/test/auth_check.py" "$OPT/test/auth_check.py"
sudo install -m 755 "$MCP_DIR/service.sh" "$OPT/libexec/service.sh"
sudo install -m 755 "$ROOT_DIR/packaging/ztgate-user.sh" "$OPT/libexec/ztgate-user.sh"
sudo install -m 755 "$MCP_DIR/ctl.cjs" "$CTL"

sudo rm -rf "$OPT/mcp/node_modules"
sudo cp -r "$MCP_DIR/node_modules" "$OPT/mcp/node_modules"
sudo install -m 644 "$MCP_DIR/package.json" "$MCP_DIR/server.js" "$OPT/mcp/"
sudo chown -R root:root "$OPT"

# ssh 로 부를 이름. 비대화형 ssh 의 PATH 에도 /usr/local/bin 은 들어 있다.
printf '#!/bin/sh\nexec /usr/bin/node %s/mcp/server.js\n' "$OPT" | sudo install -m 755 /dev/stdin /usr/local/bin/ztgate_mcp

# 설정은 처음 한 번만 만든다. 기기 목록에는 키가 있어 서버가 600 이 아니면 읽지 않는다.
sudo install -d -m 700 "$ETC"
if ! sudo test -e "$ETC/server.env"; then
	# 터널 밖으로의 전달은 꺼 둔 채로 만든다. 켜려면 관리자가 나가는 인터페이스를 적는다.
	printf 'PORT=9000\nTUN_IP=10.0.0.1\nPREFIX=24\nMTU=1400\n# FORWARD_OUT=eth0\n# SESSION_LIFETIME=3600\n# PUBLIC_ADDRESS=vpn.example.com\n' | sudo install -m 600 /dev/stdin "$ETC/server.env"
fi
if ! sudo test -e "$ETC/devices.conf"; then
	printf '# id (32 hex)  key (64 hex 또는 p256:<공개키>)  tunnel-ip  requirements  # label\n' | sudo install -m 600 /dev/stdin "$ETC/devices.conf"
fi
# 서버 키. 처음 한 번만 만든다 — 바꾸면 등록 코드로 올라온 기기가 모두 다시 등록해야 한다.
if ! sudo test -e "$ETC/server.key"; then
	sudo "$OPT/server/bin/vpn_server" genkey "$ETC/server.key" > /dev/null
fi

# 서버는 ztgate 계정으로 돈다 (계정, /etc/ztgate 소유, 콘솔 계정은 /etc/ztgate-console).
sudo "$OPT/libexec/ztgate-user.sh"

sudo install -m 644 "$MCP_DIR/ztgate.service" /etc/systemd/system/ztgate.service
sudo systemctl daemon-reload

# 헬퍼 하나만, 인자 없이 부르는 것만 허용한다. 잘못된 sudoers 는 sudo 전체를 막으므로
# 검사를 통과한 뒤에 옮긴다.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
printf '%s ALL=(root) NOPASSWD: %s ""\n' "$MCP_USER" "$CTL" > "$TMP"
sudo visudo -cf "$TMP" > /dev/null || die "generated sudoers file is invalid"
sudo install -m 440 "$TMP" /etc/sudoers.d/ztgate_mcp

say "installed. MCP command for $MCP_USER: ztgate_mcp"
if systemctl is-active --quiet ztgate.service; then
	say "ztgate.service is running the old binary until it is restarted"
fi
