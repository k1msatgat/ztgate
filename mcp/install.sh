#!/usr/bin/env bash
# 서버 장비에서 실행. MCP 서버와 배포기(ztgate-deploy)를 /opt/ztgate-mcp 에 설치한다. 서버 자신은 깔지 않는다 —
# 서버는 패키지(ztgate-server)이고, MCP 의 deploy 가 원격의 ref 를 패키지로 빌드해 깐다.
#
#   mcp/install.sh [mcp-user]     mcp-user: MCP 서버를 돌릴 계정 (기본: 지금 계정). 없는 계정이면 만든다.
#
# 새 장비: 이것을 돌린 뒤 MCP 로 deploy {"ref":"main","accept":["no_revert"]} 를 한 번 부르면 첫 패키지가 깔린다
# (되돌릴 이전 패키지가 없어서 no_revert 를 밝혀야 한다). 그다음 sudo ztgate setup 으로 서비스를 켠다.
# 예전 install.sh 로 서버를 깐 장비는 packaging/migrate-to-package.sh 로 패키지로 옮긴다.
#
# 다시 실행하면 MCP 와 배포기만 새것으로 바뀐다. /etc/ztgate-deploy/deploy.conf 는 처음 한 번만 만든다.
#
# 설치되는 것은 전부 root 소유다. 헬퍼는 root 로 도는데, 일반 계정이 고칠 수 있는 파일을 실행하면 그 계정이 곧
# root 가 된다. 그래서 저장소의 파일을 직접 가리키지 않고 복사해 둔다.

set -eu

MCP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MCP_USER=${1:-$(id -un)}

OPT=/opt/ztgate-mcp
DEPLOY=$OPT/libexec/ztgate-deploy
STATE=/var/lib/ztgate-deploy

say() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

# node_modules 가 root 소유가 되지 않도록 일반 사용자로 받는다.
[ "$(id -u)" -ne 0 ] || die "run as a normal user; the script calls sudo itself"

(cd "$MCP_DIR" && npm ci --omit=dev --no-audit --no-fund)

if ! id "$MCP_USER" > /dev/null 2>&1; then
	sudo useradd --system --create-home --shell /bin/bash "$MCP_USER"
	say "created account $MCP_USER (add the AI client's key to ~$MCP_USER/.ssh/authorized_keys)"
fi
# 배포기의 빌드는 이 계정으로, 네트워크 없이 빌드 폴더 안에서만 돈다.
if ! id ztgate-build > /dev/null 2>&1; then
	sudo useradd -r -M -d "$STATE/build" -s /usr/sbin/nologin -c "ztgate deploy builds" ztgate-build
fi

sudo install -d -m 755 "$OPT" "$OPT/libexec"
sudo rm -rf "$OPT/node_modules.new"
sudo cp -r "$MCP_DIR/node_modules" "$OPT/node_modules.new"
sudo rm -rf "$OPT/node_modules"
sudo mv "$OPT/node_modules.new" "$OPT/node_modules"
sudo install -m 644 "$MCP_DIR/package.json" "$MCP_DIR/server.js" "$OPT/"
sudo install -m 755 "$MCP_DIR/deploy.cjs" "$DEPLOY"
# 확장자 없는 배포기는 가장 가까운 package.json 을 따른다. 위의 것(MCP 서버)은 "type": "module" 이다.
printf '{ "type": "commonjs" }\n' | sudo install -m 644 /dev/stdin "$OPT/libexec/package.json"
sudo chown -R root:root "$OPT"

# ssh 로 부를 이름. 비대화형 ssh 의 PATH 에도 /usr/local/bin 은 들어 있다.
printf '#!/bin/sh\nexec /usr/bin/node %s/server.js\n' "$OPT" | sudo install -m 755 /dev/stdin /usr/local/bin/ztgate_mcp

sudo install -d -m 755 "$STATE"
sudo install -d -m 755 "$STATE/packages"
sudo install -d -m 700 "$STATE/jobs"

# 신뢰의 뿌리. 이 장비의 root 권한은 REPO 에서 BRANCHES 와 TAGS 로 닿는 커밋에 있다 (docs/decisions/0014).
sudo install -d -m 755 /etc/ztgate-deploy
if ! sudo test -e /etc/ztgate-deploy/deploy.conf; then
	printf '%s\n' \
		'# ztgate-deploy (MCP 의 deploy) 가 빌드하고 깔 수 있는 코드. root 만 고친다. KEY=VALUE 로만 읽는다.' \
		'#   REPO      https:// 주소 (또는 이 장비의 절대 경로)' \
		'#   BRANCHES  배포할 수 있는 브랜치. 이름이나 * 하나가 든 패턴을 공백으로 (운영 서버는 main 만 두는 것을 권한다)' \
		'#   TAGS      배포할 수 있는 태그. 비우면 받지 않는다' \
		'#   KEEP      되돌리기에 쓰려고 보관할 패키지 수 (1..50). 지금 것과 이전 것은 늘 남는다' \
		'# 같은 폴더에 allowed_signers 를 두면 그 키로 서명한 커밋만 깐다 (git verify-commit, gpg.format=ssh).' \
		'REPO=https://github.com/k1msatgat/ztgate.git' \
		'BRANCHES=*' \
		'TAGS=v*' \
		'KEEP=5' | sudo install -m 600 /dev/stdin /etc/ztgate-deploy/deploy.conf
fi

# 헬퍼 둘만, 인자 없이 부르는 것만 허용한다. ztgate_ctl 은 패키지의 /usr/sbin 에 있고, 예전 install.sh 로 깐
# 장비(패키지로 옮기기 전)에는 /usr/local/sbin 에 있다. 잘못된 sudoers 는 sudo 전체를 막으므로 검사를 통과한
# 뒤에 옮긴다.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
for ctl in /usr/sbin/ztgate_ctl /usr/local/sbin/ztgate_ctl; do
	if [ -e "$ctl" ]; then
		printf '%s ALL=(root) NOPASSWD: %s ""\n' "$MCP_USER" "$ctl" >> "$TMP"
	fi
done
printf '%s ALL=(root) NOPASSWD: %s ""\n' "$MCP_USER" "$DEPLOY" >> "$TMP"
sudo visudo -cf "$TMP" > /dev/null || die "generated sudoers file is invalid"
sudo install -m 440 "$TMP" /etc/sudoers.d/ztgate_mcp

say "installed. MCP command for $MCP_USER: ztgate_mcp"
if ! rpm -q ztgate-server > /dev/null 2>&1 && ! dpkg-query -W ztgate-server > /dev/null 2>&1; then
	if [ -e /usr/local/sbin/ztgate_ctl ]; then
		say "the server was installed by an older mcp/install.sh; move it to the package with packaging/migrate-to-package.sh"
	else
		say "no ztgate-server package yet: deploy {\"ref\":\"main\",\"accept\":[\"no_revert\"]} installs the first one"
	fi
fi
