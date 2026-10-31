#!/usr/bin/env bash
# 예전 mcp/install.sh 로 서버를 깐 장비를 패키지(ztgate-server) 배치로 옮긴다. 장비마다 한 번.
#
#   packaging/migrate-to-package.sh [--ref <commit>]           할 일과 사전 확인만 보여 준다 (기본)
#   packaging/migrate-to-package.sh --apply [--ref <commit>]   옮긴다
#   packaging/migrate-to-package.sh --undo [<state-dir>]       옮기기 전으로 (기본: 가장 최근의 /var/backups/ztgate/migrate-*)
#
# 일반 계정으로 저장소 체크아웃에서 돌린다 (mcp/install.sh 를 부른다). sudo 는 스스로 부른다. <commit> 의 기본은
# 이 체크아웃의 HEAD 다. 첫 패키지는 배포기(ztgate-deploy build)가 deploy.conf 의 REPO 에서 그 커밋을 받아 빌드한다.
# 그래서 그 커밋은 원격의 허용된 브랜치나 태그에 있어야 하고, 이 패키지는 나중의 배포와 같은 길로 만들어진다.
#
# 바꾸는 것
#   /etc/systemd/system/ztgate*.{service,timer,path}   패키지가 같은 이름을 가진 것은 지운다. 남기면 패키지의
#                                                      /usr/lib/systemd/system 의 유닛을 영원히 가린다. 콘솔 유닛의
#                                                      ExecStart (-l 주소) 와 Requires 가 패키지 것과 다르면 drop-in
#                                                      /etc/systemd/system/ztgate-console.service.d/listen.conf 로 옮긴다
#   /usr/local/sbin/ztgate_ctl, /opt/ztgate/mcp          지운다 (패키지의 /usr/sbin/ztgate_ctl, MCP 는 /opt/ztgate-mcp)
#   /opt/ztgate 의 나머지                                패키지 파일로 덮인다
#   sudoers                                              mcp/install.sh 가 /usr/sbin/ztgate_ctl 과 배포기로
# 건드리지 않는 것: /etc/ztgate, /etc/ztgate-console, /var/log/ztgate. 앞뒤의 sha256 이 하나라도 다르면 실패로 알린다.
#
# 서버는 한 번 내렸다 올린다 (세션이 한 번 끊기고 클라이언트는 30초 안에 다시 붙는다). 되돌리기의 근거는
# /var/backups/ztgate/migrate-<시각>/ 다: 옛 파일 묶음, 켜져 있던 유닛, 설정의 sha256, ztgate-backup 의 설정 백업.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEPLOY=/opt/ztgate-mcp/libexec/ztgate-deploy
UNITS="ztgate.service ztgate-console.service ztgate-exporter.service ztgate-jwks.service ztgate-jwks.timer ztgate-backup.service ztgate-backup.timer ztgate-sync.service ztgate-sync.path ztgate-sync.timer"
DROPIN=/etc/systemd/system/ztgate-console.service.d/listen.conf
OLD_FILES="/usr/local/sbin/ztgate_ctl /usr/local/bin/ztgate_mcp /etc/sudoers.d/ztgate_mcp /opt/ztgate"

say() { printf '[migrate] %s\n' "$*"; }
die() { printf '[migrate] ERROR: %s\n' "$*" >&2; exit 1; }

if [ -f /etc/debian_version ]; then
	KIND=deb
	pkg_version() { dpkg-query -W -f '${db:Status-Status} ${Version}' ztgate-server 2> /dev/null | awk '$1 == "installed" { print $2 }'; }
	pkg_install() { sudo dpkg -i "$1"; }
	pkg_remove() { sudo dpkg --purge ztgate-server; }
else
	KIND=rpm
	# 깔려 있지 않으면 rpm -q 는 그 말을 stdout 에 찍으므로 종료 코드로 가린다.
	pkg_version() { if rpm -q ztgate-server > /dev/null 2>&1; then rpm -q --qf '%{VERSION}-%{RELEASE}' ztgate-server; fi; }
	pkg_install() { sudo rpm -U "$1"; }
	pkg_remove() { sudo rpm -e ztgate-server; }
fi

etc_sums() { sudo find /etc/ztgate /etc/ztgate-console -type f ! -name .ztgate.lock -exec sha256sum {} + 2> /dev/null | sort; }
old_units() { for u in $UNITS; do [ ! -f "/etc/systemd/system/$u" ] || echo "$u"; done; }
# 한 줄에 셋: 이름, is-enabled, is-active. 없는 유닛에 is-enabled 가 아무것도 찍지 않는 판이 있어 not-found 로 채운다.
unit_state() {
	local e
	e=$(systemctl is-enabled "$1" 2> /dev/null || true)
	printf '%s %s %s\n' "$1" "${e:-not-found}" "$(systemctl is-active "$1" 2> /dev/null || true)"
}
# 옛 파일 묶음에 넣을 것. / 에서의 상대 경로로 (tar -C /). /etc/sudoers.d 는 root 만 들여다볼 수 있다.
old_paths() {
	for f in $OLD_FILES $(old_units | sed 's|^|/etc/systemd/system/|') /etc/systemd/system/ztgate*.service.d; do
		! sudo test -e "$f" || echo "${f#/}"
	done
}

# 예전 콘솔 유닛에서 패키지 유닛과 다른 ExecStart 와, Requires 를 drop-in 으로.
console_dropin() {
	local old=/etc/systemd/system/ztgate-console.service new=$ROOT/tools/console/ztgate-console.service exec req
	[ -f "$old" ] || return 0
	exec=$(grep '^ExecStart=' "$old" || true)
	req=$(grep '^Requires=' "$old" || true)
	[ "$exec" != "$(grep '^ExecStart=' "$new")" ] || exec=
	[ -n "$exec$req" ] || return 0
	echo "# packaging/migrate-to-package.sh 가 예전 /etc/systemd/system/ztgate-console.service 에서 옮긴 값"
	[ -z "$req" ] || printf '[Unit]\n%s\n' "$req"
	[ -z "$exec" ] || printf '[Service]\nExecStart=\n%s\n' "$exec"
}

undo() {
	local dir=${1:-$(sudo sh -c 'ls -1d /var/backups/ztgate/migrate-* 2> /dev/null' | sort | tail -n 1)}
	[ -n "$dir" ] && sudo test -f "$dir/code.tar.gz" || die "no migration state found (give the /var/backups/ztgate/migrate-<time> folder)"
	say "undo from $dir"
	sudo systemctl stop ztgate-console.service ztgate.service 2> /dev/null || true
	if [ -n "$(pkg_version)" ]; then
		pkg_remove > /dev/null
		say "removed the ztgate-server package (/etc/ztgate stays)"
	fi
	sudo rm -f "$DROPIN"
	sudo rmdir "$(dirname "$DROPIN")" 2> /dev/null || true
	sudo tar -xpzf "$dir/code.tar.gz" -C /
	sudo systemctl daemon-reload
	while read -r u enabled active; do
		[ "$enabled" != enabled ] || sudo systemctl reenable "$u" 2> /dev/null
	done < <(sudo cat "$dir/units.txt")
	while read -r u enabled active; do
		[ "$active" != active ] || sudo systemctl start "$u"
	done < <(sudo cat "$dir/units.txt")
	if [ "$(etc_sums)" = "$(sudo cat "$dir/etc.sha256")" ]; then
		say "ok: /etc/ztgate and /etc/ztgate-console are as before the migration"
	else
		die "/etc/ztgate differs from before the migration; the configuration backup is $(sudo cat "$dir/config-backup")"
	fi
	sudo cat "$dir/units.txt" | while read -r u enabled active; do
		printf '  %-24s %s %s   (before: %s %s)\n' "$u" "$(systemctl is-enabled "$u" 2> /dev/null || true)" "$(systemctl is-active "$u" 2> /dev/null || true)" "$enabled" "$active"
	done
}

MODE=plan
REF=
while [ $# -gt 0 ]; do
	case "$1" in
	--apply) MODE=apply ;;
	--undo) MODE=undo ;;
	--ref) REF=${2:?--ref needs a commit}; shift ;;
	*) [ "$MODE" = undo ] && UNDO_DIR=$1 || die "usage: migrate-to-package.sh [--apply] [--ref <commit>] | --undo [<state-dir>]" ;;
	esac
	shift
done

[ "$(id -u)" -ne 0 ] || die "run as a normal user from the repository checkout; the script calls sudo itself"
if [ "$MODE" = undo ]; then
	undo "${UNDO_DIR:-}"
	exit 0
fi

# ---- 사전 확인 (plan 과 apply 가 같이) ---------------------------------------
if [ -n "$(pkg_version)" ]; then
	say "the ztgate-server package is already installed ($(pkg_version)); nothing to migrate"
	exit 0
fi
[ -e /usr/local/sbin/ztgate_ctl ] || [ -e /etc/systemd/system/ztgate.service ] ||
	die "no server installed by mcp/install.sh here (/usr/local/sbin/ztgate_ctl, /etc/systemd/system/ztgate.service); for a new host see mcp/install.sh"
for t in git node make gcc $([ $KIND = rpm ] && echo rpmbuild || echo dpkg-deb); do
	command -v "$t" > /dev/null || die "$t is missing (the first package is built on this host)"
done
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] || die "node 18 or later is needed (ztgate_ctl, the deployer)"
REF=${REF:-$(git -C "$ROOT" rev-parse HEAD)}
MCP_USER=$(sudo awk '/NOPASSWD/ { print $1; exit }' /etc/sudoers.d/ztgate_mcp 2> /dev/null || true)
MCP_USER=${MCP_USER:-$(id -un)}
DROP=$(console_dropin)

say "package kind: $KIND; first package: ztgate-deploy build $REF (from REPO in /etc/ztgate-deploy/deploy.conf)"
say "MCP account: $MCP_USER (mcp/install.sh installs MCP and the deployer in /opt/ztgate-mcp)"
say "units now (name, enabled, active):"
for u in $UNITS; do
	s=$(unit_state "$u")
	case "$s" in *" not-found "*) continue ;; esac
	printf '  %-50s %s\n' "$s" "$([ -f "/etc/systemd/system/$u" ] && echo "/etc/systemd/system/$u is removed; the package's unit takes over" || true)"
done
say "saved, then removed or replaced: $(old_paths | sed 's|^|/|' | tr '\n' ' ')"
if [ -n "$DROP" ]; then
	say "console drop-in $DROPIN:"
	printf '%s\n' "$DROP" | sed 's/^/    /'
fi
say "kept as is: /etc/ztgate ($(sudo find /etc/ztgate -type f | wc -l) files), /etc/ztgate-console, /var/log/ztgate"

if [ "$MODE" = plan ]; then
	say "dry run: nothing changed. Run again with --apply."
	exit 0
fi

# ---- 옮기기 -----------------------------------------------------------------
STATE=/var/backups/ztgate/migrate-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 700 /var/backups/ztgate "$STATE"
for u in $UNITS; do unit_state "$u"; done | sudo tee "$STATE/units.txt" > /dev/null
etc_sums | sudo tee "$STATE/etc.sha256" > /dev/null
# shellcheck disable=SC2046
sudo tar -czpf "$STATE/code.tar.gz" -C / $(old_paths)
sudo ZTGATE_UNIT= "$ROOT/tools/backup/ztgate-backup" | sudo tee "$STATE/config-backup" > /dev/null
say "1/6 saved the old files, unit states and /etc/ztgate sha256 in $STATE (configuration: $(sudo cat "$STATE/config-backup"))"

"$ROOT/mcp/install.sh" "$MCP_USER" > /dev/null
say "2/6 installed MCP and the deployer (mcp/install.sh)"

out=$(sudo "$DEPLOY" build "$REF") || { printf '%s\n' "$out" | tail -n 20 >&2; die "the first package did not build; nothing on the server changed (undo: $0 --undo $STATE)"; }
FILE=$(printf '%s' "$out" | node -e 'const v = JSON.parse(require("fs").readFileSync(0, "utf8")); process.stdout.write(v.note)')
sudo test -f "$FILE" || die "the deployer reported no package file"
say "3/6 built the first package: $FILE"

sudo systemctl stop ztgate-console.service ztgate.service 2> /dev/null || true
for u in $(old_units); do sudo rm -f "/etc/systemd/system/$u"; done
sudo rm -f /usr/local/sbin/ztgate_ctl
sudo rm -rf /opt/ztgate/mcp
sudo systemctl daemon-reload
say "4/6 stopped the server, removed the old units, ztgate_ctl and /opt/ztgate/mcp"

pkg_install "$FILE" > /dev/null
if [ -n "$DROP" ]; then
	printf '%s\n' "$DROP" | sudo install -D -m 644 /dev/stdin "$DROPIN"
fi
sudo systemctl daemon-reload
while read -r u enabled active; do
	[ "$enabled" != enabled ] || sudo systemctl reenable "$u" 2> /dev/null
done < <(sudo cat "$STATE/units.txt")
while read -r u enabled active; do
	[ "$active" != active ] || sudo systemctl start "$u"
done < <(sudo cat "$STATE/units.txt")
say "5/6 installed $(pkg_version) and brought the units back as they were"

"$ROOT/mcp/install.sh" "$MCP_USER" > /dev/null
say "6/6 sudoers now points at /usr/sbin/ztgate_ctl and the deployer"

# ---- 확인 -------------------------------------------------------------------
bad=0
verify() {
	if [ "$2" = "$3" ]; then printf '  ok    %-56s %s\n' "$1" "$2"
	else printf '  FAIL  %-56s %s   (want %s)\n' "$1" "$2" "$3"; bad=$((bad + 1)); fi
}
verify "/etc/ztgate and /etc/ztgate-console unchanged (sha256)" "$([ "$(etc_sums)" = "$(sudo cat "$STATE/etc.sha256")" ] && echo same || echo differ)" same
while read -r u enabled active; do
	[ "$enabled $active" != "not-found inactive" ] || continue
	verify "$u" "$(systemctl is-enabled "$u" 2> /dev/null || true) $(systemctl is-active "$u" 2> /dev/null || true)" "$enabled $active"
	verify "$u comes from the package" "$(systemctl show -p FragmentPath --value "$u")" "/usr/lib/systemd/system/$u"
done < <(sudo cat "$STATE/units.txt")
if [ -n "$DROP" ] && systemctl is-active --quiet ztgate-console.service; then
	verify "ztgate-console uses the drop-in" "$(systemctl show -p DropInPaths --value ztgate-console.service)" "$DROPIN"
	listen=$(printf '%s\n' "$DROP" | sed -n 's/.* -l \([^ ]*\).*/\1/p')
	if [ -n "$listen" ]; then
		for _ in $(seq 20); do ss -ltnH | awk '{ print $4 }' | grep -qxF "$listen" && break; sleep 0.5; done
		verify "the console listens on $listen" "$(ss -ltnH | awk '{ print $4 }' | grep -xF "$listen" || true)" "$listen"
	fi
fi
verify "ztgate_ctl status" "$(echo '{"cmd":"status"}' | sudo /usr/sbin/ztgate_ctl | node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(0, "utf8")).ok))')" true
verify "the deployer sees its own package installed" "$(printf '{"cmd":"deploy_status"}' | sudo "$DEPLOY" | node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).installed.state)')" kept
verify "old ztgate_ctl gone" "$([ -e /usr/local/sbin/ztgate_ctl ] && echo present || echo gone)" gone
if [ "$bad" -ne 0 ]; then
	die "$bad check(s) failed; to go back: $0 --undo $STATE"
fi
say "migrated. The next MCP deploy can revert by itself. To go back: $0 --undo $STATE"
