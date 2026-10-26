#!/usr/bin/env bash
# tools/backup/ztgate-backup 시험. root 도 서버도 없이 임시 폴더에서 돈다.
#
#   test/backup_check.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B="$ROOT/tools/backup/ztgate-backup"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export ZTGATE_ETC="$W/etc/ztgate" BACKUP_DIR="$W/backups" ZTGATE_UNIT="" KEEP=3

failed=0
check() {
	if [ "$2" = "$3" ]; then
		printf 'ok    %-58s %s\n' "$1" "$2"
	else
		printf 'FAIL  %-58s %s   (want %s)\n' "$1" "$2" "$3"
		failed=$((failed + 1))
	fi
}

mkdir -p "$ZTGATE_ETC"
echo "device-list v1" > "$ZTGATE_ETC/devices.conf"
echo "secret" > "$ZTGATE_ETC/server.key"
touch "$ZTGATE_ETC/.ztgate.lock"

first=$("$B")
check "backup: a file is made" "$([ -f "$first" ] && echo yes)" yes
check "backup: mode 600" "$(stat -c %a "$first")" 600
check "backup: the lock file is left out" "$(tar -tzf "$first" | grep -c '.ztgate.lock')" 0

echo "device-list v2" > "$ZTGATE_ETC/devices.conf"
"$B" restore "$first" > /dev/null
check "restore: the old device list is back" "$(cat "$ZTGATE_ETC/devices.conf")" "device-list v1"
check "restore: the configuration it replaced was saved first" "$(ls "$BACKUP_DIR" | wc -l)" 2

for _ in 1 2 3 4; do "$B" > /dev/null; done
check "retention: only KEEP backups are kept" "$(ls "$BACKUP_DIR" | wc -l)" 3

mkdir -p "$W/evil/ztgate" "$W/evil/other"
echo x > "$W/evil/ztgate/server.key"
echo x > "$W/evil/other/passwd"
tar -czf "$W/outside.tar.gz" -C "$W/evil" ztgate other
check "restore: refuses a path outside ztgate/" "$("$B" restore "$W/outside.tar.gz" > /dev/null 2>&1 || echo refused)" refused
ln -s /etc/shadow "$W/evil/ztgate/link"
tar -czf "$W/link.tar.gz" -C "$W/evil" ztgate
check "restore: refuses a symbolic link" "$("$B" restore "$W/link.tar.gz" > /dev/null 2>&1 || echo refused)" refused
mkdir -p "$W/nokey/ztgate" && echo x > "$W/nokey/ztgate/devices.conf"
tar -czf "$W/nokey.tar.gz" -C "$W/nokey" ztgate
check "restore: refuses a backup without the server key" "$("$B" restore "$W/nokey.tar.gz" > /dev/null 2>&1 || echo refused)" refused
check "a refused restore leaves the configuration alone" "$(cat "$ZTGATE_ETC/devices.conf")" "device-list v1"

echo
[ "$failed" = 0 ] && echo "all passed" || echo "$failed FAILED"
exit $((failed > 0))
