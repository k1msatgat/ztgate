#!/usr/bin/env bash
# tools/sync/ztgate-sync 시험. root 도 ssh 도 없이, 부 서버를 이 PC 의 폴더 둘로 둔다.
#
#   test/sync_check.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SYNC="$ROOT/tools/sync/ztgate-sync"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export ZTGATE_ETC="$W/a"

failed=0
check() {
	if [ "$2" = "$3" ]; then
		printf 'ok    %-58s %s\n' "$1" "$2"
	else
		printf 'FAIL  %-58s %s   (want %s)\n' "$1" "$2" "$3"
		failed=$((failed + 1))
	fi
}

mkdir -p "$W/a" "$W/b" "$W/c" "$W/sync"
export ZTGATE_SYNC_CONF="$W/sync/sync.conf"
echo "devices v1" > "$W/a/devices.conf"
echo "acl v1" > "$W/a/acl.conf"
echo "key" > "$W/a/server.key"
echo "PORT=9000" > "$W/a/server.env"
echo "pending" > "$W/a/enroll.conf"
chmod 600 "$W/a/devices.conf" "$W/a/server.key"
echo "FORWARD_OUT=eth1" > "$W/b/server.env"
conf() {
	printf 'PEERS="%s"\nRELOAD="echo reload >> %s"\nRESTART="echo restart >> %s"\n' "$1" "$W/log" "$W/log" > "$ZTGATE_SYNC_CONF"
	chmod 600 "$ZTGATE_SYNC_CONF"
}
conf "$W/b $W/c"

check "no sync.conf: refused" "$(ZTGATE_SYNC_CONF=$W/none "$SYNC" > /dev/null 2>&1; echo $?)" 1
chmod 620 "$ZTGATE_SYNC_CONF"
check "sync.conf writable by the group: refused" "$("$SYNC" > /dev/null 2>&1; echo $?)" 1
chmod 600 "$ZTGATE_SYNC_CONF"
cp "$ZTGATE_SYNC_CONF" "$W/a/sync.conf"
check "sync.conf inside the server's folder: refused" "$(ZTGATE_SYNC_CONF=$W/a/sync.conf "$SYNC" > /dev/null 2>&1; echo $?)" 1
rm "$W/a/sync.conf"

"$SYNC" > "$W/out" 2>&1
check "sync: exit" "$?" 0
check "sync: the device list reaches both" "$(cat "$W/b/devices.conf") / $(cat "$W/c/devices.conf")" "devices v1 / devices v1"
check "sync: acl and server key too" "$(cat "$W/b/acl.conf") / $(cat "$W/b/server.key")" "acl v1 / key"
check "sync: modes kept" "$(stat -c %a "$W/b/server.key")" 600
check "sync: server.env is each server's own" "$(cat "$W/b/server.env")" "FORWARD_OUT=eth1"
check "sync: enrollment codes stay on the primary" "$([ -e "$W/b/enroll.conf" ] && echo yes || echo no)" no
check "sync: a new server key restarts each peer" "$(cat "$W/log" | tr '\n' ' ')" "restart restart "
check "sync: the peer knows its primary, readable" "$(cat "$W/b/.sync-primary") $(stat -c %a "$W/b/.sync-primary")" "$(hostname) 644"

: > "$W/log"
echo "devices v2" > "$W/a/devices.conf"
"$SYNC" > /dev/null 2>&1
check "again: the change arrives" "$(cat "$W/b/devices.conf")" "devices v2"
check "again: only the device list changed, so a reload" "$(cat "$W/log" | tr '\n' ' ')" "reload reload "

: > "$W/log"
rm "$W/a/acl.conf"
"$SYNC" > /dev/null 2>&1
check "acl removed on the primary: removed on the peer" "$([ -e "$W/b/acl.conf" ] && echo yes || echo no)" no
check "acl removed: a restart (the acl is decided at start)" "$(cat "$W/log" | tr '\n' ' ')" "restart restart "

check "on a secondary: refused" "$(ZTGATE_ETC=$W/b "$SYNC" > /dev/null 2>&1; echo $?)" 1

conf "$W/b $W/missing/x"
echo "devices v3" > "$W/a/devices.conf"
"$SYNC" > /dev/null 2>&1
check "one peer unreachable: failure, the other still synced" "$? $(cat "$W/b/devices.conf")" "1 devices v3"

echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed FAILED"
exit $((failed != 0))
