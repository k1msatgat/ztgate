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

mkdir -p "$W/a" "$W/b" "$W/c"
echo "devices v1" > "$W/a/devices.conf"
echo "acl v1" > "$W/a/acl.conf"
echo "key" > "$W/a/server.key"
echo "PORT=9000" > "$W/a/server.env"
echo "pending" > "$W/a/enroll.conf"
chmod 600 "$W/a/devices.conf" "$W/a/server.key"
echo "FORWARD_OUT=eth1" > "$W/b/server.env"
cat > "$W/a/sync.conf" <<EOF
PEERS="$W/b $W/c"
RELOAD="echo reload >> $W/reloads"
EOF

check "no sync.conf: refused" "$(ZTGATE_SYNC_CONF=$W/none "$SYNC" > /dev/null 2>&1; echo $?)" 1

"$SYNC" > "$W/out" 2>&1
check "sync: exit" "$?" 0
check "sync: the device list reaches both" "$(cat "$W/b/devices.conf") / $(cat "$W/c/devices.conf")" "devices v1 / devices v1"
check "sync: acl and server key too" "$(cat "$W/b/acl.conf") / $(cat "$W/b/server.key")" "acl v1 / key"
check "sync: modes kept" "$(stat -c %a "$W/b/server.key")" 600
check "sync: server.env is each server's own" "$(cat "$W/b/server.env")" "FORWARD_OUT=eth1"
check "sync: enrollment codes stay on the primary" "$([ -e "$W/b/enroll.conf" ] && echo yes || echo no)" no
check "sync: each peer reloaded once" "$(grep -c reload "$W/reloads")" 2
check "sync: the peer knows its primary" "$(cat "$W/b/.sync-primary")" "$(hostname)"

echo "devices v2" > "$W/a/devices.conf"
rm "$W/a/acl.conf"
"$SYNC" > /dev/null 2>&1
check "again: the change arrives" "$(cat "$W/b/devices.conf")" "devices v2"
check "again: a file removed on the primary is removed" "$([ -e "$W/b/acl.conf" ] && echo yes || echo no)" no

check "on a secondary: refused" "$(ZTGATE_ETC=$W/b ZTGATE_SYNC_CONF=$W/a/sync.conf "$SYNC" > /dev/null 2>&1; echo $?)" 1

cat > "$W/a/sync.conf" <<EOF
PEERS="$W/b $W/missing/x"
RELOAD="true"
EOF
"$SYNC" > /dev/null 2>&1
check "one peer unreachable: failure, the other still synced" "$? $(cat "$W/b/devices.conf")" "1 devices v2"

echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed FAILED"
exit $((failed != 0))
