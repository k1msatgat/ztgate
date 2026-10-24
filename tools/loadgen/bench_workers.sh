#!/usr/bin/env bash
# 서버의 워커 수(-w)에 따른 처리량. 부하 생성기를 세션마다 하나씩 여럿 띄워 동시에 보낸다.
#
#   sudo tools/loadgen/bench_workers.sh [out-dir]
#
# 환경 변수
#   WORKERS="1 2"    잴 워커 수
#   SESSIONS=4       동시에 보내는 세션(부하 생성기 프로세스) 수
#   DUR=10           보내는 시간(초)
#   SIZE=56          ICMP 페이로드
#   PORT=19200
#
# 왜 세션이 여럿이어야 하나: 워커는 SO_REUSEPORT 로 소켓을 나눠 갖고, 커널은 출발지 주소(포트)의
# 해시로 받을 소켓을 고른다. 세션이 하나면 늘 같은 워커로 가서 워커를 늘려도 빨라지지 않는다 —
# 실제로 기기가 여럿 붙은 서버의 모습을 잰다.
#
# CPU 가 4개 이상이면 부하 생성기를 마지막 두 CPU 에, 서버를 앞의 CPU 들에 묶는다 (워커 수만큼).
# 부하 생성기 쪽 CPU 가 늘 같아서 행끼리 비교된다. 부하 생성기가 먼저 막히면 받은 양이 보낸 양에
# 붙어 나온다 — 그때는 서버가 아니라 부하 생성기의 한계다.
set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SERVER="$ROOT/server/bin/vpn_server"
LOADGEN="$ROOT/tools/loadgen/bin/loadgen"
OUT=${1:-$(mktemp -d)}
WORKERS=${WORKERS:-"1 2"}
SESSIONS=${SESSIONS:-4}
DUR=${DUR:-10}
SIZE=${SIZE:-56}
PORT=${PORT:-19200}

die() { echo "bench_workers: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (tun device + address)"
[ -x "$SERVER" ] && [ -x "$LOADGEN" ] || die "build first: make server tools"
mkdir -p "$OUT"

NCPU=$(nproc)
DEVFILE=$(mktemp)
for i in $(seq "$SESSIONS"); do
	printf '%032x %064x 10.0.0.%d\n' "$i" "$((i + 1000))" "$((i + 10))" >> "$DEVFILE"
done
chmod 600 "$DEVFILE"

SRV_PID=
cleanup() {
	[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
	rm -f "$DEVFILE"
}
trap cleanup EXIT

start_server() {	# $1 = 워커 수
	local before dev i pin=()
	if [ "$NCPU" -ge 4 ]; then
		pin=(taskset -c "0-$(( $1 - 1 ))")
	fi
	before=$(ip -o link show type tun | awk -F': ' '{print $2}')
	"${pin[@]}" "$SERVER" -w "$1" "$PORT" "$DEVFILE" > "$OUT/server-w$1.log" 2>&1 &
	SRV_PID=$!
	for i in $(seq 50); do
		dev=$(ip -o link show type tun | awk -F': ' '{print $2}' | grep -vxF "$before" | head -n 1)
		[ -n "$dev" ] && break
		sleep 0.1
	done
	[ -n "$dev" ] || die "server did not create a tun device"
	ip addr add 10.0.0.1/24 dev "$dev"
	ip link set "$dev" mtu 1400 up
	sleep 0.3
}

TABLE="$OUT/workers.md"
{
	echo "| 워커 | 세션 | 보낸 pps (합) | 받은 pps (합) | 받은 Mbps (합) | 손실 |"
	echo "|---:|---:|---:|---:|---:|---:|"
} > "$TABLE"

for w in $WORKERS; do
	[ "$NCPU" -ge 4 ] && [ "$w" -gt $(( NCPU - 2 )) ] && { echo "skip -w $w: only $NCPU CPUs" >&2; continue; }
	start_server "$w"
	pin=()
	[ "$NCPU" -ge 4 ] && pin=(taskset -c "$(( NCPU - 2 ))-$(( NCPU - 1 ))")
	for i in $(seq "$SESSIONS"); do
		"${pin[@]}" "$LOADGEN" -s "$SIZE" -t "$DUR" 127.0.0.1 "$PORT" \
			"$(printf '%032x' "$i")" "$(printf '%064x' "$((i + 1000))")" > "$OUT/loadgen-w$w-$i.log" 2>&1 &
	done
	wait $(jobs -p | grep -vx "$SRV_PID") 2>/dev/null
	grep -h '^RESULT' "$OUT"/loadgen-w"$w"-*.log | awk -v w="$w" -v n="$SESSIONS" '
		{ for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] += kv[2] } c++ }
		END {
			loss = v["sent"] ? 100 * (v["sent"] - v["recv"]) / v["sent"] : 0
			printf "| %d | %d/%d | %.0f | %.0f | %.1f | %.2f%% |\n", w, c, n, v["tx_pps"], v["rx_pps"], v["rx_mbps"], loss
		}' >> "$TABLE"
	kill "$SRV_PID" 2>/dev/null
	wait "$SRV_PID" 2>/dev/null
	SRV_PID=
done

{
	echo
	echo "- CPU: $(lscpu | sed -n 's/^Model name: *//p'), $NCPU cores, kernel $(uname -r)"
	echo "- ${DUR}s, ${SESSIONS} sessions at once (one loadgen each), ${SIZE} B ICMP echo to the server's tun"
	[ "$NCPU" -ge 4 ] && echo "- server pinned to CPU 0..w-1, loadgens to the last two CPUs"
} >> "$TABLE"

cat "$TABLE"
