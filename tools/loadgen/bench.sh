#!/usr/bin/env bash
# 서버 데이터 경로의 처리량을 잰다. 같은 장비에서 vpn_server 와 loadgen 을 띄우고
# 페이로드 크기별로 최대 속도로 보낸 뒤, 결과를 마크다운 표로 낸다.
#
#   sudo tools/loadgen/bench.sh [out-dir]
#
# 환경 변수
#   DUR=10           한 번 보내는 시간(초)
#   SIZES="56 512 1372"   ICMP 페이로드 크기
#   LOGS="quiet file null" 서버를 어떻게 띄울지. quiet = 운영 기본값(통과한 패킷은 찍지 않는다),
#                    file = -v 로 패킷마다 한 줄을 파일에, null = -v 로 찍되 /dev/null 로
#   PERF=1           perf 가 있으면 56B 최대 속도 구간을 perf record 로 한 번 더 잰다
#   PORT=19100
#
# TUN 을 만들고 10.0.0.1/24 를 붙이므로 root 로 돌린다. 다른 vpn_server 가 그 주소를
# 쓰고 있으면 돌릴 수 없다. 측정 동안 net.core.[rw]mem_max 를 4MB 로 올렸다가 되돌린다.
# sudo 가 없으면 사용자 네임스페이스 안에서 돌릴 수 있다 (네트워크도 따로 생긴다):
#
#   unshare -rn sh -c 'ip link set lo up && tools/loadgen/bench.sh'
#
# 그 안에서는 [rw]mem_max 를 바꿀 수 없어(네임스페이스마다 따로가 아니다) 기본값으로 잰다.
#
# CPU 가 3개 이상이면 서버를 CPU 0 에, loadgen(송신 + 수신 스레드)을 CPU 1-2 에 묶는다.
# 묶지 않으면 서로 CPU 를 뺏어 숫자가 매번 달라진다.

set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SERVER="$ROOT/server/bin/vpn_server"
LOADGEN="$ROOT/tools/loadgen/bin/loadgen"
OUT=${1:-$ROOT/tools/loadgen/out}
DUR=${DUR:-10}
SIZES=${SIZES:-"56 512 1372"}
LOGS=${LOGS:-"quiet file null"}
PERF=${PERF:-0}
PORT=${PORT:-19100}

# 부하 생성기 전용 기기. 측정용이라 키를 공개해도 된다.
DEV_ID=b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
DEV_KEY=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5
TUN_IP=10.0.0.9

die() { echo "bench: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (tun device + address)"
[ -x "$SERVER" ] && [ -x "$LOADGEN" ] || die "build first: make server tools"
mkdir -p "$OUT"

if [ "$(nproc)" -ge 3 ]; then
	PIN_SERVER=(taskset -c 0)
	PIN_LOADGEN=(taskset -c 1,2)
else
	PIN_SERVER=()
	PIN_LOADGEN=()
	echo "bench: only $(nproc) CPU(s) — server and loadgen share CPUs, numbers are not comparable" >&2
fi

DEVFILE=$(mktemp)
echo "$DEV_ID $DEV_KEY $TUN_IP" > "$DEVFILE"
chmod 600 "$DEVFILE"

RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null)
WMEM=$(sysctl -n net.core.wmem_max 2>/dev/null)
if [ -z "$RMEM" ] || ! sysctl -qw net.core.rmem_max=4194304 net.core.wmem_max=4194304 2>/dev/null; then
	echo "bench: cannot raise net.core.[rw]mem_max — socket buffers stay at the default" >&2
	RMEM=
fi

SRV_PID=
cleanup() {
	[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
	[ -n "$RMEM" ] && sysctl -qw net.core.rmem_max="$RMEM" net.core.wmem_max="$WMEM"
	rm -f "$DEVFILE"
}
trap cleanup EXIT

# $1 = quiet | file | null. 새로 생긴 tun 장치를 찾아 주소를 붙인다 — null 이면 서버 로그에서
# 장치 이름을 읽을 수 없어서, 띄우기 전과 뒤의 장치 목록을 비교한다.
start_server() {
	local dest before dev i
	local opts=(-v)
	if [ "$1" = null ]; then dest=/dev/null; else dest="$OUT/server.log"; fi
	if [ "$1" = quiet ]; then opts=(); fi

	before=$(ip -o link show type tun | awk -F': ' '{print $2}')
	"${PIN_SERVER[@]}" "$SERVER" "${opts[@]}" "$PORT" "$DEVFILE" > "$dest" 2>&1 &
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

stop_server() {
	kill "$SRV_PID" 2>/dev/null
	wait "$SRV_PID" 2>/dev/null
	SRV_PID=
}

# 서버 프로세스가 지금까지 쓴 CPU 시간(틱). /proc/<pid>/stat 의 utime + stime.
cpu_ticks() {
	awk '{print $14 + $15}' "/proc/$SRV_PID/stat"
}

# loadgen 을 돌리고 RESULT 줄을 key=value 로 풀어 전역 변수 R_* 에 담는다.
run_loadgen() {
	local line kv
	line=$("${PIN_LOADGEN[@]}" "$LOADGEN" "$@" 127.0.0.1 "$PORT" "$DEV_ID" "$DEV_KEY" \
		| tee -a "$OUT/loadgen.log" | grep '^RESULT') || die "loadgen failed (see $OUT/loadgen.log)"
	for kv in ${line#RESULT }; do
		printf -v "R_${kv%%=*}" '%s' "${kv#*=}"
	done
}

HZ=$(getconf CLK_TCK)
TABLE="$OUT/result.md"
: > "$OUT/loadgen.log"

{
	echo "| 서버 로그 | 페이로드 | 보낸 pps | 받은 pps | 받은 Mbps | 손실 | 서버 CPU | p50 | p99 |"
	echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
} > "$TABLE"

for log in $LOGS; do
	start_server "$log"
	for size in $SIZES; do
		t0=$(cpu_ticks)
		s0=$(date +%s%N)
		run_loadgen -s "$size" -t "$DUR"
		t1=$(cpu_ticks)
		s1=$(date +%s%N)
		# 서버는 스레드 하나라 100% 가 한 코어를 다 쓴 것이다. 구간은 loadgen 이 도는 동안
		# 전체(핸드셰이크 + 보내는 시간 + 1초 드레인)라 보내는 동안의 값보다 조금 낮게 나온다.
		cpu=$(awk -v t="$((t1 - t0))" -v hz="$HZ" -v ns="$((s1 - s0))" \
			'BEGIN { printf "%.0f%%", 100 * t / hz / (ns / 1e9) }')
		printf "| %s | %s B | %s | %s | %s | %s%% | %s | %s us | %s us |\n" \
			"$log" "$size" "$R_tx_pps" "$R_rx_pps" "$R_rx_mbps" "$R_loss" "$cpu" \
			"$R_p50_us" "$R_p99_us" >> "$TABLE"
	done

	if [ "$PERF" = 1 ] && [ "$log" = file ] && command -v perf >/dev/null; then
		perf record -g -o "$OUT/perf.data" -p "$SRV_PID" -- sleep "$DUR" > /dev/null 2>&1 &
		perf_pid=$!
		run_loadgen -s 56 -t "$DUR"
		wait "$perf_pid"
		# perf.txt 는 함수별 비율만, perf-callgraph.txt 는 호출 경로까지.
		perf report -i "$OUT/perf.data" --stdio --no-children -g none --percent-limit 1 \
			> "$OUT/perf.txt" 2>/dev/null
		perf report -i "$OUT/perf.data" --stdio --no-children --percent-limit 1 \
			> "$OUT/perf-callgraph.txt" 2>/dev/null
		rm -f "$OUT/perf.data"
	fi
	stop_server
	rm -f "$OUT/server.log"
done

{
	echo
	echo "- CPU: $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) cores, kernel $(uname -r)"
	echo "- ${DUR}s per row, loopback, one session, inner ICMP echo to 10.0.0.1 (server's tun)"
	if [ ${#PIN_SERVER[@]} -gt 0 ]; then
		echo "- server pinned to CPU 0, loadgen to CPU 1-2"
	else
		echo "- not pinned"
	fi
} >> "$TABLE"

cat "$TABLE"
