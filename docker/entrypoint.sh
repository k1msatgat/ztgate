#!/bin/sh
# 컨테이너의 시작점.
#
#   server          /etc/ztgate 의 설정으로 vpn_server 를 띄우고, 생긴 tun 에 서버의 터널
#                   주소를 붙인다. 호스트에서 하던 `ip addr add 10.0.0.1/24 dev tun0` 이다.
#   client          SERVER 로 접속한다. 신원 파일이 없고 ENROLL_CODE 가 있으면 먼저 등록한다.
#   enroll-code ... 등록 코드를 만든다 (enroll-code.sh). 서버 컨테이너에서 docker exec 로.
#   그 밖           그 명령을 그대로 실행한다 (sh, vpn_client posture ...)
#
# 환경 변수
#   PORT=9000  TUN_ADDR=10.0.0.1/24  MTU=1400        (서버)
#   SERVER=<ip 또는 이름>  ENROLL_CODE=<code>  IFNAME=ztgate0   (클라이언트)

set -eu

ETC=/etc/ztgate
IDENT=/var/lib/ztgate/device
PORT=${PORT:-9000}

# stdout 이 docker 로그(파이프)라 그냥 두면 블록 단위로 모였다가 나온다. 줄 단위로.
line_buffered() { stdbuf -oL -eL "$@"; }

server() {
	TUN_ADDR=${TUN_ADDR:-10.0.0.1/24}
	MTU=${MTU:-1400}
	PREFIX=${TUN_ADDR#*/}

	mkdir -p "$ETC"
	# 기기 목록은 비어 있어도 된다 — 기기는 등록 코드로 올라온다. 키가 들어가는 파일이라
	# 서버는 권한이 600 이 아니면 읽지 않는다.
	for f in devices.conf enroll.conf; do
		[ -e "$ETC/$f" ] || : > "$ETC/$f"
	done
	chmod 600 "$ETC/devices.conf" "$ETC/enroll.conf"

	# 서버 키는 처음 한 번 만든다. 볼륨에 남아 컨테이너를 다시 만들어도 같은 키다 — 바뀌면 등록된
	# 기기가 모두 다시 등록해야 한다.
	[ -e "$ETC/server.key" ] || vpn_server genkey "$ETC/server.key" > /dev/null

	set -- -e "$ETC/enroll.conf" -k "$ETC/server.key" -a "$ETC/audit.log" -s /run/vpn_status.sock \
		-n "$PREFIX" -m "$MTU" "$PORT" "$ETC/devices.conf"
	if [ -f "$ETC/acl.conf" ]; then
		chmod 600 "$ETC/acl.conf"
		set -- "$@" "$ETC/acl.conf"
	fi

	line_buffered vpn_server "$@" &
	pid=$!
	trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

	# 새 컨테이너의 네트워크 네임스페이스에는 tun 이 이것 하나뿐이다.
	i=0
	while ! dev=$(ip -o link show type tun | awk -F': ' 'NR == 1 { print $2 }') || [ -z "$dev" ]; do
		i=$((i + 1))
		if [ "$i" -gt 50 ] || ! kill -0 "$pid" 2>/dev/null; then
			echo "entrypoint: vpn_server did not create a tun device" >&2
			exit 1
		fi
		sleep 0.1
	done
	ip addr add "$TUN_ADDR" dev "$dev"
	ip link set "$dev" mtu "$MTU" up
	echo "entrypoint: $dev $TUN_ADDR mtu $MTU"

	wait "$pid"
}

client() {
	: "${SERVER:?set SERVER to the server address}"
	IFNAME=${IFNAME:-ztgate0}

	# vpn_client 는 IPv4 주소만 받는다. compose 의 서비스 이름 같은 것은 여기서 푼다.
	addr=$(getent ahostsv4 "$SERVER" | awk 'NR == 1 { print $1 }')
	[ -n "$addr" ] || { echo "entrypoint: cannot resolve $SERVER" >&2; exit 1; }

	mkdir -p "$(dirname "$IDENT")"
	chmod 700 "$(dirname "$IDENT")"
	if [ ! -e "$IDENT" ]; then
		: "${ENROLL_CODE:?no identity in $IDENT; set ENROLL_CODE to enroll this container}"
		line_buffered vpn_client -k "$IDENT" enroll "$addr" "$PORT" "$ENROLL_CODE"
	fi

	exec stdbuf -oL -eL vpn_client -k "$IDENT" -i "$IFNAME" run "$addr" "$PORT"
}

case "${1:-server}" in
	server)		server ;;
	client)		client ;;
	enroll-code)	shift; exec enroll-code.sh "$@" ;;
	*)		exec "$@" ;;
esac
