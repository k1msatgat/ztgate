#!/usr/bin/env bash
# ztgate.service 가 부른다. PORT / TUN_IP / PREFIX / MTU 는 유닛의 EnvironmentFile
# (/etc/ztgate/server.env) 에서 온다.
#
#   service.sh run            vpn_server 로 exec (ExecStart)
#   service.sh tun-up <pid>   서버가 만든 tun 에 주소를 붙이고 올린다 (ExecStartPost)
#   service.sh forward-down   터널 밖으로의 전달 규칙을 뺀다 (ExecStopPost)
#
# server.env 에 FORWARD_OUT=<인터페이스> 가 있으면 tun-up 이 그 인터페이스로의 전달을 켠다.
# SESSION_LIFETIME=<초> 가 있으면 세션 키를 그 주기로 바꾼다 (vpn_server -L, 기본 3600).

set -eu

ETC=/etc/ztgate
SERVER=/opt/ztgate/server/bin/vpn_server

# 터널로 들어온 패킷을 이 장비 뒤의 네트워크로 내보낸다 (FORWARD_OUT=<나가는 인터페이스>).
#
# vpn_server 는 패킷을 tun 에 쓰는 데까지만 한다. 그 뒤 어디로 보낼지는 커널의 일이라
# 여기서 켠다. 누가 어디로 갈 수 있는지는 여전히 vpn_server 의 ACL 이 정한다 — 규칙에
# 없는 목적지는 tun 에 쓰이지도 않는다. 아래 규칙은 그 뒤의 길을 터 주는 것과, 반대
# 방향을 막는 것이다.
#
#   주소 변환  터널 주소(10.0.0.x)는 이 장비만 아는 주소다. 그대로 내보내면 받은 쪽이
#             답을 돌려보낼 길이 없다. 나갈 때 이 장비의 주소로 바꾼다.
#   반대 방향  바깥에서 터널 쪽으로는 안에서 시작한 연결의 답만 들인다. 기기가 사내
#             자원에 닿게 하려는 것이지, 사내에서 기기로 들어오게 하려는 것이 아니다.
#   그 밖      터널에서 들어와 다른 인터페이스로 나가는 것은 막는다. FORWARD_OUT 하나만
#             연다.
#
# 규칙은 우리 표(table ip ztgate) 하나에 모은다. 장비에 이미 있는 방화벽 규칙을 고치지
# 않고, 지울 때도 그 표만 지우면 된다. firewalld 같은 다른 방화벽이 전달을 막고 있으면
# 그쪽에서도 열어야 한다 (README).
forward_up() {
	local dev=$1 net

	ip link show "$FORWARD_OUT" > /dev/null 2>&1 ||
		{ echo "FORWARD_OUT=$FORWARD_OUT: no such interface" >&2; exit 1; }

	# 터널 대역은 방금 붙인 주소에서 커널이 만든 경로로 읽는다. TUN_IP 와 PREFIX 로 다시
	# 계산하면 같은 값을 두 군데서 따로 구하게 된다.
	net=$(ip -4 -o route show dev "$dev" proto kernel | awk '{ print $1; exit }')
	[ -n "$net" ] || { echo "no tunnel subnet on $dev" >&2; exit 1; }

	sysctl -qw net.ipv4.ip_forward=1

	# 표를 선언한 뒤 지우고 다시 만든다. 한 번에 적용되므로 규칙이 반쯤 들어간 순간이 없고,
	# 이전 실행이 남긴 표가 있어도 겹치지 않는다.
	nft -f - <<EOF
table ip ztgate
delete table ip ztgate
table ip ztgate {
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "$dev" oifname "$dev" accept
		iifname "$dev" oifname "$FORWARD_OUT" accept
		iifname "$FORWARD_OUT" oifname "$dev" ct state established,related accept
		iifname "$dev" drop
		oifname "$dev" drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr $net oifname "$FORWARD_OUT" masquerade
	}
}
EOF
	echo "forward: $net -> $FORWARD_OUT (masquerade), replies only on the way back"
}

case "${1:-}" in
run)
	# 상태 소켓은 RuntimeDirectory(/run/ztgate, root 전용) 안에 둔다. ztgate_ctl 이 읽는다.
	# -n / -m 은 아래 tun-up 이 tun 에 붙이는 값과 같아야 한다. 서버가 그대로 클라이언트에
	# 내려 준다.
	# -e: 등록 코드의 대기 목록. 서버가 그 코드로 온 기기를 devices.conf 에 직접 올린다.
	# -k: 서버 키. 등록 코드로 올라오는 기기(공개키 기기)의 키를 그것으로 뽑는다. install.sh 가 만든다.
	args=(-s /run/ztgate/status.sock -a /var/log/ztgate/audit.log -e "$ETC/enroll.conf" -k "$ETC/server.key" -n "$PREFIX" -m "$MTU")

	# 세션 키의 수명. 적지 않으면 서버의 기본값(1시간)이다.
	if [ -n "${SESSION_LIFETIME:-}" ]; then
		args+=(-L "$SESSION_LIFETIME")
	fi

	# 내부 DNS 는 dns.conf 가 있을 때만 내려 준다 (README 의 "내부 DNS").
	if [ -f "$ETC/dns.conf" ]; then
		args+=(-d "$ETC/dns.conf")
	fi

	# 사용자 로그인은 IdP 설정이 있을 때만 받는다 (README 의 "사용자 로그인").
	if [ -f "$ETC/idp.conf" ]; then
		args+=(-u "$ETC/idp.conf")
	fi
	args+=("$PORT" "$ETC/devices.conf")

	# ACL 은 파일이 있으면 켜진 것이다. 켜고 끄는 것은 시작할 때만 정해지므로, 어떤
	# 내용으로 떴는지 적어 둔다 — ztgate_ctl 이 지금 파일과 비교해 재시작이 필요한지 안다.
	if [ -f "$ETC/acl.conf" ]; then
		args+=("$ETC/acl.conf")
		sha256sum < "$ETC/acl.conf" | cut -d' ' -f1 > /run/ztgate/acl.applied
	else
		echo none > /run/ztgate/acl.applied
	fi

	# stdout 이 journal 로 가면 printf 가 블록 버퍼링된다. 줄 단위로 바꾼다.
	exec stdbuf -oL -eL "$SERVER" "${args[@]}"
	;;

tun-up)
	pid=$2
	dev=

	# tun 이름은 커널이 정한다. 서버 프로세스가 연 fd 에서 직접 읽는다.
	for _ in $(seq 50); do
		kill -0 "$pid" 2>/dev/null || { echo "vpn_server exited during startup" >&2; exit 1; }
		dev=$(awk '/^iff:/ { print $2; exit }' /proc/"$pid"/fdinfo/* 2>/dev/null || true)
		[ -n "$dev" ] && break
		sleep 0.1
	done
	[ -n "$dev" ] || { echo "vpn_server did not open a tun device" >&2; exit 1; }

	ip addr add "$TUN_IP/$PREFIX" dev "$dev"
	ip link set "$dev" mtu "$MTU" up
	echo "tun up: $dev $TUN_IP/$PREFIX mtu $MTU"

	# 터널 밖으로의 전달은 server.env 에 FORWARD_OUT 을 적은 경우에만 켠다.
	if [ -n "${FORWARD_OUT:-}" ]; then
		forward_up "$dev"
	fi
	;;

forward-down)
	# 서비스가 내려가면 우리가 넣은 규칙도 뺀다. 남겨 두면 다음에 같은 이름으로 뜬 다른
	# 인터페이스에 걸린다. 표 하나에 모아 뒀으므로 그 표만 지우면 된다.
	nft delete table ip ztgate 2>/dev/null || true
	;;

*)
	echo "usage: $0 run | tun-up <pid> | forward-down" >&2
	exit 1
	;;
esac
