#!/usr/bin/env bash
# Linux 서버 <-> Linux 클라이언트 전체 경로를 한 장비에서 확인한다.
#
#   test/linux_e2e.sh            root 가 아니면 사용자 네임스페이스(unshare -rn) 안에서 돈다
#   sudo test/linux_e2e.sh       root 면 새 네트워크 네임스페이스(unshare -n) 안에서 돈다
#   E2E_LOGS=<dir> test/linux_e2e.sh   서버 / 클라이언트 로그를 <dir> 에 남긴다
#
# 네트워크 네임스페이스 두 개를 veth 로 잇는다. 장비의 네트워크는 건드리지 않는다.
#
#   [서버 ns] vpn_server  192.0.2.1 --veth-- 192.0.2.2  vpn_client [클라이언트 ns]
#             tun 10.0.0.1/24                              ztgate0 (서버가 주는 주소)
#
# 시나리오
#   1. 등록 코드로 기기 등록 -> 신원 파일(0600)과 서버 기기 목록에 한 줄
#   2. 연결 -> 서버가 준 주소 / MTU / 경로가 tun 에 붙고, 터널로 ping 이 오간다
#   3. ACL -> 허용하지 않은 목적지 / 포트는 서버가 버린다
#   4. 포스처 -> 기기 정책에 firewall=on 을 걸고 SIGHUP. 다음 keepalive 에서 거절된다.
#      클라이언트 ns 에 nft 로 인바운드 기본 거부를 걸면 스스로 다시 붙는다.
#   5. 사용자 로그인 -> group=ops 규칙은 로그인 전에는 닫혀 있다.
#      로그인 도구(ztgate_login)가 시험용 OIDC 서버에서 토큰을 받아 파일에 쓰면 클라이언트가
#      보내고, 그때부터 열린다. 도구가 토큰을 갈아 끼우면 이어지고, 다른 IdP 의 토큰은 거절되며,
#      아무도 갈아 끼우지 않으면 만료되는 순간 다시 닫힌다. 터널은 그동안 그대로다.
#   6. 커넥터 -> 내부망(198.51.100.0/24) 안의 커넥터가 서버로 나가는 세션을 열면, 클라이언트의
#      ping 이 서버의 tun 이 아니라 커넥터를 지나 자원에 닿는다. 내부망 쪽에서 시작한 연결은
#      막히고, ACL 은 그대로 걸리며, 커넥터가 내려가면 다시 닿지 않는다.
#   7. TCP -> 클라이언트 쪽에서 UDP 를 막으면 같은 기기로 TCP(-T) 로 붙는다.
#   8. 서버 공개키 고정 -> 등록 때 받은 서버 공개키와 다른 공개키를 내미는 서버에는 답하지 않는다.
#   9. 장애 조치 -> 서버를 여럿 적으면 답하지 않는 서버를 건너뛰고, 연결 중에 지금 서버로 가는 길이
#      막히면 다음 서버로 넘어간다 (서버 veth 에 붙인 두 번째 주소를 두 번째 서버로 쓴다).
#  10. DPoP -> 기기 키에 묶인 토큰은 그 키(-D) 없이 보내면 거절되고, ztgate_login --dpop-key 로 받아
#      같은 키로 보내면 받아들여진다.
#  11. IPv6 -> veth 양쪽에 IPv6 주소를 붙이고, 서버의 IPv6 주소로 붙어 터널(IPv4)이 그대로 된다.
#
# 사용자 네임스페이스 안에서는 nft 규칙셋이 그 네임스페이스의 것이라 방화벽 포스처를
# 마음대로 켜고 끌 수 있다. 실제 장비에서는 그 장비의 nftables / firewalld 를 읽는다.

set -u

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(dirname "$TEST_DIR")
SERVER="$ROOT_DIR/server/bin/vpn_server"
CLIENT="$ROOT_DIR/client/bin/vpn_client"

PORT=9000
TCP_PORT=9443
SRV_VETH=192.0.2.1
CLI_VETH=192.0.2.2
SRV_TUN=10.0.0.1
CLI_TUN=10.0.0.2
ROUTED_NET=198.51.100.0/24	# ACL 의 allow 목적지 -> 서버가 경로로 내려 준다
CLI_IF=ztgate0
# 0-9 와 I L O U 를 뺀 대문자 25자 (proto.h 의 ENROLL_CODE_LEN). 테스트용 고정 값.
CODE=7K2QF-9XWM4-ABCDE-FGHJK-MNPQR
KEEPALIVE_WAIT=15		# keepalive 주기(10초) + 여유

if [ -z "${ZTGATE_E2E_NS:-}" ]; then
	[ -x "$SERVER" ] && [ -x "$CLIENT" ] || { echo "build first: make server client" >&2; exit 1; }
	export ZTGATE_E2E_NS=1
	if [ "$(id -u)" -eq 0 ]; then
		exec unshare -n "$0" "$@"
	fi
	exec unshare -rn "$0" "$@"
fi

WORK=$(mktemp -d)
DEVICES=$WORK/devices.conf
ENROLL=$WORK/enroll.conf
ACL=$WORK/acl.conf
IDENT=$WORK/device
TOKEN=$WORK/token
IDP=$WORK/idp
SLOG=$WORK/server.log
CLOG=$WORK/client.log
SRV_PID=
CLI_PID=
NS_PID=
IDP_PID=
LOGIN_PID=
CON_PID=
NS2_PID=
NS3_PID=
failed=0

cleanup() {
	[ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
	[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
	[ -n "$NS_PID" ] && kill "$NS_PID" 2>/dev/null
	[ -n "$LOGIN_PID" ] && kill "$LOGIN_PID" 2>/dev/null
	[ -n "$IDP_PID" ] && kill "$IDP_PID" 2>/dev/null
	[ -n "$CON_PID" ] && kill "$CON_PID" 2>/dev/null
	[ -n "$NS2_PID" ] && kill "$NS2_PID" 2>/dev/null
	[ -n "$NS3_PID" ] && kill "$NS3_PID" 2>/dev/null
	wait 2>/dev/null
	if [ "$failed" -ne 0 ]; then
		echo
		echo "---- server log (last 30) ----"; tail -n 30 "$SLOG"
		echo "---- client log (last 30) ----"; tail -n 30 "$CLOG"
		if [ -e "$WORK/client-tcp.log" ]; then
			echo "---- tcp client log (last 30) ----"; tail -n 30 "$WORK/client-tcp.log"
		fi
	fi
	if [ -n "${E2E_LOGS:-}" ]; then
		mkdir -p "$E2E_LOGS" && cp "$SLOG" "$CLOG" "$E2E_LOGS"/
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# 클라이언트 ns 에서 명령을 돌린다. 사용자 네임스페이스 안이면 자격을 그대로 들고 들어가야 한다.
in_cli() { nsenter -t "$NS_PID" -n --preserve-credentials "$@"; }

check() {	# check <이름> <조건 명령...>
	local name=$1; shift
	if "$@" >/dev/null 2>&1; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name"
		failed=$((failed + 1))
	fi
}

wait_for() {	# wait_for <초> <조건 명령...>
	local i=$(( $1 * 10 )); shift
	while [ "$i" -gt 0 ]; do
		"$@" >/dev/null 2>&1 && return 0
		sleep 0.1
		i=$((i - 1))
	done
	return 1
}

ping_ok() { in_cli ping -c 1 -W 1 "$1"; }
ping_fails() { ! in_cli ping -c 1 -W 1 "$1"; }
log_has() { grep -qF -- "$2" "$1"; }

# ---- 네트워크 -----------------------------------------------------------------
ip link set lo up
unshare -n sleep infinity &
NS_PID=$!
sleep 0.2
ip link add v-srv type veth peer name v-cli
ip link set v-cli netns "$NS_PID"
ip addr add "$SRV_VETH/24" dev v-srv
ip link set v-srv up
in_cli ip link set lo up
in_cli ip addr add "$CLI_VETH/24" dev v-cli
in_cli ip link set v-cli up

# ---- 서버 ---------------------------------------------------------------------
# 등록 대기 줄: 코드에서 뽑은 임시 신원 (secure.h 의 secure_enroll_identity) + 줄 터널 주소.
read -r EID EKEY < <(python3 - "$CODE" <<'EOF'
import hashlib, hmac, sys
code = sys.argv[1].replace("-", "").upper()
mac = lambda label: hmac.new(label, code.encode(), hashlib.sha256).digest()
print(mac(b"ztgate enroll id")[:16].hex(), mac(b"ztgate enroll key").hex())
EOF
)
: > "$DEVICES"
printf '%s %s %s %d  # e2e\n' "$EID" "$EKEY" "$CLI_TUN" $(( $(date +%s) + 600 )) > "$ENROLL"
cat > "$ACL" <<EOF
10.0.0.0/24  $SRV_TUN       icmp  any  allow
10.0.0.0/24  $ROUTED_NET    icmp  any  allow
10.0.0.0/24  $SRV_TUN       udp   5353 allow  group=ops
any          any            any   any  deny
EOF
# 내부 DNS. 네임스페이스 안의 클라이언트는 호스트의 systemd-resolved 에 자기 tun 을 알릴 수
# 없어(장치 번호가 다른 네임스페이스의 것이다) 실제로 걸리지는 않는다. 여기서는 v7 의 설정을
# 받아 DNS 를 처리하는 길을 지나고도 연결이 그대로인지를 본다.
printf 'server %s\ndomain corp.example\n' "$SRV_TUN" > "$WORK/dns.conf"
chmod 600 "$DEVICES" "$ENROLL" "$ACL"

before=$(ip -o link show type tun | awk -F': ' '{print $2}')
# 사용자 로그인: 시험용 IdP (tools/idp/mint.py) 의 키를 서버가 믿게 한다.
python3 "$ROOT_DIR/tools/idp/mint.py" keys "$IDP" > /dev/null || { echo "mint.py keys failed"; exit 1; }
# 서버 키: 등록 코드로 올라오는 기기는 공개키 기기라 -e 에는 -k 가 있어야 한다 (v8).
"$SERVER" genkey "$WORK/server.key" > /dev/null || { echo "genkey failed"; exit 1; }
stdbuf -oL "$SERVER" -v ${ZTGATE_WORKERS:+-w "$ZTGATE_WORKERS"} -e "$ENROLL" -k "$WORK/server.key" -t "$TCP_PORT" -u "$IDP/idp.conf" -d "$WORK/dns.conf" "$PORT" "$DEVICES" "$ACL" > "$SLOG" 2>&1 &
SRV_PID=$!
wait_for 5 sh -c "ip -o link show type tun | grep -q ." || { echo "server did not start"; cat "$SLOG"; exit 1; }
SRV_IF=$(ip -o link show type tun | awk -F': ' '{print $2}' | grep -vxF "$before" | head -n 1)
ip addr add "$SRV_TUN/24" dev "$SRV_IF"
ip link set "$SRV_IF" mtu 1400 up

echo "== 1. enrollment"
in_cli "$CLIENT" -k "$IDENT" enroll "$SRV_VETH" "$PORT" "$CODE" > "$CLOG" 2>&1
check "enroll: client reports success" log_has "$CLOG" "enrolled. identity saved"
check "enroll: identity file is mode 600" test "$(stat -c %a "$IDENT" 2>/dev/null)" = 600
check "enroll: server added the device to its list" grep -q "$(cut -c1-32 "$IDENT" 2>/dev/null)" "$DEVICES"
check "enroll: the identity keeps the server's public key" \
	test "$(awk '{ print NF; exit }' "$IDENT" 2>/dev/null)" = 3
check "enroll: the code cannot be used twice" sh -c "! nsenter -t $NS_PID -n --preserve-credentials \
	'$CLIENT' -f -k '$WORK/other' enroll '$SRV_VETH' '$PORT' '$CODE'"

echo "== 2. connect"
# 함수(in_cli)로 띄우면 $! 가 서브셸이라 끝날 때 클라이언트를 멈추지 못하고 남는다 (tun 과
# 네임스페이스를 붙든 채로). nsenter 를 바로 불러 $! 가 클라이언트 자신이 되게 한다.
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" -t "$TOKEN" \
	run "$SRV_VETH" "$PORT" > "$CLOG" 2>&1 &
CLI_PID=$!
check "connect: session established" wait_for 10 log_has "$CLOG" "] connected"
check "connect: tun has the address the server assigned" \
	sh -c "nsenter -t $NS_PID -n --preserve-credentials ip -o -4 addr show $CLI_IF | grep -q '$CLI_TUN/24'"
check "connect: tun mtu is the server's (1400)" \
	sh -c "nsenter -t $NS_PID -n --preserve-credentials ip -o link show $CLI_IF | grep -q 'mtu 1400'"
check "connect: route from the ACL allow rule ($ROUTED_NET)" \
	sh -c "nsenter -t $NS_PID -n --preserve-credentials ip route show $ROUTED_NET | grep -q $CLI_IF"
check "connect: ping $SRV_TUN through the tunnel" ping_ok "$SRV_TUN"
check "connect: the client handles the pushed internal dns" log_has "$CLOG" "[cfg] dns"

echo "== 3. acl"
denied_before=$(grep -c '^\[deny\]' "$SLOG")
in_cli bash -c "echo probe > /dev/udp/$SRV_TUN/22" 2>/dev/null
check "acl: udp to $SRV_TUN:22 is dropped by the server" \
	wait_for 3 sh -c "[ \$(grep -c '^\[deny\]' '$SLOG') -gt $denied_before ]"
check "acl: the session survives a denied packet" ping_ok "$SRV_TUN"
# 서버가 막힌 패킷에 ICMP '관리자가 막음'을 돌려주므로 connect() 가 타임아웃을 기다리지 않고
# 바로 실패한다. 돌려주지 않으면 SYN 을 다시 보내며 3초를 다 쓰고 timeout 이 124 로 끝난다.
check "acl: a denied tcp connect fails at once (icmp prohibited), not by timeout" \
	sh -c "nsenter -t $NS_PID -n --preserve-credentials timeout 3 bash -c 'echo > /dev/tcp/$SRV_TUN/22' 2>/dev/null; [ \$? -ne 124 ]"

echo "== 4. posture"
check "posture: client ns has no inbound filter (firewall=off)" \
	sh -c "nsenter -t $NS_PID -n --preserve-credentials '$CLIENT' posture | grep -q 'firewall  off'"
# 기기 정책을 조인다: 이 기기 줄의 터널 주소 뒤에 firewall=on.
sed -i -E "s/^([0-9a-f]{32}[[:space:]]+(p256:)?[0-9a-f]+[[:space:]]+$CLI_TUN)/\1 firewall=on/" "$DEVICES"
kill -HUP "$SRV_PID"
t0=$(date +%s)
check "posture: policy tightened -> denied at the next keepalive" \
	wait_for "$KEEPALIVE_WAIT" log_has "$CLOG" "[deny] posture does not meet policy"
echo "     (denied after $(( $(date +%s) - t0 ))s)"
check "posture: no traffic while denied" ping_fails "$SRV_TUN"
check "posture: tun stays up while denied" in_cli ip link show "$CLI_IF"

# 인바운드 기본 거부. 터널(서버의 UDP, 7단계의 TCP, tun)과 lo, IPv6 의 이웃 탐색(11단계)만 받는다. conntrack 을 쓰지 않는 것은
# 사용자 네임스페이스에서 모듈을 올릴 수 없어서다.
in_cli nft -f - <<EOF
table inet e2e {
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		udp sport $PORT accept
		tcp sport $TCP_PORT accept
		meta l4proto ipv6-icmp accept
		iifname "$CLI_IF" accept
	}
}
EOF
t0=$(date +%s)
check "posture: firewall on -> client re-handshakes by itself" \
	wait_for 10 sh -c "[ \$(grep -c '] connected' '$CLOG') -ge 2 ]"
echo "     (reconnected after $(( $(date +%s) - t0 ))s)"
check "posture: traffic flows again" ping_ok "$SRV_TUN"

echo "== 5. user login"
udp_probe() { in_cli bash -c "echo probe > /dev/udp/$SRV_TUN/5353" 2>/dev/null; }
probe_passes() {
	local before; before=$(grep -c '^\[udp->tun\]' "$SLOG")
	udp_probe
	wait_for 3 sh -c "[ \$(grep -c '^\[udp->tun\]' '$SLOG') -gt $before ]"
}
probe_denied() {
	local before; before=$(grep -c '^\[deny\]' "$SLOG")
	udp_probe
	wait_for 3 sh -c "[ \$(grep -c '^\[deny\]' '$SLOG') -gt $before ]"
}

check "login: group=ops rule is closed before anyone logs in" probe_denied
check "login: the server says nobody is logged in" log_has "$SLOG" "(logged in: nobody)"

# 로그인 도구(client/ztgate_login)가 기기 인가로 토큰을 받아 파일에 쓰고, 끝나기 전에 갈아
# 끼운다. IdP 자리에는 시험용 OIDC 서버(tools/idp/mock_oidc.py)를 둔다. 토큰 수명을 12초로
# 짧게 줘서 갱신과 만료를 이 시험 안에서 본다.
TOKEN_TTL=12
python3 "$ROOT_DIR/tools/idp/mock_oidc.py" "$IDP" 18080 alice --groups ops,dev --ttl $TOKEN_TTL \
	> "$WORK/idp.log" 2>&1 &
IDP_PID=$!
wait_for 3 sh -c "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 18080))'"
python3 "$ROOT_DIR/client/ztgate_login" --issuer http://127.0.0.1:18080 --client-id ztgate \
	--token-file "$TOKEN" --keep > "$WORK/login.log" 2>&1 &
LOGIN_PID=$!

check "login: the login tool finishes the device grant" wait_for 10 log_has "$WORK/login.log" "signed in."
check "login: the token file is mode 600" test "$(stat -c %a "$TOKEN" 2>/dev/null)" = 600
check "login: the client sends the token and the server accepts it" \
	wait_for 5 log_has "$CLOG" "[login] logged in as alice"
check "login: the server attached alice to the session" log_has "$SLOG" "user alice (2 groups)"
check "login: group=ops rule is open for alice" probe_passes

check "login: the tool refreshes the token before it expires" \
	wait_for 15 log_has "$WORK/login.log" "token refreshed"
check "login: the client sends the new token" \
	wait_for 5 sh -c "[ \$(grep -c 'user alice (2 groups)' '$SLOG') -ge 2 ]"
check "login: still open after the first token's exp" probe_passes

# 도구를 멈추고 다른 IdP 의 토큰을 파일에 넣는다. 거절되고, 받아 둔 토큰은 그대로 쓴다.
kill "$LOGIN_PID" 2>/dev/null; wait "$LOGIN_PID" 2>/dev/null; LOGIN_PID=
python3 "$ROOT_DIR/tools/idp/mint.py" token "$IDP" alice --iss https://evil.test > "$TOKEN.tmp"
chmod 600 "$TOKEN.tmp" && mv "$TOKEN.tmp" "$TOKEN"
check "login: a token from another issuer is rejected" \
	wait_for 5 log_has "$CLOG" "[login] rejected: token is for another issuer or audience"
check "login: ...and alice stays logged in" probe_passes

# 아무도 갈아 끼우지 않으면 토큰이 끝나고, 그 순간부터 사용자 규칙은 닫힌다. 세션은 그대로다.
check "login: the client notices the token expired" \
	wait_for $((TOKEN_TTL + 3)) log_has "$CLOG" "[login] token expired"
check "login: group=ops rule is closed again" probe_denied
check "login: the tunnel itself still works" ping_ok "$SRV_TUN"

echo "== 6. connector"
# 커넥터 장비(ns2)와 그 뒤의 내부망 자원(ns3). 서버와 커넥터는 다른 veth 로 잇는다. 자원에는
# 터널 대역으로 가는 경로가 없다 — 답이 돌아온다면 커넥터의 NAT 를 지난 것이다.
#
#   [서버 ns] 192.0.3.1 --veth-- 192.0.3.2 [ns2: vpn_client connector] 198.51.100.1 --veth-- 198.51.100.10 [ns3]
RESOURCE=198.51.100.10
CON_ID=c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
CON_KEY=0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
in_con() { nsenter -t "$NS2_PID" -n --preserve-credentials "$@"; }
in_res() { nsenter -t "$NS3_PID" -n --preserve-credentials "$@"; }
unshare -n sleep infinity &
NS2_PID=$!
unshare -n sleep infinity &
NS3_PID=$!
sleep 0.2
ip link add v-srv2 type veth peer name v-con
ip link set v-con netns "$NS2_PID"
ip addr add 192.0.3.1/24 dev v-srv2
ip link set v-srv2 up
in_con ip link set lo up
in_con ip addr add 192.0.3.2/24 dev v-con
in_con ip link set v-con up
in_con ip link add v-lan type veth peer name v-res
in_con ip link set v-res netns "$NS3_PID"
in_con ip addr add 198.51.100.1/24 dev v-lan
in_con ip link set v-lan up
in_res ip link set lo up
in_res ip addr add "$RESOURCE/24" dev v-res
in_res ip link set v-res up

# 커넥터를 기기 목록에 올린다 (등록 코드로 올려도 같다 — 코드의 조건에 connector= 를 적는다).
printf '%s %s 10.0.0.9 connector=198.51.100.0/24\n' "$CON_ID" "$CON_KEY" >> "$DEVICES"
printf '%s %s\n' "$CON_ID" "$CON_KEY" > "$WORK/connector"
chmod 600 "$WORK/connector"
kill -HUP "$SRV_PID"
check "connector: the server reads connector=198.51.100.0/24" \
	wait_for 3 log_has "$SLOG" "connector: 198.51.100.0/24"

check "connector: before it connects, its network is unreachable" ping_fails "$RESOURCE"
check "connector: the server says the connector is not connected" \
	log_has "$SLOG" "[drop] connector $CON_ID is not connected"

# 클라이언트처럼 nsenter 를 바로 불러야 $! 로 멈출 수 있다.
nsenter -t "$NS2_PID" -n --preserve-credentials "$CLIENT" -k "$WORK/connector" -i ztgate1 connector 192.0.3.1 "$PORT" v-lan \
	> "$WORK/connector.log" 2>&1 &
CON_PID=$!
check "connector: session established" wait_for 10 log_has "$WORK/connector.log" "] connected"
check "connector: forwarding and NAT are set up" log_has "$WORK/connector.log" "[connector] forwarding 10.0.0.0/24"
check "connector: no route to its own network is pushed into the tunnel" \
	sh -c "! nsenter -t $NS2_PID -n --preserve-credentials ip route show 198.51.100.0/24 | grep -q ztgate1"
check "connector: the client reaches $RESOURCE through the connector" ping_ok "$RESOURCE"
check "connector: the server relayed it instead of using its own tun" log_has "$SLOG" "[udp->connector]"

# 내부망 쪽에서 터널로 연결을 시작하는 것은 막힌다. 자원이 커넥터를 거쳐 클라이언트에
# 닿을 길을 일부러 만들어 주고 시도한다.
in_res ip route add 10.0.0.0/24 via 198.51.100.1
check "connector: the LAN cannot open connections into the tunnel" \
	sh -c "! nsenter -t $NS3_PID -n --preserve-credentials ping -c 1 -W 1 $CLI_TUN"
in_res ip route del 10.0.0.0/24 via 198.51.100.1

# ACL 은 커넥터로 가기 전에 서버에서 걸린다.
denied_before=$(grep -c '^\[deny\]' "$SLOG")
in_cli bash -c "echo probe > /dev/udp/$RESOURCE/53" 2>/dev/null
check "connector: the ACL still applies (udp/53 to $RESOURCE is not allowed)" \
	wait_for 3 sh -c "[ \$(grep -c '^\[deny\]' '$SLOG') -gt $denied_before ]"

kill "$CON_PID"; wait "$CON_PID" 2>/dev/null; CON_PID=
check "connector: the server drops its session right away (DISCONNECT)" \
	wait_for 2 log_has "$SLOG" "10.0.0.9 closed its session"
check "connector: its nft table is removed when it stops" \
	sh -c "! nsenter -t $NS2_PID -n --preserve-credentials nft list table ip ztgate_connector"
check "connector: with the connector gone, its network is unreachable again" ping_fails "$RESOURCE"

echo "== 7. tcp"
# UDP 가 막힌 네트워크: 클라이언트 쪽에서 서버로 가는 UDP 를 버리고, 같은 기기로 TCP(-T) 로 다시 붙는다.
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=
in_cli nft -f - <<EOF
table inet e2e_noudp {
	chain output {
		type filter hook output priority 0; policy accept;
		udp dport $PORT drop
	}
}
EOF
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" -T "$TCP_PORT" \
	run "$SRV_VETH" "$PORT" > "$WORK/client-tcp.log" 2>&1 &
CLI_PID=$!
check "tcp: with udp blocked the client connects over tcp" wait_for 10 log_has "$WORK/client-tcp.log" "] connected"
check "tcp: ping $SRV_TUN through the tunnel over tcp" ping_ok "$SRV_TUN"
check "tcp: the server sees it as a tcp session" log_has "$SLOG" "(tcp) idx="
in_cli nft delete table inet e2e_noudp

echo "== 8. server key pinning"
# 신원 파일의 서버 공개키를 다른 키의 것으로 바꿔 둔다. 서버가 내미는 공개키와 다르므로 클라이언트는
# CHALLENGE 에 답하지 않는다 (사이에 낀 쪽이 공개키를 바꿔 끼운 것과 같은 장면).
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=
other_pub=$("$SERVER" genkey "$WORK/other.key")
awk -v p="$other_pub" '{ print $1, $2, p }' "$IDENT" > "$WORK/pinned"
chmod 600 "$WORK/pinned"
hs_before=$(grep -c "authenticated as $CLI_TUN" "$SLOG")
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$WORK/pinned" -i "$CLI_IF" \
	run "$SRV_VETH" "$PORT" > "$WORK/client-pin.log" 2>&1 &
CLI_PID=$!
check "pinning: a challenge with another server key is not answered" \
	wait_for 5 log_has "$WORK/client-pin.log" "not the one this device enrolled with"
check "pinning: so the server sees no AUTH from it" \
	test "$(grep -c "authenticated as $CLI_TUN" "$SLOG")" = "$hs_before"
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=

echo "== 9. failover"
# 192.0.2.9 에는 아무도 없다. 192.0.2.3 은 같은 서버의 두 번째 주소 — 클라이언트에게는 다른 서버다.
SRV_VETH2=192.0.2.3
ip addr add "$SRV_VETH2/24" dev v-srv
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" \
	run "192.0.2.9,$SRV_VETH,$SRV_VETH2" "$PORT" > "$WORK/client-fo.log" 2>&1 &
CLI_PID=$!
check "failover: a server that does not answer is skipped" wait_for 15 log_has "$WORK/client-fo.log" "] connected"
check "failover: ...and the next one is used" log_has "$WORK/client-fo.log" "tunneling to $SRV_VETH:"
check "failover: ping through the tunnel" ping_ok "$SRV_TUN"
# 지금 서버로 가는 길만 끊는다. 30초 동안 답이 없으면 다시 핸드셰이크하고, 실패하면 다음 서버로.
in_cli nft -f - <<EOF
table inet e2e_fo {
	chain output {
		type filter hook output priority 0; policy accept;
		ip daddr $SRV_VETH udp dport $PORT drop
	}
}
EOF
check "failover: when the current server goes silent the client moves on" \
	wait_for 50 log_has "$WORK/client-fo.log" "does not answer, switching to $SRV_VETH2"
check "failover: connected again through the other server" \
	wait_for 10 sh -c "[ \$(grep -c '] connected' '$WORK/client-fo.log') -ge 2 ]"
check "failover: ping through the tunnel after the switch" ping_ok "$SRV_TUN"
in_cli nft delete table inet e2e_fo
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=

echo "== 11. ipv6"
SRV_V6=fd00:e2e::1
in_cli ip -6 addr add fd00:e2e::2/64 dev v-cli nodad
ip -6 addr add "$SRV_V6/64" dev v-srv nodad
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" \
	run "$SRV_V6" "$PORT" > "$WORK/client-v6.log" 2>&1 &
CLI_PID=$!
check "ipv6: the client reaches the server over IPv6" wait_for 10 log_has "$WORK/client-v6.log" "] connected"
check "ipv6: ...and says where" log_has "$WORK/client-v6.log" "tunneling to [$SRV_V6]:$PORT"
check "ipv6: the server sees an IPv6 endpoint" log_has "$SLOG" "<- [fd00:e2e::2]:"
check "ipv6: ping through the tunnel" ping_ok "$SRV_TUN"
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=

echo "== 10. dpop"
DKEY=$WORK/dpop.pem
DTOK=$WORK/dpop-token
"$CLIENT" -D "$DKEY" dpop-jkt > "$WORK/jkt" 2>/dev/null
check "dpop: the client makes its device key (mode 600)" test "$(stat -c %a "$DKEY" 2>/dev/null)" = 600
python3 "$ROOT_DIR/tools/idp/mint.py" token "$IDP" alice --groups ops --dpop-key "$DKEY" > "$DTOK"
chmod 600 "$DTOK"
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" -t "$DTOK" \
	run "$SRV_VETH" "$PORT" > "$WORK/client-dpop1.log" 2>&1 &
CLI_PID=$!
check "dpop: a token bound to the key, sent without it, is rejected" \
	wait_for 10 log_has "$WORK/client-dpop1.log" "bound to a device key"
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=

# 로그인 도구가 IdP 에 같은 키의 증명을 보내 그 키에 묶인 토큰을 받는다.
python3 "$ROOT_DIR/client/ztgate_login" --issuer http://127.0.0.1:18080 --client-id ztgate \
	--token-file "$DTOK" --dpop-key "$DKEY" > "$WORK/login-dpop.log" 2>&1
check "dpop: the IdP bound the token to this device's key" \
	log_has "$WORK/idp.log" "DPoP-bound token for jkt $(cat "$WORK/jkt")"
nsenter -t "$NS_PID" -n --preserve-credentials "$CLIENT" -k "$IDENT" -i "$CLI_IF" -t "$DTOK" -D "$DKEY" \
	run "$SRV_VETH" "$PORT" > "$WORK/client-dpop2.log" 2>&1 &
CLI_PID=$!
check "dpop: with the device key the server accepts it" \
	wait_for 10 log_has "$WORK/client-dpop2.log" "[login] logged in as alice"
kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null; CLI_PID=

echo
if [ "$failed" -eq 0 ]; then
	echo "all passed"
else
	echo "$failed failed"
fi
exit "$failed"
