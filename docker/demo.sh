#!/usr/bin/env bash
# docker compose 로 서버 + Linux 클라이언트 두 컨테이너를 띄워 test/linux_e2e.sh 와 같은
# 시나리오를 돌린다: 등록 -> 연결 -> ACL 차단 -> 포스처 거부와 복구.
#
#   docker/demo.sh          끝나면 컨테이너와 볼륨을 지운다
#   KEEP=1 docker/demo.sh   남겨 둔다 (docker compose logs / exec 로 들여다볼 수 있다)

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DC=(docker compose)
SRV_TUN=10.0.0.1
CLI_TUN=10.0.0.2
OTHER=10.0.0.3		# ACL 이 열지 않은 목적지
KEEPALIVE_WAIT=15
failed=0

cleanup() {
	if [ "$failed" -ne 0 ]; then
		echo; echo "---- server ----"; "${DC[@]}" logs --no-color --tail 40 server
		echo "---- client ----"; "${DC[@]}" logs --no-color --tail 40 client
	fi
	[ -n "${KEEP:-}" ] || "${DC[@]}" down -v --remove-orphans > /dev/null 2>&1
}
trap cleanup EXIT

check() {
	local name=$1; shift
	if "$@" > /dev/null 2>&1; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name"
		failed=$((failed + 1))
	fi
}

wait_for() {
	local i=$(( $1 * 2 )); shift
	while [ "$i" -gt 0 ]; do
		"$@" > /dev/null 2>&1 && return 0
		sleep 0.5
		i=$((i - 1))
	done
	return 1
}

logs_have() { "${DC[@]}" logs --no-color "$1" 2>/dev/null | grep -qF -- "$2"; }
cli() { "${DC[@]}" exec -T client "$@"; }
srv() { "${DC[@]}" exec -T server "$@"; }

"${DC[@]}" down -v --remove-orphans > /dev/null 2>&1
"${DC[@]}" build -q || exit 1

echo "== server"
"${DC[@]}" up -d server > /dev/null || exit 1
# ACL 을 쓸지는 서버가 뜰 때 정해진다. 규칙을 넣고 다시 띄운다.
srv sh -c 'cat > /etc/ztgate/acl.conf' <<EOF
10.0.0.0/24  $SRV_TUN  icmp  any  allow
any          any       any   any  deny
EOF
"${DC[@]}" restart server > /dev/null
# 처음 뜬 것과 다시 뜬 것, 두 번 찍혀야 다시 뜬 서버가 준비된 것이다.
check "server: restarted with the ACL, tun up with $SRV_TUN" \
	wait_for 10 sh -c "[ \$(${DC[*]} logs --no-color server | grep -cF ' $SRV_TUN/24 mtu ') -ge 2 ]"

echo "== enroll + connect"
CODE=$(srv enroll-code.sh "$CLI_TUN" -l demo)
echo "     code $CODE"
ENROLL_CODE=$CODE "${DC[@]}" up -d client > /dev/null
check "client: enrolled with the code" wait_for 10 logs_have client "enrolled. identity saved"
check "client: connected" wait_for 10 logs_have client "] connected"
check "client: tun has $CLI_TUN from the server" sh -c "${DC[*]} exec -T client ip -o -4 addr show ztgate0 | grep -q $CLI_TUN/24"
check "client: ping $SRV_TUN through the tunnel" cli ping -c 1 -W 2 "$SRV_TUN"

echo "== acl"
cli ping -c 1 -W 1 "$OTHER" > /dev/null 2>&1
check "acl: $CLI_TUN -> $OTHER denied by the server" wait_for 3 logs_have server "[deny] $CLI_TUN -> $OTHER"

echo "== posture"
check "posture: client container has no inbound filter" sh -c "${DC[*]} exec -T client vpn_client posture | grep -q 'firewall  off'"
srv sh -c "sed -i -E 's/^([0-9a-f]{32}[[:space:]]+(p256:)?[0-9a-f]+[[:space:]]+$CLI_TUN)/\1 firewall=on/' /etc/ztgate/devices.conf && pkill -HUP -x vpn_server"
check "posture: policy tightened -> denied at the next keepalive" \
	wait_for "$KEEPALIVE_WAIT" logs_have client "[deny] posture does not meet policy"
check "posture: no traffic while denied" sh -c "! ${DC[*]} exec -T client ping -c 1 -W 1 $SRV_TUN"
cli nft -f - <<EOF
table inet demo {
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		udp sport 9000 accept
		iifname "ztgate0" accept
	}
}
EOF
check "posture: firewall on -> client re-handshakes by itself" \
	wait_for 10 sh -c "[ \$(${DC[*]} logs --no-color client | grep -cF '] connected') -ge 2 ]"
check "posture: traffic flows again" cli ping -c 1 -W 2 "$SRV_TUN"

echo
if [ "$failed" -eq 0 ]; then
	echo "all passed"
else
	echo "$failed failed"
fi
exit "$failed"
