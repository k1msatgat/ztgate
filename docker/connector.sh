#!/usr/bin/env bash
# 앱 커넥터 패키지(ztgate-connector)를 실제로 설치해 돌린다. Debian 12 에서 .deb 를 만들고, systemd 가
# 도는 컨테이너에 설치해 초대 링크로 등록한 뒤, 클라이언트가 그 커넥터를 지나 내부망의 장비에 닿는지 본다.
#
#   [client] --wan 172.30.77.0/24-- [server] --wan-- [connector: systemd, ztgate-connector] --lan 172.30.78.0/24-- [lanhost]
#
# lan 은 docker 의 internal 망이라 밖으로 나가는 길이 없다. 클라이언트에게 lanhost 로 가는 길은 터널뿐이다.
# 커넥터 컨테이너는 systemd 를 띄우려고 --privileged 로 돈다. 서비스가 받는 힘은 단위 파일이 정한다
# (그것도 여기서 본다).
#
#   docker/connector.sh          끝나면 컨테이너, 망, 이미지를 지운다
#   KEEP=1 docker/connector.sh   남겨 둔다
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD
W=$(mktemp -d)
P=zt-conn
WAN=172.30.77
LAN=172.30.78
HOST=$LAN.20
failed=0

cleanup() {
	if [ "$failed" -ne 0 ]; then
		echo "---- server ----"; docker logs --tail 30 $P-server 2>&1
		echo "---- connector ----"; docker exec $P-connector journalctl -u ztgate-connector -n 30 --no-pager 2>&1
		echo "---- client ----"; docker logs --tail 30 $P-client 2>&1
	fi
	if [ -z "${KEEP:-}" ]; then
		docker rm -f $P-server $P-connector $P-client $P-lanhost > /dev/null 2>&1
		docker network rm $P-wan $P-lan > /dev/null 2>&1
		docker image rm $P-ztgate $P-connector > /dev/null 2>&1
	fi
	rm -rf "$W" 2> /dev/null || docker run --rm -v "$W:/w" debian:bookworm rm -rf /w/out
}
trap cleanup EXIT

check() {
	if [ "$2" = "$3" ]; then printf 'ok    %-62s %s\n' "$1" "$2"
	else printf 'FAIL  %-62s %s   (want %s)\n' "$1" "$2" "$3"; failed=$((failed + 1)); fi
}
until_ok() {	# 초 명령..
	local n=$(( $1 * 2 )); shift
	for _ in $(seq 1 $n); do "$@" > /dev/null 2>&1 && return 0; sleep 0.5; done
	return 1
}
yes_if() { "$@" > /dev/null 2>&1 && echo yes || echo no; }
srv() { docker exec $P-server "$@"; }
con() { docker exec $P-connector "$@"; }
cli() { docker exec $P-client "$@"; }
reaches() { cli ping -c 1 -W 1 "$HOST"; }
active() { con systemctl is-active ztgate-connector; }
main_pid() { con systemctl show -p MainPID --value ztgate-connector; }

echo "== package"
mkdir "$W/out"
docker run --rm -v "$ROOT:/src:ro" -v "$W/out:/out" debian:bookworm bash -euc '
	apt-get update -qq > /dev/null
	apt-get install -y -qq --no-install-recommends gcc make libc6-dev libssl-dev binutils dpkg-dev > /dev/null
	cp -a /src /b && cd /b && make clean > /dev/null && make client CFLAGS="-Wall -Wextra -Werror -O2" > /dev/null
	packaging/build.sh connector-deb /out > /dev/null' || exit 1
DEB=$(cd "$W/out" && ls ztgate-connector_*.deb)
check "built $DEB" "$(yes_if test -s "$W/out/$DEB")" yes

cat > "$W/out/Dockerfile" <<'EOF'
FROM debian:bookworm
RUN apt-get update && apt-get install -y -qq --no-install-recommends systemd systemd-sysv iproute2 iputils-ping \
	&& rm -rf /var/lib/apt/lists/*
COPY *.deb /root/
RUN apt-get update && apt-get install -y -qq --no-install-recommends /root/*.deb && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker build -q -t $P-connector "$W/out" > /dev/null || exit 1
docker build -q -t $P-ztgate . > /dev/null || exit 1

docker network create --subnet $WAN.0/24 $P-wan > /dev/null || exit 1
docker network create --internal --subnet $LAN.0/24 $P-lan > /dev/null || exit 1

echo "== server"
docker run -d --name $P-server --network $P-wan --ip $WAN.10 --network-alias vpn.zt-conn.test \
	--cap-add NET_ADMIN --device /dev/net/tun $P-ztgate server > /dev/null || exit 1
until_ok 10 srv test -S /run/vpn_status.sock
# ACL 을 쓸지는 서버가 뜰 때 정해진다. 규칙을 넣고 다시 띄운다. allow 의 목적지가 클라이언트의 경로가 된다.
printf '10.0.0.0/24  %s.0/24  icmp  any  allow\nany  any  any  any  deny\n' $LAN | docker exec -i $P-server sh -c "cat > /etc/ztgate/acl.conf"
docker restart $P-server > /dev/null
until_ok 10 srv test -S /run/vpn_status.sock

docker run -d --name $P-lanhost --network $P-lan --ip $HOST --entrypoint sleep $P-ztgate infinity > /dev/null || exit 1

echo "== client"
code=$(srv enroll-code.sh 10.0.0.2 -l laptop)
docker run -d --name $P-client --network $P-wan --ip $WAN.20 -e SERVER=vpn.zt-conn.test -e ENROLL_CODE="$code" \
	--cap-add NET_ADMIN --device /dev/net/tun $P-ztgate client > /dev/null || exit 1
check "client: connected" "$(yes_if until_ok 15 sh -c "docker logs $P-client 2>&1 | grep -q '] connected'")" yes
check "client: the route to $LAN.0/24 goes into the tunnel" "$(cli ip -o route get $HOST | awk '{print $3}')" ztgate0
check "no connector yet: $HOST is unreachable" "$(yes_if reaches)" no

echo "== connector"
docker create --name $P-connector --privileged --network $P-wan --ip $WAN.30 --tmpfs /run --tmpfs /run/lock \
	$P-connector > /dev/null || exit 1
docker network connect --ip $LAN.2 $P-lan $P-connector || exit 1
docker start $P-connector > /dev/null || exit 1
until_ok 30 sh -c "docker exec $P-connector systemctl is-system-running | grep -Eq 'running|degraded'"
LAN_IF=$(con ip -o -4 addr show | awk -v n="$LAN.2/" 'index($4, n) == 1 { print $2 }')
check "installed, not enrolled: the service is off" "$(con systemctl is-enabled ztgate-connector) $(active)" "disabled inactive"
check "the identity folder is root's 700" "$(con stat -c '%U %a' /var/lib/ztgate-connector)" "root 700"
check "enroll without root: refused" "$(con setpriv --reuid=65534 --regid=65534 --clear-groups ztgate-connector enroll x 1 y --lan-if "$LAN_IF" > /dev/null 2>&1; echo $?)" 1

code=$(srv enroll-code.sh 10.0.0.9 -l gw connector=$LAN.0/24)
invite="ztgate://enroll?server=vpn.zt-conn.test&port=9000&code=$code"
out=$(con ztgate-connector enroll "$invite" --lan-if "$LAN_IF" 2>&1)
check "enroll with the invite link" "$(echo "$out" | grep -c -e 'enrolled.' -e '서비스를 켰습니다')" 2
check "connector.env" "$(con grep -v '^#' /etc/ztgate-connector/connector.env | tr '\n' ' ')" "SERVER=vpn.zt-conn.test PORT=9000 LAN_IF=$LAN_IF "
check "the identity is root's 600" "$(con stat -c '%U %a' /var/lib/ztgate-connector/device)" "root 600"
check "the service is enabled and active" "$(con systemctl is-enabled ztgate-connector) $(yes_if until_ok 10 active)" "enabled yes"
check "the journal shows forwarding to $LAN_IF" "$(yes_if until_ok 10 sh -c "docker exec $P-connector journalctl -u ztgate-connector --no-pager | grep -q 'forwarding 10.0.0.0/24 -> $LAN_IF'")" yes
pid=$(main_pid)
check "the main process is vpn_client (the wrapper exec'd it)" "$(con cat /proc/$pid/comm)" vpn_client
check "it holds CAP_NET_ADMIN only" "$(con awk '/^CapEff/ { print $2 }' /proc/$pid/status)" 0000000000001000
check "the client reaches $HOST through the connector" "$(yes_if until_ok 15 reaches)" yes
check "status shows the unit and the log" "$(con ztgate-connector status | grep -c -e '서비스    active, enabled' -e 'forwarding')" 2

con systemctl stop ztgate-connector
check "stop: the nft table is gone" "$(yes_if con nft list table ip ztgate_connector)" no
check "stop: $HOST is unreachable again" "$(yes_if reaches)" no
con systemctl start ztgate-connector
check "start: reachable again" "$(yes_if until_ok 15 reaches)" yes

con systemctl kill --signal=KILL ztgate-connector
check "killed: systemd brings it back (Restart=always)" "$(yes_if until_ok 20 sh -c "[ \"\$(docker exec $P-connector systemctl show -p NRestarts --value ztgate-connector)\" -ge 1 ]")" yes
check "...and the client reaches $HOST again" "$(yes_if until_ok 20 reaches)" yes

sum=$(con sha256sum /var/lib/ztgate-connector/device)
pid=$(main_pid)
con dpkg -i "/root/$DEB" > /dev/null
check "upgrade (dpkg -i again): identity unchanged" "$(con sha256sum /var/lib/ztgate-connector/device)" "$sum"
check "upgrade: the running connector was restarted" "$(yes_if until_ok 10 sh -c "[ \"\$(docker exec $P-connector systemctl show -p MainPID --value ztgate-connector)\" != $pid ] && docker exec $P-connector systemctl is-active -q ztgate-connector")" yes
check "upgrade: reachable" "$(yes_if until_ok 15 reaches)" yes

con dpkg -r ztgate-connector > /dev/null
check "remove: the service is stopped" "$(active)" inactive
check "remove: identity and connector.env stay" "$(con sha256sum /var/lib/ztgate-connector/device) $(yes_if con test -f /etc/ztgate-connector/connector.env)" "$sum yes"
check "remove: the program is gone" "$(yes_if con test -e /opt/ztgate-connector/bin/vpn_client)" no
con dpkg -i "/root/$DEB" > /dev/null
con systemctl enable --now ztgate-connector 2> /dev/null
check "reinstall + enable: the same identity connects" "$(yes_if until_ok 15 reaches)" yes

check "unenroll without --yes: refused" "$(con ztgate-connector unenroll > /dev/null 2>&1; echo $?)" 1
con ztgate-connector unenroll --yes > /dev/null
check "unenroll: service off, identity and env gone" "$(con systemctl is-enabled ztgate-connector) $(active) $(yes_if con test -e /var/lib/ztgate-connector/device)$(yes_if con test -e /etc/ztgate-connector/connector.env)" "disabled inactive nono"
check "unenroll: $HOST is unreachable" "$(yes_if reaches)" no

echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
