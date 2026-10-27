#!/usr/bin/env bash
# 서버 두 대의 동기화(tools/sync/ztgate-sync)를 실제 ssh 로 돌린다. docker/ha/compose.yml 의 주 서버,
# 부 서버, 두 서버를 다 아는 Linux 클라이언트로 관리자 안내서의 "서버 두 대로 장애에 대비하기" 를 따라 간다:
# 주에서 등록한 기기가 동기화 뒤 주가 꺼지면 부로 넘어가 붙는지, ACL 을 켜면 부가 다시 뜨고 고치면 다시
# 읽는지, 꺼져 있던 부가 다음 동기화에 따라잡는지.
#
#   docker/ha.sh          끝나면 컨테이너와 볼륨을 지운다
#   KEEP=1 docker/ha.sh   남겨 둔다
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD
W=$(mktemp -d)
DC=(docker compose -p ztha -f "$W/compose.yml")
failed=0

cleanup() {
	if [ "$failed" -ne 0 ]; then
		for s in primary secondary; do echo "---- $s ----"; "${DC[@]}" logs --no-color --tail 30 $s; done
		echo "---- client ----"; "${DC[@]}" exec -T client cat /tmp/run.log 2>/dev/null | tail -30
	fi
	[ -n "${KEEP:-}" ] || "${DC[@]}" down -v --remove-orphans > /dev/null 2>&1
	rm -rf "$W"
}
trap cleanup EXIT

check() {
	if [ "$2" = "$3" ]; then printf 'ok    %-58s %s\n' "$1" "$2"
	else printf 'FAIL  %-58s %s   (want %s)\n' "$1" "$2" "$3"; failed=$((failed + 1)); fi
}
p() { "${DC[@]}" exec -T primary "$@"; }
s() { "${DC[@]}" exec -T secondary "$@"; }
c() { "${DC[@]}" exec -T client "$@"; }
starts() { "${DC[@]}" logs --no-color "$1" 2>/dev/null | grep -c 'entrypoint: '; }
started_more() { test "$(starts "$1")" -gt "$2"; }
sum() { "${DC[@]}" exec -T "$1" sha256sum "/etc/ztgate/$2" 2>/dev/null | cut -c1-16; }
until_ok() {	# 초 명령..
	local n=$(( $1 * 2 )); shift
	for _ in $(seq 1 $n); do "$@" > /dev/null 2>&1 && return 0; sleep 0.5; done
	return 1
}
yes_if() { "$@" > /dev/null 2>&1 && echo yes || echo no; }

cp docker/ha/compose.yml docker/ha/secondary.sh docker/ha/Dockerfile tools/sync/ztgate-sync "$W/"
mkdir "$W/keys"
ssh-keygen -q -t ed25519 -N '' -f "$W/keys/sync.key"
ssh-keygen -q -t ed25519 -N '' -f "$W/keys/host_ed25519"
docker build -q -t ztgate . > /dev/null || exit 1
docker build -q -t ztgate-ha "$W" > /dev/null || exit 1
"${DC[@]}" up -d > /dev/null 2>&1 || exit 1
until_ok 20 started_more primary 0 && until_ok 20 started_more secondary 0 || { failed=1; echo "servers did not start"; exit 1; }

# 3단계: 주 서버의 /etc/ztgate-sync (root, 700) 에 키와 sync.conf (600)
p sh -c 'install -d -m 700 /etc/ztgate-sync && install -m 600 /dev/stdin /etc/ztgate-sync/sync.key' < "$W/keys/sync.key"
p sh -c 'printf "PEERS=\"ztsync@172.30.9.12\"\nSSH_KEY=/etc/ztgate-sync/sync.key\nRELOAD=\"sudo pkill -HUP -x vpn_server\"\nRESTART=\"sudo pkill -TERM -x vpn_server\"\n" | install -m 600 /dev/stdin /etc/ztgate-sync/sync.conf'
check "server keys differ before the first sync" "$(yes_if test "$(sum primary server.key)" != "$(sum secondary server.key)")" yes

code=$(p enroll-code.sh 10.0.0.2 -l ha-laptop)
check "a device enrolls at the primary" "$(yes_if c vpn_client -k /var/lib/ztgate/device enroll 172.30.9.11 9000 "$code")" yes

check "sync before the secondary's host key is known: refused" "$(p ztgate-sync > /dev/null 2>&1; echo $?)" 1
# 4단계: 처음 한 번 root 로 접속해 부 서버의 호스트 키를 받아 둔다 (사람은 지문을 보고 yes)
p ssh -o StrictHostKeyChecking=accept-new -i /etc/ztgate-sync/sync.key ztsync@172.30.9.12 true > /dev/null 2>&1

n=$(starts secondary)
out=$(p ztgate-sync 2>&1)
check "first sync" "$out" "ztgate-sync: ztsync@172.30.9.12: done (restarted)"
check "the secondary restarted for the new server key" "$(yes_if until_ok 20 started_more secondary "$n")" yes
check "server.key is the same on both" "$(sum secondary server.key)" "$(sum primary server.key)"
check "devices.conf is the same on both" "$(sum secondary devices.conf)" "$(sum primary devices.conf)"
check "enrollment codes stay on the primary" "$(s grep -c . /etc/ztgate/enroll.conf)" 0
check "the secondary knows its primary" "$(s cat /etc/ztgate/.sync-primary)" vpn1

"${DC[@]}" exec -d client sh -c 'stdbuf -oL -eL vpn_client -k /var/lib/ztgate/device run 172.30.9.11,172.30.9.12 9000 > /tmp/run.log 2>&1'
check "the client reaches the primary" "$(yes_if until_ok 15 c ping -c 1 -W 1 10.0.0.1)" yes

docker stop ztha-primary-1 > /dev/null
check "primary down: the client moves to the secondary" "$(yes_if until_ok 60 c grep -q 'switching to 172.30.9.12' /tmp/run.log)" yes
check "the tunnel works through the secondary" "$(yes_if until_ok 20 c ping -c 1 -W 1 10.0.0.1)" yes
docker start ztha-primary-1 > /dev/null
until_ok 20 p test -S /run/vpn_status.sock

printf '10.0.0.0/24  10.0.0.1  icmp  any  allow\nany  any  any  any  deny\n' | p sh -c 'install -m 600 /dev/stdin /etc/ztgate/acl.conf'
check "a new acl.conf restarts the secondary" "$(p ztgate-sync 2>&1)" "ztgate-sync: ztsync@172.30.9.12: done (restarted)"
check "icmp allowed by the synced acl" "$(yes_if until_ok 30 c ping -c 1 -W 1 10.0.0.1)" yes
printf '10.0.0.0/24  10.0.0.1  tcp  22  allow\nany  any  any  any  deny\n' | p sh -c 'install -m 600 /dev/stdin /etc/ztgate/acl.conf'
check "a changed acl.conf only reloads" "$(p ztgate-sync 2>&1)" "ztgate-sync: ztsync@172.30.9.12: done (reloaded)"
sleep 1
check "icmp now denied by the secondary" "$(yes_if c ping -c 1 -W 2 10.0.0.1)" no
check "the secondary logged the deny" "$(yes_if until_ok 5 sh -c "docker logs ztha-secondary-1 2>&1 | grep -qF '[deny] 10.0.0.2 -> 10.0.0.1'")" yes

docker stop ztha-secondary-1 > /dev/null
p sh -c 'echo "# changed while vpn2 was down" >> /etc/ztgate/devices.conf'
check "secondary down: the sync fails" "$(p ztgate-sync > /dev/null 2>&1; echo $?)" 1
docker start ztha-secondary-1 > /dev/null
until_ok 20 s test -S /run/vpn_status.sock
check "the next sync catches up" "$(p ztgate-sync > /dev/null 2>&1; echo $?)" 0
check "devices.conf caught up" "$(sum secondary devices.conf)" "$(sum primary devices.conf)"

echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
