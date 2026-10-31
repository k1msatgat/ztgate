#!/usr/bin/env bash
# MCP 배포기(mcp/deploy.cjs, ztgate-deploy)를 systemd 가 도는 장비에서 실제로 돌린다. 이 체크아웃으로 원격 저장소를
# 만들고 좋은 커밋과 깨진 커밋을 더한 뒤, MCP 의 deploy / deploy_status / deploy_rollback 이 보내는 것과 같은 JSON 을
# sudo ztgate-deploy 에 보낸다. 끝에서 MCP 서버(server.js)를 stdio 로 띄워 도구 하나를 실제 JSON-RPC 로 부른다.
#
#   test/deploy_check.sh      일반 계정으로 (sudo 를 스스로 부른다). 장비의 서버 패키지를 바꾸므로 버려도 되는
#                             장비에서만: CI 러너(deb), docker/deploy 의 Rocky 9 컨테이너(rpm). ztgate-server 가
#                             깔려 있지 않은 장비에서 시작한다
#
# 빌드를 여섯 번 하고, 검사마다 서비스를 15초씩 지켜본다. 1 CPU 컨테이너에서 전체가 몇 분이다.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD
T=/srv/ztgate-deploy-check
REMOTE=$T/remote.git
DEPLOY=/opt/ztgate-mcp/libexec/ztgate-deploy
failed=0

check() {
	if [ "$2" = "$3" ]; then printf 'ok    %-66s %s\n' "$1" "$2"
	else printf 'FAIL  %-66s %s   (want %s)\n' "$1" "$2" "$3"; failed=$((failed + 1)); fi
}
yes_if() { "$@" > /dev/null 2>&1 && echo yes || echo no; }
dz() { printf '%s' "$1" | sudo -n "$DEPLOY"; }
j() { python3 -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
rgit() { sudo git -C "$T/work" -c user.name=deploy-check -c user.email=deploy-check@example.invalid "$@"; }
commit() {	# 브랜치 메시지 -> 새 커밋 id
	rgit add -A > /dev/null && rgit commit -q -m "$2" && rgit push -q "$REMOTE" "HEAD:refs/heads/$1" && rgit rev-parse HEAD
}
mark() {	# 서버가 뜰 때 찍는 줄을 바꿔 실행 파일이 달라지게 한다
	sudo sed -i "s/listening[^\"]*on UDP/listening ($1) on UDP/" "$T/work/server/src/server.c"
}
wait_job() {	# 작업 id -> 끝난 뒤의 deploy_status
	local out
	for _ in $(seq 12); do
		out=$(dz "{\"cmd\":\"deploy_status\",\"job\":\"$1\",\"wait_seconds\":150}")
		if [ "$(echo "$out" | j 'd["job"]["outcome"]')" != None ]; then echo "$out"; return; fi
	done
	echo "$out"
}
start() {	# 요청 JSON -> 작업 id
	dz "$1" | j 'd["job"]["id"] if d["ok"] else "ERROR " + d["error"]'
}
installed() { dz '{"cmd":"deploy_status"}' | j 'd["installed"].get("commit")'; }
etc_sums() { sudo find /etc/ztgate -type f ! -name .ztgate.lock -exec sha256sum {} + | sort | sha256sum | cut -c1-16; }
main_pid() { systemctl show -p MainPID --value ztgate; }
outcome() { echo "$1" | j 'd["job"]["outcome"]'; }
on_fail() {
	echo "---- last job"
	dz '{"cmd":"deploy_status"}' | python3 -m json.tool | tail -n 60
	sudo journalctl -u ztgate-deploy -n 20 --no-pager
}

if rpm -q ztgate-server > /dev/null 2>&1 || dpkg-query -W ztgate-server > /dev/null 2>&1; then
	echo "ztgate-server is installed; run this on a throwaway host without it" >&2
	exit 2
fi

echo "== remote with commits from this checkout"
sudo rm -rf "$T"
sudo mkdir -p "$T/work"
sudo git init -q --bare "$REMOTE"
if [ -d .git ]; then
	git archive HEAD | sudo tar -x -C "$T/work"
else
	tar -c --exclude=./mcp/node_modules --exclude='*.o' --exclude=./server/bin --exclude=./client/bin . | sudo tar -x -C "$T/work"
fi
sudo git init -q -b main "$T/work"
BASE=$(commit main base)
check "base commit on main" "${#BASE}" 40

echo "== install MCP and the deployer (mcp/install.sh)"
mcp/install.sh "$(id -un)" > /dev/null || exit 1
printf 'REPO=%s\nBRANCHES=main wip/*\nTAGS=v*\nKEEP=5\n' "$REMOTE" | sudo install -m 600 /dev/stdin /etc/ztgate-deploy/deploy.conf
check "sudoers: the deployer, without arguments" "$(sudo grep -c "NOPASSWD: $DEPLOY \"\"$" /etc/sudoers.d/ztgate_mcp)" 1

echo "== first package"
out=$(dz '{"cmd":"deploy","ref":"main","actor":"mcp"}')
check "nothing installed: refused without no_revert" "$(echo "$out" | j 'd["ok"], "no_revert" in d["error"]')" "False True"
id=$(start '{"cmd":"deploy","ref":"main","accept":["no_revert"],"actor":"mcp"}')
out=$(wait_job "$id")
check "first package: installed" "$(outcome "$out")" installed
check "first package: the stopped server was not checked as running" "$(echo "$out" | j '[c["ok"] for c in d["job"]["check"]["checks"] if c["name"] == "service"]')" "[None]"
check "first package: installed commit is the base" "$(installed)" "${BASE:0:12}"
build1=$(echo "$out" | j 'd["job"]["build"]')
echo "      build: $build1"
sudo ztgate setup --yes --no-firewall > /dev/null
check "ztgate setup started the server" "$(systemctl is-active ztgate)" active
sums=$(etc_sums)

echo "== good commit"
mark good
GOOD=$(commit main good)
id=$(start '{"cmd":"deploy","ref":"main","actor":"mcp"}')
for _ in $(seq 600); do
	[ "$(dz "{\"cmd\":\"deploy_status\",\"job\":\"$id\"}" | j 'd["job"]["phase"]')" = checking ] && break
	sleep 0.5
done
out=$(echo '{"cmd":"restart","actor":"mcp"}' | sudo -n /usr/sbin/ztgate_ctl)
check "while the new server is checked, ztgate_ctl refuses restart" "$(echo "$out" | j 'd["ok"], "a deploy is installing" in d.get("error", "")')" "False True"
out=$(wait_job "$id")
check "good commit: installed" "$(outcome "$out")" installed
check "good commit: every check passed" "$(echo "$out" | j 'd["job"]["check"]["passed"], sorted(c["name"] for c in d["job"]["check"]["checks"] if c["ok"])')" \
	"True ['binary', 'ctl', 'package', 'server_key', 'service', 'udp']"
check "good commit: installed commit" "$(installed)" "${GOOD:0:12}"
check "good commit: the new binary runs (its startup line)" "$(yes_if sh -c 'sudo journalctl -u ztgate -n 200 --no-pager | grep -q "listening (good) on UDP"')" yes
check "good commit: previous is the base" "$(dz '{"cmd":"deploy_status"}' | j 'd["previous"]["commit"]')" "${BASE:0:12}"
check "good commit: /etc/ztgate unchanged" "$(etc_sums)" "$sums"

echo "== same commit"
pid=$(main_pid)
out=$(wait_job "$(start '{"cmd":"deploy","ref":"main","actor":"mcp"}')")
check "same commit: unchanged" "$(outcome "$out")" unchanged
check "same commit: no build, no restart" "$(echo "$out" | j 'd["job"]["build"]') $(main_pid)" "None $pid"

echo "== broken commit (the service exits at start)"
rgit checkout -q -b wip/broken
sudo sed -i 's/^run)$/run)\n\techo "deploy_check: broken on purpose" >\&2; exit 3/' "$T/work/mcp/service.sh"
BROKEN=$(commit wip/broken broken)
rgit checkout -q main
out=$(wait_job "$(start '{"cmd":"deploy","ref":"wip/broken","actor":"mcp"}')")
check "broken: reverted" "$(outcome "$out")" reverted
check "broken: the service check is what failed" "$(echo "$out" | j '[c["name"] for c in d["job"]["check"]["checks"] if c["ok"] is False]')" "['service']"
check "broken: the check after the revert passed" "$(echo "$out" | j 'd["job"]["revert_check"]["passed"]')" True
check "broken: the good commit is installed again" "$(installed)" "${GOOD:0:12}"
check "broken: the server is up" "$(systemctl is-active ztgate)" active
check "broken: /etc/ztgate is byte-identical" "$(etc_sums)" "$sums"
check "broken: its package is kept for inspection" "$(dz '{"cmd":"deploy_status"}' | j '"'"${BROKEN:0:12}"'" in [k["commit"] for k in d["kept"]]')" True
check "broken: previous is still the base (a reverted try is not previous)" "$(dz '{"cmd":"deploy_status"}' | j 'd["previous"]["commit"]')" "${BASE:0:12}"

echo "== rollback"
out=$(wait_job "$(start '{"cmd":"deploy_rollback","actor":"mcp"}')")
check "rollback: installed" "$(outcome "$out") $(echo "$out" | j 'd["job"]["build"]')" "installed None"
check "rollback: the base is installed" "$(installed)" "${BASE:0:12}"
out=$(wait_job "$(start "{\"cmd\":\"deploy_rollback\",\"to\":\"${GOOD:0:9}\",\"actor\":\"mcp\"}")")
check "rollback to a kept commit: installed" "$(outcome "$out")" installed
check "rollback to a kept commit: good again" "$(installed)" "${GOOD:0:12}"

echo "== one job at a time"
mark good2
GOOD2=$(commit main good2)
id=$(start '{"cmd":"deploy","ref":"main","actor":"mcp"}')
jobs=$(sudo ls /var/lib/ztgate-deploy/jobs | wc -l)
out=$(dz '{"cmd":"deploy","ref":"main","actor":"mcp"}')
check "same target again: the running job, already_running" "$(echo "$out" | j 'd["job"]["id"], d["already_running"]')" "$id True"
out=$(dz '{"cmd":"deploy","ref":"wip/broken","actor":"mcp"}')
check "another target: refused" "$(echo "$out" | j 'd["ok"], "another deploy job is running" in d["error"]')" "False True"
check "neither wrote a job" "$(sudo ls /var/lib/ztgate-deploy/jobs | wc -l)" "$jobs"
out=$(wait_job "$id")
check "the job finished: installed" "$(outcome "$out") $(installed)" "installed ${GOOD2:0:12}"

echo "== refs outside deploy.conf"
rgit checkout -q -b evil
echo evil | sudo tee "$T/work/EVIL" > /dev/null
EVIL=$(commit evil evil)
rgit checkout -q main
out=$(dz '{"cmd":"deploy","ref":"evil","actor":"mcp"}')
check "a branch not in BRANCHES: refused at once" "$(echo "$out" | j 'd["ok"], "not an allowed branch or tag" in d["error"]')" "False True"
out=$(wait_job "$(start "{\"cmd\":\"deploy\",\"ref\":\"$EVIL\",\"actor\":\"mcp\"}")")
check "its commit id: failed, not reachable from an allowed ref" "$(outcome "$out") $(echo "$out" | j '"not reachable" in d["job"]["error"] or "no commit" in d["job"]["error"]')" "failed True"
check "nothing changed" "$(installed)" "${GOOD2:0:12}"

echo "== interrupted"
mark good3
GOOD3=$(commit main good3)
id=$(start '{"cmd":"deploy","ref":"main","actor":"mcp"}')
for _ in $(seq 1200); do
	systemctl is-active --quiet ztgate-deploy-build.service && break
	sleep 0.2
done
sudo systemctl kill -s KILL ztgate-deploy.service
sleep 2
out=$(dz "{\"cmd\":\"deploy_status\",\"job\":\"$id\"}")
check "killed while building: interrupted, at building" "$(echo "$out" | j 'd["job"]["outcome"], d["job"]["phase"]')" "interrupted building"
check "the build unit went with it (BindsTo)" "$(systemctl is-active ztgate-deploy-build.service)" inactive
check "nothing changed" "$(installed) $(systemctl is-active ztgate)" "${GOOD2:0:12} active"
out=$(wait_job "$(start '{"cmd":"deploy","ref":"main","actor":"mcp"}')")
check "the next deploy builds and installs" "$(outcome "$out") $(installed)" "installed ${GOOD3:0:12}"

echo "== audit log"
# /var/log/ztgate 는 서버가 처음 뜰 때 생긴다 (ztgate setup). 그 뒤의 요청 12 개와, 끝을 적은 작업 8 개.
check "admin lines for the requests" "$(sudo grep -c '"event":"admin".*"cmd":"deploy' /var/log/ztgate/audit.log)" 12
check "deploy lines for the ends" "$(sudo grep -c '"event":"deploy"' /var/log/ztgate/audit.log)" 8
check "the reverted one says so" "$(sudo grep '"event":"deploy"' /var/log/ztgate/audit.log | grep -c "\"outcome\":\"reverted\",\"from\":\"${GOOD:0:12}\",\"to\":\"${BROKEN:0:12}\"")" 1

echo "== MCP server over stdio"
out=$({ printf '%s\n' \
	'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deploy_check","version":"0"}}}' \
	'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deploy_status","arguments":{}}}'; sleep 8; } |
	timeout 60 /usr/local/bin/ztgate_mcp | grep '"id":2')
check "deploy_status over MCP: the installed commit" "$(echo "$out" | j 'json.loads(d["result"]["content"][0]["text"])["installed"]["commit"]')" "${GOOD3:0:12}"
echo "$out" | j 'json.loads(d["result"]["content"][0]["text"])["job"]["build"]' | sed 's/^/      last build: /'

[ "$failed" -eq 0 ] || on_fail
echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
