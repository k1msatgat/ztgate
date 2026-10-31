#!/usr/bin/env bash
# tools/connector/ztgate-connector 시험. root 도 서버도 없이, vpn_client / systemctl / getent 를 가짜로 둔다.
#
#   test/connector_check.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZC="$ROOT/tools/connector/ztgate-connector"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

failed=0
check() {
	if [ "$2" = "$3" ]; then
		printf 'ok    %-58s %s\n' "$1" "$2"
	else
		printf 'FAIL  %-58s %s   (want %s)\n' "$1" "$2" "$3"
		failed=$((failed + 1))
	fi
}

mkdir -p "$W/bin" "$W/sys/eth1" "$W/systemd"
export ZTGATE_CONNECTOR_ETC="$W/etc" ZTGATE_CONNECTOR_STATE="$W/state" ZTGATE_CONNECTOR_CLIENT="$W/bin/vpn_client"
export ZTGATE_CONNECTOR_SYSFS="$W/sys" ZTGATE_CONNECTOR_SYSTEMD="$W/systemd" ZTGATE_CONNECTOR_NOROOT=1
export PATH="$W/bin:$PATH" LOG="$W/log"

# 등록은 -k 의 파일을 쓴다. FAIL_ADDR 로 온 등록은 서버가 답하지 않은 것처럼 끝난다.
cat > "$W/bin/vpn_client" <<'EOF'
#!/bin/bash
echo "vpn_client $*" >> "$LOG"
while getopts "k:i:T:" o; do [ "$o" = k ] && k=$OPTARG; done
shift $((OPTIND - 1))
if [ "$1" = enroll ]; then
	[ "$2" = "${FAIL_ADDR:-}" ] && exit 1
	printf '%032x %064x\n' 1 2 > "$k"
	chmod 600 "$k"
fi
EOF
printf '#!/bin/sh\necho "systemctl $*" >> "$LOG"\n[ "$1" = is-active ] && echo active\n[ "$1" = is-enabled ] && echo enabled\nexit 0\n' > "$W/bin/systemctl"
printf '#!/bin/sh\necho "-- journal of $2 --"\n' > "$W/bin/journalctl"
cat > "$W/bin/getent" <<'EOF'
#!/bin/sh
case "$1 $2" in
	"ahostsv4 vpn1.example.com") echo "203.0.113.5     STREAM vpn1.example.com" ;;
	"ahostsv6 v6only.example.com") echo "2001:db8::5     STREAM v6only.example.com" ;;
	*) exit 2 ;;
esac
EOF
chmod +x "$W/bin/"*

zc() { "$ZC" "$@" > "$W/out" 2>&1; echo $?; }
log() { tr '\n' '|' < "$LOG"; }
env_of() { grep -v '^#' "$W/etc/connector.env" | tr '\n' ' '; }
fresh() { rm -rf "$W/etc" "$W/state"; : > "$LOG"; }
CODE=7K2QF-9XWM4-ABCDE-FGHJK-MNPQR

fresh
check "no --lan-if: refused" "$(zc enroll vpn1.example.com 9000 "$CODE")" 1
check "bad port: refused" "$(zc enroll vpn1.example.com 70000 "$CODE" --lan-if eth1)" 1
check "code with a space: refused" "$(zc enroll vpn1.example.com 9000 "AB CD" --lan-if eth1)" 1
check "bad server characters: refused" "$(zc enroll 'vpn!.example.com' 9000 "$CODE" --lan-if eth1)" 1
check "five servers: refused" "$(zc enroll a,b,c,d,e 9000 "$CODE" --lan-if eth1)" 1
check "interface name with a slash: refused" "$(zc enroll vpn1.example.com 9000 "$CODE" --lan-if ../x)" 1
check "interface that does not exist: refused" "$(zc enroll vpn1.example.com 9000 "$CODE" --lan-if eth9)" 1
check "...and nothing was run or written" "$(log)$([ -e "$W/etc/connector.env" ] && echo env)" ""
if [ "$(id -u)" -ne 0 ]; then
	check "not root: refused" "$(ZTGATE_CONNECTOR_NOROOT= zc enroll vpn1.example.com 9000 "$CODE" --lan-if eth1)$(log)" 1
fi

fresh
check "enroll: exit" "$(zc enroll vpn1.example.com 9000 "$CODE" --lan-if eth1)" 0
check "enroll: the name is resolved for vpn_client" "$(head -n 1 "$LOG")" "vpn_client -k $W/state/device enroll 203.0.113.5 9000 $CODE"
check "enroll: connector.env keeps the name" "$(env_of)" "SERVER=vpn1.example.com PORT=9000 LAN_IF=eth1 "
check "enroll: modes (state 700, env 644)" "$(stat -c %a "$W/state") $(stat -c %a "$W/etc/connector.env")" "700 644"
check "enroll: the service is enabled and (re)started" "$(grep systemctl "$LOG" | tr '\n' '|')" "systemctl enable --quiet ztgate-connector.service|systemctl restart ztgate-connector.service|"

: > "$LOG"
cp "$W/etc/connector.env" "$W/env.before"
check "enroll again: refused without --force" "$(zc enroll 10.9.9.9 9000 "$CODE" --lan-if eth1)" 1
check "...vpn_client not run, connector.env unchanged" "$(log)$(cmp -s "$W/env.before" "$W/etc/connector.env" && echo same)" "same"
check "enroll --force --tcp: exit" "$(zc enroll 10.9.9.9 443 "$CODE" --lan-if eth1 --tcp --force)" 0
check "...vpn_client gets -T and -f" "$(head -n 1 "$LOG")" "vpn_client -k $W/state/device -T 443 enroll 10.9.9.9 443 $CODE -f"
check "...connector.env has TCP_PORT" "$(env_of)" "SERVER=10.9.9.9 PORT=443 LAN_IF=eth1 TCP_PORT=443 "

fresh
check "enroll that the server refuses: exit" "$(FAIL_ADDR=203.0.113.5 zc enroll vpn1.example.com 9000 "$CODE" --lan-if eth1)" 1
check "...no connector.env, service untouched" "$([ -e "$W/etc/connector.env" ] && echo env)$(grep -c systemctl "$LOG")" "0"

fresh
INV="ztgate://enroll?server=vpn1.example.com%2C10.0.0.2&port=9000&code=$CODE"
check "invite: exit" "$(zc enroll "$INV" --lan-if eth1)" 0
check "invite: server list and port from the link" "$(env_of)" "SERVER=vpn1.example.com,10.0.0.2 PORT=9000 LAN_IF=eth1 "
fresh
check "invite: first server silent, the second takes the code" "$(FAIL_ADDR=203.0.113.5 zc enroll "$INV" --lan-if eth1)" 0
check "...both were tried in order" "$(grep -o 'enroll [0-9.]*' "$LOG" | tr '\n' '|')" "enroll 203.0.113.5|enroll 10.0.0.2|"
fresh
check "invite: upper case, quoted, unknown key" "$(zc enroll "\"ZTGATE://ENROLL?CODE=$CODE&SERVER=10.0.0.7&PORT=443&v=2\"" --lan-if eth1)" 0
check "...read" "$(env_of)" "SERVER=10.0.0.7 PORT=443 LAN_IF=eth1 "
for bad in "server=a&port=1" "server=a&port=70000&code=x" "server=a%20b&port=1&code=x" "server=a+b&port=1&code=x" \
		"server=a.com%00evil&port=1&code=x" "server=a&port=1&code=AB%0ACD" "server=a&port=1&code=AB%2FCD" "server=a&port=1&code"; do
	fresh
	check "invite rejected: $bad" "$(zc enroll "ztgate://enroll?$bad" --lan-if eth1)$(log)" 1
done
check "invite rejected: another scheme" "$(zc enroll "https://enroll?server=a&port=1&code=x" --lan-if eth1)" 1

fresh
check "run before enrolling: refused" "$(zc run)" 1
zc enroll "vpn1.example.com,10.0.0.2,v6only.example.com,gone.example.com" 9000 "$CODE" --lan-if eth1 > /dev/null
: > "$LOG"
check "run: exit (vpn_client's)" "$(zc run)" 0
check "run: names resolved, the unknown one left out" "$(log)" "vpn_client -k $W/state/device -i ztconn0 connector 203.0.113.5,10.0.0.2,2001:db8::5 9000 eth1|"
check "run: says which name it could not resolve" "$(grep -c gone.example.com "$W/out")" 1
printf 'SERVER=gone.example.com\nPORT=9000\nLAN_IF=eth1\n' > "$W/etc/connector.env"
check "run: no server resolves -> fail (systemd retries)" "$(zc run)" 1
printf 'SERVER=10.0.0.2\nPORT=9000\nLAN_IF=eth1\nTCP_PORT=443\nLAN_IF2=$(touch %s/pwned)\n' "$W" > "$W/etc/connector.env"
: > "$LOG"
zc run > /dev/null
check "run: TCP_PORT -> -T, unknown keys are not run" "$(log)$([ -e "$W/pwned" ] && echo pwned)" "vpn_client -k $W/state/device -i ztconn0 -T 443 connector 10.0.0.2 9000 eth1|"
printf 'SERVER=10.0.0.2\nPORT=9000\nLAN_IF=eth1;reboot\n' > "$W/etc/connector.env"
check "run: a bad LAN_IF in connector.env: refused" "$(zc run)" 1
check "status: says which key is wrong" "$(zc status)$(grep -c 'LAN_IF 가 틀렸습니다' "$W/out")" "01"
printf 'SERVER=[2001:db8::7]\nPORT=9000\nLAN_IF=eth1\n' > "$W/etc/connector.env"
: > "$LOG"
zc run > /dev/null
check "run: a bracketed IPv6 address goes as it is" "$(log)" "vpn_client -k $W/state/device -i ztconn0 connector [2001:db8::7] 9000 eth1|"

check "status: exit" "$(zc status)" 0
check "status: enrolled, device id" "$(grep -c "등록      됨 (기기 id 00000000000000000000000000000001)" "$W/out")" 1
check "status: service state and journal" "$(grep -c -e '서비스    active, enabled' -e 'journal of ztgate-connector.service' "$W/out")" 2

: > "$LOG"
check "unenroll without --yes: refused" "$(zc unenroll)" 1
check "...identity kept" "$([ -e "$W/state/device" ] && echo kept)$(log)" "kept"
check "unenroll --yes: exit" "$(zc unenroll --yes)" 0
check "...service stopped, identity and env gone" "$(log)$(find "$W/state" "$W/etc" -type f)" "systemctl disable --now --quiet ztgate-connector.service|"
check "unenroll again: still fine" "$(zc unenroll --yes)" 0
check "status after unenroll: not enrolled" "$(zc status)$(grep -c '등록      안 됨' "$W/out")" "01"

fresh
rmdir "$W/systemd"
check "no systemd: enroll still works" "$(zc enroll 10.0.0.2 9000 "$CODE" --lan-if eth1)" 0
check "...and says how to run it in the foreground" "$(grep -c 'ztgate-connector run' "$W/out")$(grep -c systemctl "$LOG")" "10"

echo
[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit $((failed > 0))
