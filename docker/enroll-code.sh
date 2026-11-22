#!/bin/sh
# 등록 코드를 만들어 서버의 등록 대기 목록에 한 줄 쓰고, 돌고 있는 서버에 SIGHUP 을 보낸다.
#
#   enroll-code.sh <tunnel-ip> [requirement ...] [-l label] [-t ttl-minutes]
#   예) enroll-code.sh 10.0.0.2 firewall=on -l laptop
#
# 출력은 코드 한 줄(7K2QF-9XWM4-...)이다. 그 코드를 기기에서 `vpn_client enroll` 에 적는다.
#
# MCP 의 enroll_create (mcp/ctl.cjs) 와 같은 일을 셸과 openssl 만으로 한다 — 컨테이너에
# Node 를 넣지 않으려는 것이다. 코드에서 임시 신원을 뽑는 방법은 secure.h 의
# secure_enroll_identity 와 같아야 한다:
#
#   id  = HMAC-SHA256(key = "ztgate enroll id",  msg = 코드) 의 앞 16B
#   key = HMAC-SHA256(key = "ztgate enroll key", msg = 코드)
#
# 대기 목록의 한 줄: id  key  tunnel-ip  expires(unix)  [requirement ...]  # label

set -eu

ENROLL=${ENROLL_FILE:-/etc/ztgate/enroll.conf}
# 0-9 와 헷갈리는 글자(I L O U)를 뺀 대문자 32개 (proto.h 의 ENROLL_CODE_LEN 과 함께)
ALPHABET=0123456789ABCDEFGHJKMNPQRSTVWXYZ
CODE_LEN=25
TTL_MIN=15

usage() { echo "usage: $0 <tunnel-ip> [requirement ...] [-l label] [-t ttl-minutes]" >&2; exit 1; }

[ $# -ge 1 ] || usage
TUN_IP=$1
shift
REQS=
LABEL=
while [ $# -gt 0 ]; do
	case "$1" in
		-l) [ $# -ge 2 ] || usage; LABEL=$2; shift 2 ;;
		-t) [ $# -ge 2 ] || usage; TTL_MIN=$2; shift 2 ;;
		*)  REQS="$REQS $1"; shift ;;
	esac
done

# 바이트 하나의 하위 5비트로 글자 하나. 256 이 32 로 나누어떨어져 치우침이 없다.
CODE=
for b in $(od -An -tu1 -N"$CODE_LEN" /dev/urandom); do
	i=$((b % 32))
	CODE="$CODE$(printf '%s' "$ALPHABET" | cut -c$((i + 1)))"
done

hmac() {	# hmac <key> -> 코드에 대한 HMAC-SHA256 (hex)
	printf '%s' "$CODE" | openssl dgst -sha256 -mac HMAC -macopt "key:$1" | awk '{ print $NF }'
}

ID=$(hmac "ztgate enroll id" | cut -c1-32)
KEY=$(hmac "ztgate enroll key")
EXPIRES=$(( $(date +%s) + TTL_MIN * 60 ))

# 서버도 이 파일을 고친다 (쓰인 줄을 지운다). 서버처럼 옆에 새 파일을 쓰고 이름을 바꿔
# 반쯤 쓰인 파일이 보이지 않게 한다. 읽고 바꾸는 사이에 서버가 끼면 서버가 지운 줄이 되살아나므로
# 서버와 ztgate_ctl 이 잡는 잠금(같은 디렉터리의 .ztgate.lock, server/src/enroll.c)을 잡고 한다.
umask 077
tmp="$ENROLL.tmp.$$"
exec 9>> "$(dirname "$ENROLL")/.ztgate.lock"
flock -x -w 5 9 || { echo "$0: the enroll list is being changed by the server; try again" >&2; exit 1; }
{ [ -f "$ENROLL" ] && cat "$ENROLL"; printf '%s %s %s %s%s  # %s\n' "$ID" "$KEY" "$TUN_IP" "$EXPIRES" "$REQS" "$LABEL"; } > "$tmp"
mv "$tmp" "$ENROLL"
exec 9>&-

pkill -HUP -x vpn_server 2>/dev/null || true

printf '%s\n' "$CODE" | sed -E 's/(.{5})/\1-/g; s/-$//'
