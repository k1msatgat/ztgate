#!/usr/bin/env bash
# 버전은 저장소 맨 위의 VERSION 하나에서 온다. packaging/build.sh 와 windows/installer/build.ps1 은 그것을
# 읽고, 파일을 읽을 수 없는 곳(Windows 리소스, WiX 의 기본값)은 이 검사가 같은 값인지 본다.
#
#   tools/check_version.sh
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
v=$(tr -d '[:space:]' < "$ROOT/VERSION")
IFS=. read -r major minor patch <<<"$v"
fail=0
want() {
	if grep -qF -- "$2" "$ROOT/$1"; then
		printf 'ok    %-34s %s\n' "$1" "$2"
	else
		printf 'FAIL  %-34s wants %s\n' "$1" "$2"
		fail=1
	fi
}
want windows/version.rc "ZTGATE_VERSION_NUM	$major,$minor,$patch,0"
want windows/version.rc "ZTGATE_VERSION_STR	\"$v.0\""
want windows/installer/ztgate.wxs "<?define Version = \"$v\"?>"
exit $fail
