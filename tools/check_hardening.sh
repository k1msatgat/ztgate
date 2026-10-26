#!/usr/bin/env bash
# 실행 파일이 하드닝 플래그(Makefile 의 HARDEN)로 빌드됐는지 본다. 하나라도 빠지면 실패.
#
#   tools/check_hardening.sh server/bin/vpn_server client/bin/vpn_client
#
# PIE, 전체 RELRO(BIND_NOW), 실행할 수 없는 스택, 스택 카나리, _FORTIFY_SOURCE 의 검사 함수.
set -u

fail=0
for bin in "$@"; do
	[ -f "$bin" ] || { echo "missing: $bin"; fail=1; continue; }
	hdr=$(readelf -hW "$bin")
	seg=$(readelf -lW "$bin")
	dyn=$(readelf -dW "$bin")
	syms=$(readelf -sW --dyn-syms "$bin")

	check() {
		if [ "$2" = 1 ]; then
			printf 'ok    %-28s %s\n' "$bin" "$1"
		else
			printf 'FAIL  %-28s %s\n' "$bin" "$1"
			fail=1
		fi
	}
	check "PIE" "$(grep -q 'Type:[[:space:]]*DYN' <<<"$hdr" && echo 1)"
	check "RELRO" "$(grep -q 'GNU_RELRO' <<<"$seg" && echo 1)"
	check "BIND_NOW" "$(grep -Eq 'BIND_NOW|FLAGS.*NOW' <<<"$dyn" && echo 1)"
	check "non-executable stack" "$(grep 'GNU_STACK' <<<"$seg" | grep -qv 'RWE' && echo 1)"
	check "stack protector" "$(grep -q '__stack_chk_fail' <<<"$syms" && echo 1)"
	check "FORTIFY_SOURCE" "$(grep -Eq '__[a-z_]+_chk(@|$| )' <<<"$syms" && echo 1)"
done
exit $fail
