#!/usr/bin/env bash
# 서버 패키지를 만든다.
#
#   packaging/build.sh deb [out-dir]      dpkg-deb 로 ztgate-server_<ver>_<arch>.deb
#   packaging/build.sh rpm [out-dir]      rpmbuild 로 ztgate-server-<ver>-1.<arch>.rpm
#
# 먼저 make server 로 빌드해 둔다. 버전은 CHANGELOG 와 같게 VERSION 으로 준다 (기본 0.9.2).
# 의존: libssl (OpenSSL 3 의 libcrypto), iproute2(ip), nftables(서버 뒤로 내보낼 때), python3(도구).
# node 는 ztgate_ctl 에만 필요해 권장으로 둔다.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KIND=${1:?usage: build.sh deb|rpm [out-dir]}
OUT=${2:-$ROOT/packaging/out}
VERSION=${VERSION:-0.9.2}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

case "$KIND" in
deb)
	ARCH=$(dpkg --print-architecture)
	S="$WORK/ztgate-server"
	"$ROOT/packaging/stage.sh" "$S"
	install -d "$S/DEBIAN"
	cat > "$S/DEBIAN/control" <<EOF
Package: ztgate-server
Version: $VERSION
Architecture: $ARCH
Maintainer: ztgate <noreply@example.invalid>
Depends: libssl3 | libssl3t64, iproute2, python3
Recommends: nftables, nodejs
Section: net
Priority: optional
Description: ztgate ZTNA server
 Device-authenticated, posture-checked tunnel server with per-destination ACL,
 user login (OIDC tokens), app connectors and an audit log.
EOF
	printf '#!/bin/sh\nset -e\n/opt/ztgate/libexec/postinst.sh\n' > "$S/DEBIAN/postinst"
	# 지울 때 서비스를 멈춘다. /etc/ztgate 는 남긴다 (purge 에서도 — 기기 키를 실수로 잃지 않게).
	printf '#!/bin/sh\nset -e\nif [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then\n\tsystemctl disable --now ztgate.service ztgate-exporter.service ztgate-console.service ztgate-jwks.timer ztgate-backup.timer 2>/dev/null || true\nfi\n' > "$S/DEBIAN/prerm"
	chmod 755 "$S/DEBIAN/postinst" "$S/DEBIAN/prerm"
	echo /etc/logrotate.d/ztgate > "$S/DEBIAN/conffiles"
	dpkg-deb --root-owner-group --build "$S" "$OUT/ztgate-server_${VERSION}_${ARCH}.deb"
	;;
rpm)
	S="$WORK/stage"
	"$ROOT/packaging/stage.sh" "$S"
	install -d "$WORK/rpm/SPECS"
	sed -e "s|@VERSION@|$VERSION|" -e "s|@STAGE@|$S|" "$ROOT/packaging/ztgate-server.spec" > "$WORK/rpm/SPECS/ztgate-server.spec"
	rpmbuild --define "_topdir $WORK/rpm" -bb "$WORK/rpm/SPECS/ztgate-server.spec"
	find "$WORK/rpm/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
	;;
*)
	echo "usage: build.sh deb|rpm [out-dir]" >&2
	exit 1
	;;
esac

ls -l "$OUT"
