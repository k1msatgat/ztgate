#!/usr/bin/env bash
# 서버 패키지와 앱 커넥터 패키지를 만든다.
#
#   packaging/build.sh deb [out-dir]      dpkg-deb 로 ztgate-server_<ver>_<arch>.deb
#   packaging/build.sh rpm [out-dir]      rpmbuild 로 ztgate-server-<ver>-<release>.<arch>.rpm (정식 판은 release 1)
#   packaging/build.sh connector-deb|connector-rpm [out-dir]
#                                         ztgate-connector (먼저 make client). 의존은 libssl, nftables
#
# 먼저 make server 로 빌드해 둔다. 버전은 CHANGELOG 와 같게 VERSION 으로 준다 (기본 0.9.2).
# 의존: libssl (OpenSSL 3 의 libcrypto), iproute2(ip), nftables(서버 뒤로 내보낼 때), python3(도구).
# node 는 ztgate_ctl 에만 필요해 권장으로 둔다.
#
# SNAPSHOT=<UTC yyyymmddHHMMSS>.g<커밋 앞 12자> 를 주면 커밋마다 다른 판이 된다 (MCP 배포기 ztgate-deploy 가
# 커밋 시각과 id 로 준다). rpm 은 Release 0.<SNAPSHOT>, deb 는 Version <ver>~<SNAPSHOT>. 둘 다 같은 VERSION 의
# 정식 판보다 앞으로 정렬되므로 나중에 정식 판을 깔면 올리기가 된다. 비우면 지금까지의 정식 판 그대로다.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KIND=${1:?usage: build.sh deb|rpm|connector-deb|connector-rpm [out-dir]}
OUT=${2:-$ROOT/packaging/out}
VERSION=${VERSION:-$(tr -d '[:space:]' < "$ROOT/VERSION")}
SNAPSHOT=${SNAPSHOT:-}
if [ -z "$SNAPSHOT" ]; then
	RELEASE=1
	DEB_VERSION=$VERSION
elif [[ "$SNAPSHOT" =~ ^[0-9]{14}\.g[0-9a-f]{12}$ ]]; then
	RELEASE=0.$SNAPSHOT
	DEB_VERSION=$VERSION~$SNAPSHOT
else
	echo "SNAPSHOT must be <yyyymmddHHMMSS>.g<12 hex> (got '$SNAPSHOT')" >&2
	exit 1
fi
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
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: ztgate <noreply@example.invalid>
Depends: libssl3 | libssl3t64, iproute2, python3
Recommends: nftables, nodejs, rsync
Section: net
Priority: optional
Description: ztgate ZTNA server
 Device-authenticated, posture-checked tunnel server with per-destination ACL,
 user login (OIDC tokens), app connectors and an audit log.
EOF
	printf '#!/bin/sh\nset -e\n/opt/ztgate/libexec/postinst.sh\n' > "$S/DEBIAN/postinst"
	# 지울 때 서비스를 멈춘다. /etc/ztgate 는 남긴다 (purge 에서도 — 기기 키를 실수로 잃지 않게).
	printf '#!/bin/sh\nset -e\nif [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then\n\tsystemctl disable --now ztgate.service ztgate-exporter.service ztgate-console.service ztgate-jwks.timer ztgate-backup.timer ztgate-sync.path ztgate-sync.timer 2>/dev/null || true\nfi\n' > "$S/DEBIAN/prerm"
	chmod 755 "$S/DEBIAN/postinst" "$S/DEBIAN/prerm"
	echo /etc/logrotate.d/ztgate > "$S/DEBIAN/conffiles"
	dpkg-deb --root-owner-group --build "$S" "$OUT/ztgate-server_${DEB_VERSION}_${ARCH}.deb"
	;;
rpm)
	S="$WORK/stage"
	"$ROOT/packaging/stage.sh" "$S"
	install -d "$WORK/rpm/SPECS"
	sed -e "s|@VERSION@|$VERSION|" -e "s|@RELEASE@|$RELEASE|" -e "s|@STAGE@|$S|" "$ROOT/packaging/ztgate-server.spec" > "$WORK/rpm/SPECS/ztgate-server.spec"
	rpmbuild --define "_topdir $WORK/rpm" -bb "$WORK/rpm/SPECS/ztgate-server.spec"
	find "$WORK/rpm/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
	;;
connector-deb)
	ARCH=$(dpkg --print-architecture)
	S="$WORK/ztgate-connector"
	"$ROOT/packaging/connector-stage.sh" "$S"
	install -d "$S/DEBIAN"
	cat > "$S/DEBIAN/control" <<EOF
Package: ztgate-connector
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: ztgate <noreply@example.invalid>
Depends: libssl3 | libssl3t64, nftables
Section: net
Priority: optional
Description: ztgate app connector
 Runs inside a protected network and opens an outbound session to the ztgate
 server, which relays traffic for that network to it. No inbound port is opened.
EOF
	printf '#!/bin/sh\nset -e\n/opt/ztgate-connector/libexec/postinst.sh\n' > "$S/DEBIAN/postinst"
	# 지울 때 서비스를 멈춘다. 신원과 connector.env 는 남긴다 (purge 에서도).
	printf '#!/bin/sh\nset -e\nif [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then\n\tsystemctl disable --now ztgate-connector.service 2>/dev/null || true\nfi\n' > "$S/DEBIAN/prerm"
	chmod 755 "$S/DEBIAN/postinst" "$S/DEBIAN/prerm"
	dpkg-deb --root-owner-group --build "$S" "$OUT/ztgate-connector_${DEB_VERSION}_${ARCH}.deb"
	;;
connector-rpm)
	S="$WORK/stage"
	"$ROOT/packaging/connector-stage.sh" "$S"
	install -d "$WORK/rpm/SPECS"
	sed -e "s|@VERSION@|$VERSION|" -e "s|@RELEASE@|$RELEASE|" -e "s|@STAGE@|$S|" "$ROOT/packaging/ztgate-connector.spec" > "$WORK/rpm/SPECS/ztgate-connector.spec"
	rpmbuild --define "_topdir $WORK/rpm" -bb "$WORK/rpm/SPECS/ztgate-connector.spec"
	find "$WORK/rpm/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
	;;
*)
	echo "usage: build.sh deb|rpm|connector-deb|connector-rpm [out-dir]" >&2
	exit 1
	;;
esac

ls -l "$OUT"
