#!/usr/bin/env bash
# 커넥터 패키지(ztgate-connector, DEB / RPM)에 들어갈 파일을 <stage> 아래에 실제 경로대로 놓는다.
#
#   packaging/connector-stage.sh <stage>        먼저 make client 로 빌드해 둔다
#
# 들어가는 것
#   /opt/ztgate-connector/bin/vpn_client                   Linux 클라이언트. 커넥터로만 쓴다
#   /opt/ztgate-connector/libexec/postinst.sh              설치 뒤 한 번: 폴더와 서비스 다시 읽기
#   /usr/sbin/ztgate-connector                             등록, 상태, 등록 해제, 서비스가 부르는 run
#   /usr/lib/systemd/system/ztgate-connector.service
#   /usr/share/doc/ztgate-connector/                       라이선스(copyright)와 서드파티 고지
#
# 넣지 않는 것: /etc/ztgate-connector/connector.env 와 /var/lib/ztgate-connector/device. 등록이
# 만드는 것이라 제거하거나 업그레이드해도 남는다 (다시 등록할 코드를 받지 않아도 된다).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${1:?usage: connector-stage.sh <stage-dir>}

[ -x "$ROOT/client/bin/vpn_client" ] || { echo "build first: make client" >&2; exit 1; }

install -d "$S/opt/ztgate-connector/bin" "$S/opt/ztgate-connector/libexec" "$S/usr/sbin" \
	"$S/usr/lib/systemd/system" "$S/usr/share/doc/ztgate-connector"
# 디버그 정보는 떼고 넣는다 (-s). 빌드 트리의 실행 파일에는 남아 있다.
install -m 755 -s "$ROOT/client/bin/vpn_client" "$S/opt/ztgate-connector/bin/vpn_client"
install -m 755 "$ROOT/packaging/connector-postinst.sh" "$S/opt/ztgate-connector/libexec/postinst.sh"
install -m 755 "$ROOT/tools/connector/ztgate-connector" "$S/usr/sbin/ztgate-connector"
install -m 644 "$ROOT/tools/connector/ztgate-connector.service" "$S/usr/lib/systemd/system/ztgate-connector.service"
install -m 644 "$ROOT/LICENSE" "$S/usr/share/doc/ztgate-connector/copyright"
install -m 644 "$ROOT/THIRD_PARTY_NOTICES.md" "$S/usr/share/doc/ztgate-connector/THIRD_PARTY_NOTICES.md"
