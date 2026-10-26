#!/usr/bin/env bash
# 서버 패키지(DEB / RPM)에 들어갈 파일을 <stage> 아래에 실제 경로대로 놓는다. 둘이 같은 배치를 쓴다.
#
#   packaging/stage.sh <stage>        먼저 make server 로 빌드해 둔다
#
# 들어가는 것
#   /opt/ztgate/server/bin/vpn_server
#   /opt/ztgate/libexec/service.sh               systemd 가 부른다 (mcp/service.sh)
#   /opt/ztgate/libexec/postinst.sh              설치 뒤 한 번: /etc/ztgate 와 서버 키
#   /opt/ztgate/tools/ztgate_exporter.py         Prometheus 지표
#   /opt/ztgate/tools/ztgate_jwks.py             JWKS 갱신
#   /opt/ztgate/tools/ztgate_console.py          웹 관리 콘솔
#   /opt/ztgate/test/auth_check.py               ztgate_ctl 의 자체 시험이 돌린다
#   /usr/sbin/ztgate_ctl                         관리 헬퍼 (node 가 있어야 돈다)
#   /usr/bin/ztgate                              운영자가 터미널에서 읽는 상태 (ztgate status 등)
#   /usr/lib/systemd/system/ztgate.service, ztgate-exporter.service, ztgate-console.service, ztgate-jwks.{service,timer}
#
# 넣지 않는 것: MCP 서버(npm 의존성이 있다 — mcp/install.sh), /etc/ztgate 의 설정. 설정은 패키지의
# 파일이 아니라서 제거하거나 업그레이드해도 남는다 (기기 목록과 서버 키를 잃지 않는다).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${1:?usage: stage.sh <stage-dir>}

[ -x "$ROOT/server/bin/vpn_server" ] || { echo "build first: make server" >&2; exit 1; }

install -d "$S/opt/ztgate/server/bin" "$S/opt/ztgate/libexec" "$S/opt/ztgate/tools" "$S/opt/ztgate/test" \
	"$S/usr/sbin" "$S/usr/bin" "$S/usr/lib/systemd/system"
install -m 755 "$ROOT/server/bin/vpn_server" "$S/opt/ztgate/server/bin/vpn_server"
install -m 755 "$ROOT/mcp/service.sh" "$S/opt/ztgate/libexec/service.sh"
install -m 755 "$ROOT/packaging/postinst.sh" "$S/opt/ztgate/libexec/postinst.sh"
install -m 755 "$ROOT/tools/metrics/ztgate_exporter.py" "$S/opt/ztgate/tools/ztgate_exporter.py"
install -m 755 "$ROOT/tools/idp/ztgate_jwks.py" "$S/opt/ztgate/tools/ztgate_jwks.py"
install -m 755 "$ROOT/tools/console/ztgate_console.py" "$S/opt/ztgate/tools/ztgate_console.py"
install -m 644 "$ROOT/test/auth_check.py" "$S/opt/ztgate/test/auth_check.py"
install -m 755 "$ROOT/mcp/ctl.cjs" "$S/usr/sbin/ztgate_ctl"
install -m 755 "$ROOT/tools/cli/ztgate" "$S/usr/bin/ztgate"
install -m 644 "$ROOT/mcp/ztgate.service" "$S/usr/lib/systemd/system/ztgate.service"
install -m 644 "$ROOT/tools/metrics/ztgate-exporter.service" "$S/usr/lib/systemd/system/ztgate-exporter.service"
install -m 644 "$ROOT/tools/console/ztgate-console.service" "$S/usr/lib/systemd/system/ztgate-console.service"
install -m 644 "$ROOT/tools/idp/ztgate-jwks.service" "$ROOT/tools/idp/ztgate-jwks.timer" "$S/usr/lib/systemd/system/"
