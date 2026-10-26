#!/usr/bin/env bash
# 서버 패키지(DEB / RPM)에 들어갈 파일을 <stage> 아래에 실제 경로대로 놓는다. 둘이 같은 배치를 쓴다.
#
#   packaging/stage.sh <stage>        먼저 make server 로 빌드해 둔다
#
# 들어가는 것
#   /opt/ztgate/server/bin/vpn_server
#   /opt/ztgate/libexec/service.sh               systemd 가 부른다 (mcp/service.sh)
#   /opt/ztgate/libexec/postinst.sh              설치 뒤 한 번: /etc/ztgate 와 서버 키
#   /opt/ztgate/libexec/ztgate-user.sh           서버 계정(ztgate)과 파일 소유. 서비스가 뜨고 다시 읽기 전에도 돈다
#   /opt/ztgate/tools/ztgate_exporter.py         Prometheus 지표
#   /opt/ztgate/tools/ztgate_jwks.py             JWKS 갱신
#   /opt/ztgate/tools/ztgate_console.py          웹 관리 콘솔
#   /opt/ztgate/test/auth_check.py               ztgate_ctl 의 자체 시험이 돌린다
#   /usr/sbin/ztgate_ctl                         관리 헬퍼 (node 가 있어야 돈다)
#   /usr/bin/ztgate                              운영자가 터미널에서 읽는 상태 (ztgate status 등)
#   /usr/sbin/ztgate-backup                      설정과 서버 키의 백업 / 되살리기 (+ ztgate-backup.timer, 하루 한 번)
#   /etc/logrotate.d/ztgate                      감사 로그 돌리기
#   /usr/share/doc/ztgate-server/                라이선스(copyright)와 서드파티 고지
#   /usr/lib/systemd/system/ztgate.service, ztgate-exporter.service, ztgate-console.service, ztgate-jwks.{service,timer}
#
# 넣지 않는 것: MCP 서버(npm 의존성이 있다 — mcp/install.sh), /etc/ztgate 의 설정. 설정은 패키지의
# 파일이 아니라서 제거하거나 업그레이드해도 남는다 (기기 목록과 서버 키를 잃지 않는다).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${1:?usage: stage.sh <stage-dir>}

[ -x "$ROOT/server/bin/vpn_server" ] || { echo "build first: make server" >&2; exit 1; }

install -d "$S/opt/ztgate/server/bin" "$S/opt/ztgate/libexec" "$S/opt/ztgate/tools" "$S/opt/ztgate/test" \
	"$S/usr/sbin" "$S/usr/bin" "$S/usr/lib/systemd/system" "$S/etc/logrotate.d" "$S/usr/share/doc/ztgate-server"
# 디버그 정보는 떼고 넣는다 (-s). 빌드 트리의 실행 파일에는 남아 있다.
install -m 755 -s "$ROOT/server/bin/vpn_server" "$S/opt/ztgate/server/bin/vpn_server"
install -m 755 "$ROOT/mcp/service.sh" "$S/opt/ztgate/libexec/service.sh"
install -m 755 "$ROOT/packaging/postinst.sh" "$S/opt/ztgate/libexec/postinst.sh"
install -m 755 "$ROOT/packaging/ztgate-user.sh" "$S/opt/ztgate/libexec/ztgate-user.sh"
install -m 755 "$ROOT/tools/metrics/ztgate_exporter.py" "$S/opt/ztgate/tools/ztgate_exporter.py"
install -m 755 "$ROOT/tools/idp/ztgate_jwks.py" "$S/opt/ztgate/tools/ztgate_jwks.py"
install -m 755 "$ROOT/tools/console/ztgate_console.py" "$S/opt/ztgate/tools/ztgate_console.py"
install -m 644 "$ROOT/test/auth_check.py" "$S/opt/ztgate/test/auth_check.py"
install -m 755 "$ROOT/mcp/ctl.cjs" "$S/usr/sbin/ztgate_ctl"
install -m 755 "$ROOT/tools/cli/ztgate" "$S/usr/bin/ztgate"
install -m 755 "$ROOT/tools/backup/ztgate-backup" "$S/usr/sbin/ztgate-backup"
install -m 644 "$ROOT/tools/backup/ztgate-backup.service" "$ROOT/tools/backup/ztgate-backup.timer" "$S/usr/lib/systemd/system/"
install -m 644 "$ROOT/packaging/ztgate.logrotate" "$S/etc/logrotate.d/ztgate"
install -m 644 "$ROOT/LICENSE" "$S/usr/share/doc/ztgate-server/copyright"
install -m 644 "$ROOT/THIRD_PARTY_NOTICES.md" "$S/usr/share/doc/ztgate-server/THIRD_PARTY_NOTICES.md"
install -m 644 "$ROOT/mcp/ztgate.service" "$S/usr/lib/systemd/system/ztgate.service"
install -m 644 "$ROOT/tools/metrics/ztgate-exporter.service" "$S/usr/lib/systemd/system/ztgate-exporter.service"
install -m 644 "$ROOT/tools/console/ztgate-console.service" "$S/usr/lib/systemd/system/ztgate-console.service"
install -m 644 "$ROOT/tools/idp/ztgate-jwks.service" "$ROOT/tools/idp/ztgate-jwks.timer" "$S/usr/lib/systemd/system/"
