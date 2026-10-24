#!/usr/bin/env python3
"""ztgate 서버의 상태를 Prometheus 지표로 내준다.

    sudo tools/metrics/ztgate_exporter.py [-s /run/ztgate/status.sock] [-l 127.0.0.1:9469] [--per-session]

서버의 상태 소켓(읽기 전용, JSON 한 덩어리)을 요청마다 읽어 텍스트 형식(exposition format
0.0.4)으로 바꾼다. 서버 안에 HTTP 를 넣지 않는다 — 서버는 터널을 나르는 단일 스레드 루프라
느린 수집기가 붙어도 기다리지 않아야 하고, 그 일은 상태 소켓이 이미 한다(크기 제한 없이, 루프를
막지 않고). 이 도구가 죽어도 터널은 그대로다.

상태 소켓은 root 전용(600)이라 root 로 돌린다. 기본으로 127.0.0.1 에만 듣는다. 지표에는 기기
ID 와 터널 주소, 사용자 이름이 들어갈 수 있다(--per-session) — 밖으로 열려면 앞에 인증하는
프록시를 둔다.

표준 라이브러리만 쓴다. 서버가 도는 장비에 따로 설치할 것이 없다.
"""

import argparse
import http.server
import json
import socket
import sys

# 상태 소켓의 counters 와 그 뜻. 모두 서버가 뜬 뒤로 늘기만 하는 수다.
COUNTERS = {
    "handshake_ok": "sessions opened",
    "deny_unknown_device": "handshakes refused: device not registered",
    "deny_bad_auth": "handshakes refused: wrong key or stale nonce",
    "deny_tun_ip": "handshakes refused: tunnel address (protocol 3 and older)",
    "deny_posture": "handshakes and sessions refused: posture below policy",
    "keepalive_dropped": "keepalives dropped (short or out of order)",
    "bad_tag": "session packets whose tag did not verify (forged, corrupt, another session)",
    "replayed": "session packets with a counter already seen",
    "unknown_session": "packets for a session number the server does not have",
    "spoofed_src": "tunnel packets whose inner source was not the session's address",
    "acl_denied": "tunnel packets denied by the ACL",
    "acl_denied_posture": "tunnel packets denied because a rule's posture was not met",
    "acl_denied_user": "tunnel packets denied because a rule was for other users",
    "login_ok": "user tokens accepted",
    "login_failed": "user tokens rejected",
    "connector_offline": "packets for a connector network while its connector was not connected",
    "connector_dropped": "packets from a connector to a client with no session",
    "flow_dropped": "packets toward a client that were not replies to a flow it opened (-F)",
}


def read_status(path, timeout=3.0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return json.loads(buf.decode())


def label(v):
    """라벨 값의 이스케이프 (역슬래시, 따옴표, 줄바꿈). 상태의 값은 정해진 글자뿐이지만 기대지 않는다."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(st, per_session):
    out = []

    def metric(name, kind, help_text, samples):
        out.append("# HELP %s %s" % (name, help_text))
        out.append("# TYPE %s %s" % (name, kind))
        for labels, value in samples:
            if labels:
                text = ",".join('%s="%s"' % (k, label(v)) for k, v in labels)
                out.append("%s{%s} %s" % (name, text, value))
            else:
                out.append("%s %s" % (name, value))

    sessions = [s for s in st.get("sessions", [])]
    metric("ztgate_up", "gauge", "1 if the server's status socket answered", [((), 1)])
    metric("ztgate_uptime_seconds", "gauge", "seconds since the server started", [((), st.get("uptime_sec", 0))])
    metric("ztgate_devices", "gauge", "devices in the device list", [((), st.get("devices", 0))])
    metric("ztgate_acl_rules", "gauge", "rules in the ACL (0 when the ACL is off)",
           [((), st.get("acl", {}).get("rules", 0) if st.get("acl", {}).get("enabled") else 0)])
    metric("ztgate_sessions", "gauge", "open device sessions", [((), len(sessions))])
    metric("ztgate_flows", "gauge", "open flows in the stateful table (0 when -F is off)",
           [((), st.get("flows", {}).get("open", 0))])
    metric("ztgate_sessions_logged_in", "gauge", "open sessions with a logged-in user",
           [((), sum(1 for s in sessions if s.get("user")))])

    counters = st.get("counters", {})
    for key, help_text in COUNTERS.items():
        if key in counters:
            metric("ztgate_%s_total" % key, "counter", help_text, [((), counters[key])])

    # 세션 전체의 합. 세션이 닫히면 그 몫이 빠지므로 counter 가 아니라 gauge 다.
    for key, help_text in (("rx_bytes", "bytes received from open sessions (client to server, after the ACL)"),
                           ("tx_bytes", "bytes sent to open sessions"),
                           ("rx_packets", "packets received from open sessions"),
                           ("tx_packets", "packets sent to open sessions")):
        metric("ztgate_sessions_%s" % key, "gauge", help_text, [((), sum(s.get(key, 0) for s in sessions))])

    if per_session:
        for key, kind in (("rx_bytes", "gauge"), ("tx_bytes", "gauge"), ("acl_denied", "gauge"), ("age_sec", "gauge")):
            samples = []
            for s in sessions:
                labels = [("device", s.get("device_id", "")), ("tunnel_ip", s.get("tunnel_ip", ""))]
                if s.get("user"):
                    labels.append(("user", s["user"].get("name", "")))
                samples.append((tuple(labels), s.get(key, 0)))
            metric("ztgate_session_%s" % key, kind, "per open session: %s" % key, samples)

    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-s", "--status", default="/run/ztgate/status.sock", help="server status socket")
    ap.add_argument("-l", "--listen", default="127.0.0.1:9469", help="address:port to serve /metrics on")
    ap.add_argument("--per-session", action="store_true",
                    help="also export one series per open session (device id, tunnel ip, user)")
    a = ap.parse_args()

    host, _, port = a.listen.rpartition(":")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            try:
                body = render(read_status(a.status), a.per_session)
                code = 200
            except (OSError, ValueError) as e:
                # 서버가 내려가 있다. 수집기가 그것을 알 수 있게 up 0 을 준다.
                body = "# status socket: %s\n# TYPE ztgate_up gauge\nztgate_up 0\n" % label(e)
                code = 200
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            pass

    srv = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    print("serving http://%s:%s/metrics from %s" % (host, port, a.status), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
