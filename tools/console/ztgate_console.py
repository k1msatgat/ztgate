#!/usr/bin/env python3
"""ztgate 웹 관리 콘솔. 표준 라이브러리만 쓴다.

    ztgate_console.py [-l 127.0.0.1:9470] [--ctl /usr/sbin/ztgate_ctl] [--token-file /etc/ztgate/console.token]
                      [--tls-cert cert.pem --tls-key key.pem]

브라우저로 지금 붙어 있는 세션, 기기 목록, 등록 코드, ACL, 감사 로그를 보고 기기 지우기 / 등록 코드
만들기와 거두기를 한다. 일은 모두 ztgate_ctl(관리 헬퍼, mcp/ctl.cjs)에 넘긴다 — 검증과 파일 잠금,
서버 다시 읽기가 한 곳에 있다. MCP 서버와 같은 길이다.

누가 들어오는가
  - 기본은 127.0.0.1 에서만 듣는다. 밖에서는 SSH 포워딩(ssh -L 9470:127.0.0.1:9470 서버)으로 들어오거나,
    --tls-cert / --tls-key 로 TLS 를 켜고 -l 0.0.0.0:9470 으로 연다.
  - 로그인은 토큰 하나다. 처음 뜰 때 --token-file 에 무작위 값을 만들어 둔다 (600, root 전용).
    관리자는 `sudo cat /etc/ztgate/console.token` 으로 읽는다.
  - 세션 쿠키는 HttpOnly, SameSite=Strict (TLS 면 Secure). 바꾸는 요청(POST)은 세션마다의 CSRF 값이
    맞아야 받는다. 로그인 실패는 1초에 한 번까지만 받는다.

ztgate_ctl 이 root 로만 돌므로 이 콘솔도 root 로 돈다 (tools/console/ztgate-console.service).
"""

import argparse
import hmac
import html
import http.server
import json
import os
import secrets
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

SESSION_TTL = 8 * 3600
CTL_TIMEOUT = 60


class Console:
    def __init__(self, ctl, token, secure):
        self.ctl = ctl
        self.token = token
        self.secure = secure
        self.sessions = {}          # 쿠키 -> (CSRF 값, 만료 시각)
        self.lock = threading.Lock()
        self.last_fail = 0.0

    def call(self, cmd, **args):
        """ztgate_ctl 에 명령 하나. 결과 dict (ok, error ...)."""
        req = dict(args, cmd=cmd)
        try:
            p = subprocess.run([self.ctl], input=json.dumps(req), capture_output=True, text=True,
                               timeout=CTL_TIMEOUT)
            return json.loads(p.stdout.strip().splitlines()[-1])
        except (OSError, ValueError, IndexError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "error": "ztgate_ctl: %s" % type(e).__name__}

    def login(self, given):
        with self.lock:
            now = time.time()
            if now - self.last_fail < 1.0:
                return None
            if not hmac.compare_digest(given.encode(), self.token.encode()):
                self.last_fail = now
                return None
            sid = secrets.token_urlsafe(32)
            self.sessions = {k: v for k, v in self.sessions.items() if v[1] > now}
            self.sessions[sid] = (secrets.token_urlsafe(24), now + SESSION_TTL)
            return sid

    def check(self, sid):
        """세션이면 그 CSRF 값, 아니면 None."""
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s[1] < time.time():
                self.sessions.pop(sid, None)
                return None
            return s[0]

    def logout(self, sid):
        with self.lock:
            self.sessions.pop(sid, None)


# ---- 화면 -----------------------------------------------------------------------

CSS = """
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI","Malgun Gothic",sans-serif;margin:0;background:#f5f6f8;color:#1d2330}
header{background:#1d2330;color:#fff;padding:10px 20px;display:flex;gap:18px;align-items:center}
header b{font-size:16px;margin-right:12px} header a{color:#c9d1e0;text-decoration:none} header a.on{color:#fff;font-weight:600}
main{padding:18px 20px;max-width:1200px} h2{font-size:16px;margin:22px 0 8px}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #dde1e8}
th,td{padding:6px 9px;border-bottom:1px solid #eceff4;text-align:left;vertical-align:top;font-size:13px}
th{background:#f0f2f6;font-weight:600} code{font-size:12px}
.card{background:#fff;border:1px solid #dde1e8;padding:12px 16px;margin:8px 0;display:inline-block;min-width:150px;margin-right:8px}
.card b{display:block;font-size:20px} .ok{color:#127a3a} .bad{color:#b42318} .muted{color:#6b7385}
.msg{padding:9px 12px;margin:10px 0;border-radius:4px} .msg.err{background:#fde8e6;color:#8a1c12} .msg.ok{background:#e4f5ea;color:#11602f}
form.inline{display:inline} input,select{font:inherit;padding:4px 6px} button{font:inherit;padding:4px 10px;cursor:pointer}
pre{background:#fff;border:1px solid #dde1e8;padding:10px;overflow:auto;font-size:12px}
"""

PAGES = [("/", "개요"), ("/devices", "기기"), ("/enroll", "등록 코드"), ("/acl", "ACL"), ("/audit", "감사 로그")]


def e(v):
    return html.escape("" if v is None else str(v))


def size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def req_text(r):
    if not r:
        return ""
    t = []
    if r.get("firewall"):
        t.append("firewall=on")
    if r.get("antivirus"):
        t.append("antivirus=on")
    if r.get("disk"):
        t.append("disk=on")
    if r.get("min_build"):
        t.append("min-build=%d" % r["min_build"])
    return " ".join(t)


def page(path, body, csrf=None, msg=None):
    nav = "".join('<a href="%s"%s>%s</a>' % (p, ' class="on"' if p == path else "", n) for p, n in PAGES)
    logout = ('<form class="inline" method="post" action="/logout" style="margin-left:auto">'
              '<input type="hidden" name="csrf" value="%s"><button>로그아웃</button></form>' % e(csrf)) if csrf else ""
    note = ""
    if msg:
        note = '<div class="msg %s">%s</div>' % ("err" if msg[0] == "err" else "ok", e(msg[1]))
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>ztgate 콘솔</title>'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><style>%s</style></head>'
            '<body><header><b>ztgate</b>%s%s</header><main>%s%s</main></body></html>') % (
        CSS, nav if csrf else "", logout, note, body)


def view_overview(c):
    st = c.call("status")
    if not st.get("ok"):
        return '<div class="msg err">%s</div>' % e(st.get("error"))
    run = '<span class="ok">실행 중</span>' if st.get("running") else '<span class="bad">멈춤</span>'
    cnt = st.get("counters", {})
    cards = [("서버", run), ("붙어 있는 세션", len(st.get("sessions", []))),
             ("등록된 기기", st.get("registered_devices")), ("ACL", "%d 규칙" % st.get("acl", {}).get("rules", 0)),
             ("핸드셰이크 성공", cnt.get("handshake_ok", 0)),
             ("거절 (모르는 기기 / 인증 / 포스처)", "%d / %d / %d" % (
                 cnt.get("deny_unknown_device", 0), cnt.get("deny_bad_auth", 0), cnt.get("deny_posture", 0))),
             ("ACL 차단", cnt.get("acl_denied", 0))]
    out = "".join('<div class="card"><span class="muted">%s</span><b>%s</b></div>' % (e(k), v if k == "서버" else e(v))
                  for k, v in cards)
    rows = []
    for s in st.get("sessions", []):
        p = s.get("posture", {})
        user = (s.get("user") or {}).get("name", "")
        rows.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td>"
                    "<td>방화벽 %s · 백신 %s · 디스크 %s · 빌드 %s</td><td>%s / %s</td><td>%s</td></tr>" % (
                        e(s.get("tunnel_ip")), e(s.get("device_id")), e(user), e(s.get("endpoint")),
                        e(" ".join(s.get("tags", []))), e(p.get("firewall")), e(p.get("antivirus")),
                        e(p.get("disk")), e(p.get("os_build")), size(s.get("rx_bytes", 0)), size(s.get("tx_bytes", 0)),
                        "%d분" % (s.get("age_sec", 0) // 60)))
    table = ("<table><tr><th>터널 주소</th><th>기기</th><th>사용자</th><th>출발지</th><th>태그</th><th>포스처</th>"
             "<th>받음 / 보냄</th><th>연결된 지</th></tr>%s</table>" % "".join(rows)) if rows else \
        '<p class="muted">붙어 있는 세션이 없습니다.</p>'
    return "<h2>상태</h2>%s<h2>세션</h2>%s" % (out, table)


def view_devices(c, csrf):
    r = c.call("device_list")
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    rows = []
    for d in r.get("devices", []):
        rows.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>"
                    '<form class="inline" method="post" action="/devices/remove" onsubmit="return confirm(\'이 기기를 지울까요? 다음 keepalive 에서 끊깁니다.\')">'
                    '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                    "<button>지우기</button></form></td></tr>" % (
                        e(d.get("label")), e(d.get("id")), e(d.get("tunnel_ip")), e(d.get("key_type")),
                        e(req_text(d.get("requirements"))), e(" ".join(d.get("tags", []))), e(csrf), e(d.get("id"))))
    return ("<h2>기기 (%d)</h2><table><tr><th>이름</th><th>ID</th><th>터널 주소</th><th>키</th><th>조건</th><th>태그</th>"
            "<th></th></tr>%s</table>" % (len(rows), "".join(rows)))


def view_enroll(c, csrf, made=None):
    r = c.call("enroll_list")
    rows = []
    for p in r.get("pending", []) if r.get("ok") else []:
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d분</td><td>"
                    '<form class="inline" method="post" action="/enroll/revoke">'
                    '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                    "<button>거두기</button></form></td></tr>" % (
                        e(p.get("label")), e(p.get("tunnel_ip")), e(req_text(p.get("requirements"))),
                        e(" ".join(p.get("tags", []))), max(0, p.get("expires_in_sec", 0)) // 60, e(csrf), e(p.get("id"))))
    code = ""
    if made:
        code = ('<div class="msg ok">등록 코드 <b style="font-size:20px;letter-spacing:1px">%s</b> — %s 에 배정. '
                "한 번만 쓸 수 있고 곧 만료됩니다. 기기에서 <code>vpn_client enroll &lt;서버&gt; &lt;포트&gt; &lt;코드&gt;</code> "
                "또는 GUI 의 [기기 등록]</div>") % (e(made.get("code")), e(made.get("enrollment", {}).get("tunnel_ip")))
    form = ('<h2>새 등록 코드</h2><form method="post" action="/enroll/create">'
            '<input type="hidden" name="csrf" value="%s">'
            '이름 <input name="label" size="16" placeholder="laptop-kim"> '
            '터널 주소 <input name="tunnel_ip" size="12" placeholder="비우면 자동"> '
            '태그 <input name="tags" size="14" placeholder="eng laptop"> '
            '<label><input type="checkbox" name="firewall"> 방화벽</label> '
            '<label><input type="checkbox" name="antivirus"> 백신</label> '
            '<label><input type="checkbox" name="disk"> 디스크 암호화</label> '
            '유효 <input name="ttl" size="3" value="15">분 <button>만들기</button></form>') % e(csrf)
    pending = ("<table><tr><th>이름</th><th>터널 주소</th><th>조건</th><th>태그</th><th>남은 시간</th><th></th></tr>%s</table>"
               % "".join(rows)) if rows else '<p class="muted">기다리는 등록 코드가 없습니다.</p>'
    return "%s%s<h2>기다리는 등록</h2>%s" % (code, form, pending)


def view_acl(c):
    r = c.call("acl_get")
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    if not r.get("enabled"):
        return '<p class="muted">ACL 이 꺼져 있습니다 (터널 대역 안까지만 닿습니다).</p>'
    rows = []
    for i, rule in enumerate(r.get("rules") or []):
        cond = []
        if rule.get("tags"):
            cond.append("tag=" + ",".join(rule["tags"]))
        if rule.get("users"):
            cond.append(json.dumps(rule["users"], ensure_ascii=False))
        cond.append(req_text(rule.get("require") or rule.get("requirements")))
        rows.append("<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            i, e(rule.get("src")), e(rule.get("dst")), e(rule.get("proto")), e(rule.get("dport")),
            '<span class="%s">%s</span>' % ("ok" if rule.get("action") == "allow" else "bad", e(rule.get("action"))),
            e(" ".join(x for x in cond if x))))
    return ("<h2>ACL (위에서부터 첫 일치)</h2><table><tr><th>#</th><th>출발지</th><th>목적지</th><th>프로토콜</th>"
            "<th>포트</th><th>판정</th><th>조건</th></tr>%s</table><p class=\"muted\">규칙을 바꾸는 것은 MCP 의 acl_set "
            "또는 /etc/ztgate/acl.conf 를 고친 뒤 reload 입니다.</p>" % "".join(rows))


def view_audit(c, q):
    args = {"lines": 200}
    if q.get("event"):
        args["event"] = q["event"]
    r = c.call("audit", **args)
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    events = ["", "session_open", "session_close", "auth_denied", "enrolled", "access", "login", "reload"]
    sel = "".join('<option%s>%s</option>' % (" selected" if q.get("event") == v else "", e(v)) for v in events)
    rows = []
    for ev in reversed(r.get("events", [])):
        rest = {k: v for k, v in ev.items() if k not in ("time", "event")}
        rows.append("<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
            e(ev.get("time")), e(ev.get("event")), e(json.dumps(rest, ensure_ascii=False))))
    return ('<h2>감사 로그 (최근 200)</h2><form method="get">종류 <select name="event">%s</select> <button>보기</button></form>'
            "<table><tr><th>시각</th><th>종류</th><th>내용</th></tr>%s</table>" % (sel, "".join(rows)))


LOGIN = ('<h2>로그인</h2><form method="post" action="/login"><p>관리 토큰 '
         '<input type="password" name="token" size="44" autofocus> <button>들어가기</button></p>'
         '<p class="muted">서버에서 <code>sudo cat /etc/ztgate/console.token</code></p></form>')


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ztgate-console"
    console = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ztgate_session":
                return v
        return ""

    def send(self, code, body, headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, where, headers=None):
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        c = self.console
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        csrf = c.check(self.cookie())
        if csrf is None:
            self.send(200 if url.path in ("/", "/login") else 401, page("/login", LOGIN))
            return
        views = {"/": lambda: view_overview(c), "/devices": lambda: view_devices(c, csrf),
                 "/enroll": lambda: view_enroll(c, csrf), "/acl": lambda: view_acl(c), "/audit": lambda: view_audit(c, q)}
        if url.path not in views:
            self.send(404, page(url.path, "<p>없는 페이지입니다.</p>", csrf))
            return
        msg = None
        if q.get("ok"):
            msg = ("ok", q["ok"])
        elif q.get("err"):
            msg = ("err", q["err"])
        self.send(200, page(url.path, views[url.path](), csrf, msg))

    def do_POST(self):
        c = self.console
        n = int(self.headers.get("Content-Length") or 0)
        if n > 16384:
            self.send(413, page("/", "<p>요청이 너무 큽니다.</p>"))
            return
        form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode("utf-8", "replace")))
        path = urllib.parse.urlsplit(self.path).path

        if path == "/login":
            sid = c.login(form.get("token", ""))
            if sid is None:
                self.send(403, page("/login", '<div class="msg err">토큰이 맞지 않습니다.</div>' + LOGIN))
                return
            flags = "HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s" % (SESSION_TTL, "; Secure" if c.secure else "")
            self.redirect("/", {"Set-Cookie": "ztgate_session=%s; %s" % (sid, flags)})
            return

        sid = self.cookie()
        csrf = c.check(sid)
        if csrf is None or not hmac.compare_digest(form.get("csrf", ""), csrf):
            self.send(403, page("/login", '<div class="msg err">세션이 끝났거나 요청이 이 콘솔에서 온 것이 아닙니다.</div>' + LOGIN))
            return

        if path == "/logout":
            c.logout(sid)
            self.redirect("/", {"Set-Cookie": "ztgate_session=; Max-Age=0; Path=/"})
            return
        if path == "/devices/remove":
            r = c.call("device_remove", id=form.get("id", ""))
            self.done("/devices", r, "기기를 지웠습니다")
            return
        if path == "/enroll/revoke":
            r = c.call("enroll_revoke", id=form.get("id", ""))
            self.done("/enroll", r, "등록 코드를 거뒀습니다")
            return
        if path == "/enroll/create":
            args = {"requirements": {k: True for k in ("firewall", "antivirus", "disk") if form.get(k)}}
            if form.get("label"):
                args["label"] = form["label"]
            if form.get("tunnel_ip"):
                args["tunnel_ip"] = form["tunnel_ip"].strip()
            if form.get("tags", "").strip():
                args["tags"] = form["tags"].split()
            try:
                args["ttl_minutes"] = int(form.get("ttl") or 15)
            except ValueError:
                args["ttl_minutes"] = 15
            r = c.call("enroll_create", **args)
            if not r.get("ok"):
                self.done("/enroll", r, "")
                return
            self.send(200, page("/enroll", view_enroll(c, csrf, made=r), csrf))
            return
        self.send(404, page(path, "<p>없는 동작입니다.</p>", csrf))

    def done(self, where, r, ok_text):
        key, text = ("ok", ok_text) if r.get("ok") else ("err", r.get("error") or "실패")
        self.redirect("%s?%s" % (where, urllib.parse.urlencode({key: text})))


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def load_token(path):
    try:
        with open(path) as f:
            t = f.read().strip()
        if len(t) >= 20:
            return t
    except FileNotFoundError:
        pass
    t = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(t + "\n")
    print("console: a new login token is in %s" % path, file=sys.stderr)
    return t


def main():
    ap = argparse.ArgumentParser(description="ztgate web console")
    ap.add_argument("-l", "--listen", default="127.0.0.1:9470")
    ap.add_argument("--ctl", default="/usr/sbin/ztgate_ctl" if os.path.exists("/usr/sbin/ztgate_ctl") else "/usr/local/sbin/ztgate_ctl")
    ap.add_argument("--token-file", default="/etc/ztgate/console.token")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    a = ap.parse_args()

    host, _, port = a.listen.rpartition(":")
    Handler.console = Console(a.ctl, load_token(a.token_file), bool(a.tls_cert))
    srv = Server((host, int(port)), Handler)
    if a.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    elif host not in ("127.0.0.1", "localhost", "::1"):
        print("console: listening on %s without TLS — the token and cookies cross the network in clear" % host,
              file=sys.stderr)
    print("console: http%s://%s/" % ("s" if a.tls_cert else "", a.listen), file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
