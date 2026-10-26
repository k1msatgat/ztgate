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
# 색과 간격은 docs/design/tokens.md 를 따른다. 밖에서 받아 오는 파일(글꼴, 스크립트, 그림)은 없다.

CSS = """
:root{--navy-950:#0B1626;--navy-900:#0F1E36;--navy-800:#16294A;--bg:#F5F7FA;--surface:#FFFFFF;--surface-2:#EEF2F7;
--border:#DCE3EC;--text:#1A2333;--muted:#5B6678;--accent:#1E4E8C;--accent-hover:#173F73;--accent-soft:#E6EEF8;
--teal:#2A9D8F;--teal-text:#1F7A6F;--teal-soft:#E3F4F1;--warn:#C27C0E;--warn-soft:#FBF1DE;--danger:#B4232F;
--danger-soft:#FBE9EA;--idle:#8A95A8;--shadow:0 1px 2px rgba(15,30,54,.06),0 1px 8px rgba(15,30,54,.04);color-scheme:light}
:root[data-theme=dark]{--bg:#0B1626;--surface:#13233A;--surface-2:#1A2D48;--border:#24395A;--text:#E6ECF5;--muted:#9AA8BD;
--accent:#5B8FD6;--accent-hover:#78A5E2;--accent-soft:#1B3254;--teal:#3FBFAE;--teal-text:#3FBFAE;--teal-soft:#123A3A;
--warn:#E0A33A;--warn-soft:#3A2C12;--danger:#E5636D;--danger-soft:#3D1A20;--idle:#6F7D93;--shadow:none;color-scheme:dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0B1626;--surface:#13233A;--surface-2:#1A2D48;
--border:#24395A;--text:#E6ECF5;--muted:#9AA8BD;--accent:#5B8FD6;--accent-hover:#78A5E2;--accent-soft:#1B3254;
--teal:#3FBFAE;--teal-text:#3FBFAE;--teal-soft:#123A3A;--warn:#E0A33A;--warn-soft:#3A2C12;--danger:#E5636D;
--danger-soft:#3D1A20;--idle:#6F7D93;--shadow:none;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 system-ui,"Segoe UI","Malgun Gothic","Apple SD Gothic Neo",sans-serif;background:var(--bg);color:var(--text)}
code,.mono,textarea{font-family:ui-monospace,Consolas,"D2Coding",monospace}
code{font-size:12.5px}
a{color:var(--accent)}
.app{display:flex;min-height:100vh}
.side{width:232px;flex:none;background:var(--navy-900);border-right:1px solid rgba(255,255,255,.06);position:sticky;top:0;height:100vh;color:#C9D4E5;display:flex;flex-direction:column;padding:20px 14px}
.brand{display:flex;align-items:center;gap:10px;padding:2px 8px 22px}
.brand b{display:block;color:#fff;font-size:17px;letter-spacing:.2px}
.brand small{display:block;color:#8FA1BC;font-size:11.5px}
.nav a{display:flex;align-items:center;gap:11px;padding:9px 12px;margin:2px 0;border-radius:8px;color:#C9D4E5;text-decoration:none;font-size:14px}
.nav a:hover{background:rgba(255,255,255,.05);color:#fff}
.nav a.on{background:var(--navy-800);color:#fff;font-weight:600;box-shadow:inset 3px 0 0 #2A9D8F}
.nav svg{width:18px;height:18px;flex:none;opacity:.9}
.side-foot{margin-top:auto;padding:12px 8px 0;border-top:1px solid rgba(255,255,255,.08);font-size:12px;color:#8FA1BC}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.top{display:flex;align-items:center;gap:12px;padding:18px 32px;border-bottom:1px solid var(--border);background:var(--surface)}
.top h1{font-size:20px;margin:0;font-weight:650}
.top .sub{color:var(--muted);font-size:13px;margin-left:4px}
.top .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.content{padding:24px 32px 48px;max-width:1280px;width:100%}
h2{font-size:16px;margin:28px 0 12px;font-weight:650}
h2:first-child{margin-top:0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow)}
.card.pad{padding:20px 22px}
.card.scroll{overflow-x:auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.stat{padding:16px 18px}
.stat .k{color:var(--muted);font-size:12.5px;display:flex;align-items:center;gap:6px}
.stat .v{font-size:26px;font-weight:650;margin-top:6px;line-height:1.2;font-variant-numeric:tabular-nums}
.stat .s{color:var(--muted);font-size:12px;margin-top:4px}
.stat.hl{border-top:3px solid var(--teal)}
.stat.alert .v{color:var(--danger)}
.tbl{width:100%;border-collapse:separate;border-spacing:0}
.tbl th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);background:var(--surface-2);padding:9px 14px;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl th:first-child{border-top-left-radius:10px}.tbl th:last-child{border-top-right-radius:10px}
.tbl td{padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:middle;font-size:13.5px}
.tbl tr:last-child td{border-bottom:0}
.tbl tr:hover td{background:color-mix(in srgb,var(--accent-soft) 45%,transparent)}
.tbl .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.badge.ok{background:var(--teal-soft);color:var(--teal-text)}
.badge.warn{background:var(--warn-soft);color:var(--warn)}
.badge.bad{background:var(--danger-soft);color:var(--danger)}
.badge.idle{background:var(--surface-2);color:var(--idle)}
.badge.info{background:var(--accent-soft);color:var(--accent)}
.chip{display:inline-block;padding:1px 8px;margin:1px 4px 1px 0;border-radius:6px;font-size:12px;background:var(--surface-2);color:var(--text);border:1px solid var(--border);white-space:nowrap}
.chip.ok{background:var(--teal-soft);color:var(--teal-text);border-color:transparent}
.chip.bad{background:var(--danger-soft);color:var(--danger);border-color:transparent}
.chip.mono{font-family:ui-monospace,Consolas,monospace}
.muted{color:var(--muted)}
.id{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--idle);margin-right:8px;vertical-align:1px}
.dot.on{background:var(--teal);box-shadow:0 0 0 3px var(--teal-soft)}
.btn{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:13.5px;font-weight:600;padding:7px 14px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;text-decoration:none}
.btn:hover{background:var(--surface-2)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{background:var(--accent-hover)}
.btn.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 35%,var(--border))}
.btn.danger:hover{background:var(--danger-soft)}
.btn.sm{padding:4px 10px;font-size:12.5px}
.btn.icon{padding:7px 9px}
.btn svg{width:16px;height:16px}
form.inline{display:inline}
.msg{display:flex;gap:10px;align-items:flex-start;padding:12px 16px;margin:0 0 18px;border-radius:10px;border:1px solid transparent;font-size:13.5px}
.msg.err{background:var(--danger-soft);color:var(--danger);border-color:color-mix(in srgb,var(--danger) 25%,transparent)}
.msg.ok{background:var(--teal-soft);color:var(--teal-text);border-color:color-mix(in srgb,var(--teal) 25%,transparent)}
.empty{padding:36px;text-align:center;color:var(--muted)}
.empty svg{width:34px;height:34px;opacity:.5;display:block;margin:0 auto 10px}
.grid2{display:grid;grid-template-columns:minmax(320px,420px) 1fr;gap:20px;align-items:start}
.field{display:block;margin-bottom:14px}
.field>span{display:block;font-size:12.5px;font-weight:600;color:var(--muted);margin-bottom:5px}
.field input[type=text],.field input:not([type]),.field input[type=password],.field input[type=number],select{width:100%;font:inherit;padding:8px 11px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text)}
input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 45%,transparent);outline-offset:1px;border-color:var(--accent)}
.checks{display:flex;flex-wrap:wrap;gap:8px}
.checks label{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:13px}
.checks input{accent-color:var(--accent)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.callout{display:flex;gap:18px;align-items:center;padding:18px 22px;border-radius:10px;background:var(--teal-soft);border:1px solid color-mix(in srgb,var(--teal) 30%,transparent);margin-bottom:20px}
.callout .code{font:600 22px/1.2 ui-monospace,Consolas,monospace;letter-spacing:1.5px;color:var(--text);user-select:all}
.callout p{margin:4px 0 0;color:var(--muted);font-size:13px}
textarea{width:100%;font-size:13px;line-height:1.6;padding:12px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2);color:var(--text);resize:vertical}
.help{color:var(--muted);font-size:12.5px;margin:10px 0 14px}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.filters a{padding:5px 12px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-decoration:none;font-size:12.5px}
.filters a.on{background:var(--accent);border-color:var(--accent);color:#fff}
.kv{display:inline-block;margin:1px 8px 1px 0;font-size:12px;white-space:nowrap}
.kv i{font-style:normal;color:var(--muted)}
.login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background:radial-gradient(1200px 600px at 20% -10%,#1E4E8C33,transparent),var(--navy-950)}
.login .card{width:100%;max-width:400px;padding:34px 32px}
.login h1{font-size:20px;margin:16px 0 4px}
.login p.lead{color:var(--muted);margin:0 0 22px;font-size:13.5px}
.login .btn.primary{width:100%;justify-content:center;padding:10px}
.login .foot{margin-top:18px;color:var(--muted);font-size:12px}
@media (max-width:860px){.app{flex-direction:column}.side{width:auto;position:static;height:auto;flex-direction:row;align-items:center;padding:10px 14px;gap:6px;overflow-x:auto}
.brand{padding:0 10px 0 0}.brand small,.side-foot{display:none}.nav{display:flex}.nav a{padding:7px 10px;white-space:nowrap}
.top,.content{padding-left:16px;padding-right:16px}.top .sub{display:none}.stats{grid-template-columns:1fr 1fr}.grid2{grid-template-columns:1fr}}
"""

THEME_JS = ("(function(){var k='ztgate-theme';try{var t=localStorage.getItem(k);if(t)document.documentElement.dataset.theme=t}"
            "catch(x){}window.ztTheme=function(){var d=document.documentElement,c=d.dataset.theme||(matchMedia("
            "'(prefers-color-scheme: dark)').matches?'dark':'light'),n=c==='dark'?'light':'dark';d.dataset.theme=n;"
            "try{localStorage.setItem(k,n)}catch(x){}};window.ztCopy=function(el){var t=el.getAttribute('data-copy');"
            "function sel(){var r=document.createRange();r.selectNodeContents(document.getElementById('code'));"
            "var s=getSelection();s.removeAllRanges();s.addRange(r)}if(navigator.clipboard&&isSecureContext)"
            "navigator.clipboard.writeText(t).then(function(){el.textContent='복사했습니다'},sel);else sel()}})();")

LOGO = ('<svg width="%d" height="%d" viewBox="0 0 64 64" aria-hidden="true">'
        '<path d="M32 4 56 12v18c0 15-10 25-24 30C18 55 8 45 8 30V12z" fill="#0F1E36"/>'
        '<path d="M32 7.5 53 14.5V30c0 13-8.6 21.8-21 26.4C19.6 51.8 11 43 11 30V14.5z" fill="none" stroke="#2C5E9E" stroke-width="1.5"/>'
        '<rect x="20" y="19" width="3.5" height="26" rx="1.5" fill="#5B8FD6"/><rect x="34" y="19" width="3.5" height="26" rx="1.5" fill="#5B8FD6"/>'
        '<path d="M14 32h32" stroke="#2A9D8F" stroke-width="4" stroke-linecap="round"/>'
        '<path d="M43 26.5l6 5.5-6 5.5" fill="none" stroke="#2A9D8F" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>')

_I = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">%s</svg>'
ICONS = {
    "/": _I % '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/>'
              '<rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "/devices": _I % '<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
    "/enroll": _I % '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/>',
    "/acl": _I % '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "/audit": _I % '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
    "theme": _I % '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    "logout": _I % '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    "empty": _I % '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    "plus": _I % '<path d="M12 5v14M5 12h14"/>',
}

PAGES = [("/", "개요"), ("/devices", "기기"), ("/enroll", "등록 코드"), ("/acl", "ACL"), ("/audit", "감사 로그")]
SUBTITLE = {"/": "서버 상태와 지금 붙어 있는 세션", "/devices": "등록된 기기와 접속 조건",
            "/enroll": "새 기기를 들일 일회용 코드", "/acl": "위에서부터 첫 일치, 일치하지 않으면 거부",
            "/audit": "최근 200건"}


def e(v):
    return html.escape("" if v is None else str(v))


def size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def ago(sec):
    sec = max(0, int(sec or 0))
    if sec < 60:
        return "%d초" % sec
    if sec < 3600:
        return "%d분" % (sec // 60)
    return "%d시간 %d분" % (sec // 3600, sec % 3600 // 60)


def num(v):
    return "{:,}".format(v) if isinstance(v, int) else e(v)


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


REQ_NAMES = {"firewall=on": "방화벽", "antivirus=on": "백신", "disk=on": "디스크 암호화"}


def req_chips(r):
    """조건을 알약으로. 파일에 적는 모양(firewall=on)은 title 로 남긴다."""
    out = []
    for t in req_text(r).split():
        name = REQ_NAMES.get(t) or "빌드 %s 이상" % t.split("=", 1)[1]
        out.append('<span class="chip" title="%s">%s</span>' % (e(t), e(name)))
    return "".join(out) or '<span class="muted">—</span>'


def tag_chips(tags):
    return "".join('<span class="chip mono">#%s</span>' % e(t) for t in tags or []) or '<span class="muted">—</span>'


def badge(kind, text):
    return '<span class="badge %s">%s</span>' % (kind, e(text))


def empty(text):
    return '<div class="card empty">%s%s</div>' % (ICONS["empty"], e(text))


def card_table(head, rows):
    return ('<div class="card scroll"><table class="tbl"><tr>%s</tr>%s</table></div>'
            % ("".join("<th%s>%s</th>" % (' class="num"' if h.startswith(">") else "", e(h.lstrip(">"))) for h in head),
               "".join(rows)))


def page(path, body, csrf=None, msg=None):
    note = ""
    if msg:
        note = '<div class="msg %s">%s</div>' % ("err" if msg[0] == "err" else "ok", e(msg[1]))
    head = ('<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>ztgate 콘솔</title>'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">'
            '<style>%s</style><script>%s</script></head>') % (CSS, THEME_JS)
    if not csrf:
        return head + '<body><div class="login">%s%s</div></body></html>' % (note, body)
    nav = "".join('<a href="%s"%s>%s<span>%s</span></a>' % (p, ' class="on"' if p == path else "", ICONS[p], n)
                  for p, n in PAGES)
    title = dict(PAGES).get(path, "없는 페이지")
    return head + (
        '<body><div class="app"><aside class="side"><div class="brand">%s<div><b>ztgate</b><small>Zero Trust Gateway</small>'
        '</div></div><nav class="nav">%s</nav><div class="side-foot">관리 콘솔 · 터널 안에서만</div></aside>'
        '<div class="main"><header class="top"><h1>%s</h1><span class="sub">%s</span><div class="right">'
        '<button class="btn icon" type="button" onclick="ztTheme()" title="밝게 / 어둡게">%s</button>'
        '<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="%s">'
        '<button class="btn">%s로그아웃</button></form></div></header><main class="content">%s%s</main></div></div>'
        '</body></html>') % (LOGO % (34, 34), nav, e(title), e(SUBTITLE.get(path, "")), ICONS["theme"], e(csrf),
                             ICONS["logout"], note, body)


def posture_chips(p):
    out = []
    for key, name in (("firewall", "방화벽"), ("antivirus", "백신"), ("disk", "디스크")):
        v = p.get(key)
        cls = "ok" if v == "on" else "bad" if v == "off" else ""
        out.append('<span class="chip %s" title="%s=%s">%s</span>' % (cls, key, e(v), name))
    if p.get("os_build"):
        out.append('<span class="chip mono">build %s</span>' % e(p.get("os_build")))
    return "".join(out)


def view_overview(c):
    st = c.call("status")
    if not st.get("ok"):
        return '<div class="msg err">%s</div>' % e(st.get("error"))
    cnt = st.get("counters", {})
    sessions = st.get("sessions", [])
    denied = sum(cnt.get(k, 0) for k in ("deny_unknown_device", "deny_bad_auth", "deny_posture"))
    run = badge("ok", "실행 중") if st.get("running") else badge("bad", "멈춤")
    cards = [
        ("서버", run, "vpn_server", "hl"),
        ("연결된 세션", num(len(sessions)), "터널이 열린 기기", "hl"),
        ("등록된 기기", num(st.get("registered_devices")), "", ""),
        ("ACL 규칙", num(st.get("acl", {}).get("rules", 0)), "첫 일치 · 기본 거부", ""),
        ("핸드셰이크 성공", num(cnt.get("handshake_ok", 0)), "서버가 뜬 뒤", ""),
        ("거절", num(denied), "모르는 기기 %s · 인증 %s · 포스처 %s" % (
            num(cnt.get("deny_unknown_device", 0)), num(cnt.get("deny_bad_auth", 0)), num(cnt.get("deny_posture", 0))),
         "alert" if denied else ""),
        ("ACL 차단", num(cnt.get("acl_denied", 0)), "규칙에 막힌 패킷", "alert" if cnt.get("acl_denied") else ""),
    ]
    out = "".join('<div class="card stat %s"><div class="k">%s</div><div class="v">%s</div><div class="s">%s</div></div>'
                  % (cls, e(k), v, e(s)) for k, v, s, cls in cards)
    rows = []
    for s in sessions:
        user = (s.get("user") or {}).get("name", "")
        dev = s.get("device_id") or ""
        rows.append('<tr><td><span class="dot on"></span><b>%s</b></td><td><span class="id" title="%s">%s…</span></td>'
                    '<td>%s</td><td class="mono">%s</td><td>%s</td><td>%s</td><td class="num">↓ %s<br>↑ %s</td>'
                    '<td class="num">%s</td></tr>' % (
                        e(s.get("tunnel_ip")), e(dev), e(dev[:12]),
                        e(user) if user else '<span class="muted">—</span>', e(s.get("endpoint")),
                        tag_chips(s.get("tags")), posture_chips(s.get("posture", {})),
                        size(s.get("rx_bytes", 0)), size(s.get("tx_bytes", 0)), ago(s.get("age_sec"))))
    table = card_table(["터널 주소", "기기", "사용자", "출발지", "태그", "포스처", ">받음 / 보냄", ">연결된 지"], rows) \
        if rows else empty("붙어 있는 세션이 없습니다.")
    return '<div class="stats">%s</div><h2>세션 <span class="muted">%d</span></h2>%s' % (out, len(rows), table)


def view_devices(c, csrf):
    r = c.call("device_list")
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    st = c.call("status")
    online = {s.get("device_id") for s in st.get("sessions", [])} if st.get("ok") else set()
    rows = []
    for d in r.get("devices", []):
        on = d.get("id") in online
        key = "P-256" if d.get("key_type") == "p256" else "공유 키" if d.get("key_type") else ""
        rows.append('<tr><td style="white-space:nowrap"><span class="dot%s"></span><b>%s</b></td><td><span class="id" title="%s">%s…</span></td>'
                    '<td class="mono">%s</td><td>%s</td><td style="white-space:nowrap">%s</td><td>%s</td><td>%s</td><td class="num">'
                    '<form class="inline" method="post" action="/devices/remove" onsubmit="return confirm(\'이 기기를 지울까요? 다음 keepalive 에서 끊깁니다.\')">'
                    '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                    '<button class="btn sm danger">지우기</button></form></td></tr>' % (
                        " on" if on else "", e(d.get("label") or "(이름 없음)"), e(d.get("id")), e((d.get("id") or "")[:16]),
                        e(d.get("tunnel_ip")), badge("ok", "연결됨") if on else badge("idle", "끊김"),
                        e(key), req_chips(d.get("requirements")), tag_chips(d.get("tags")), e(csrf), e(d.get("id"))))
    head = ('<div class="row" style="margin-bottom:14px"><h2 style="margin:0">기기 <span class="muted">%d</span></h2>'
            '<a class="btn primary" style="margin-left:auto" href="/enroll">%s새 기기 등록</a></div>') % (len(rows), ICONS["plus"])
    table = card_table(["이름", "ID", "터널 주소", "상태", "키", "접속 조건", "태그", ""], rows) if rows else \
        empty("등록된 기기가 없습니다. [등록 코드]에서 코드를 만들어 기기에 넣으세요.")
    return head + table


def view_enroll(c, csrf, made=None):
    r = c.call("enroll_list")
    rows = []
    for p in r.get("pending", []) if r.get("ok") else []:
        left = max(0, p.get("expires_in_sec", 0))
        rows.append('<tr><td><b>%s</b></td><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">'
                    '<form class="inline" method="post" action="/enroll/revoke">'
                    '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                    '<button class="btn sm danger">거두기</button></form></td></tr>' % (
                        e(p.get("label") or "(이름 없음)"), e(p.get("tunnel_ip")), req_chips(p.get("requirements")),
                        tag_chips(p.get("tags")), badge("warn" if left < 180 else "idle", "%d분 남음" % (left // 60)),
                        e(csrf), e(p.get("id"))))
    code = ""
    if made:
        code = ('<div class="callout"><div style="flex:1"><div class="muted" style="font-size:12.5px">등록 코드 · %s 에 배정</div>'
                '<div class="code" id="code">%s</div><p>한 번만 쓸 수 있고 곧 만료됩니다. 기기에서 '
                '<code>vpn_client enroll &lt;서버&gt; &lt;포트&gt; &lt;코드&gt;</code> 또는 GUI 의 [기기 등록]</p></div>'
                '<button class="btn" type="button" data-copy="%s" onclick="ztCopy(this)">복사</button></div>') % (
            e(made.get("enrollment", {}).get("tunnel_ip")), e(made.get("code")), e(made.get("code")))
    form = ('<div class="card pad"><h2>새 등록 코드</h2><form method="post" action="/enroll/create">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label class="field"><span>이름</span><input name="label" placeholder="laptop-kim"></label>'
            '<label class="field"><span>터널 주소</span><input name="tunnel_ip" placeholder="비우면 자동으로 배정"></label>'
            '<label class="field"><span>태그 (빈칸으로 나눔)</span><input name="tags" placeholder="eng laptop"></label>'
            '<div class="field"><span>접속 조건</span><div class="checks">'
            '<label><input type="checkbox" name="firewall"> 방화벽</label>'
            '<label><input type="checkbox" name="antivirus"> 백신</label>'
            '<label><input type="checkbox" name="disk"> 디스크 암호화</label></div></div>'
            '<label class="field"><span>유효 시간 (분)</span><input type="number" name="ttl" value="15" min="1" max="1440"></label>'
            '<button class="btn primary">%s코드 만들기</button></form></div>') % (e(csrf), ICONS["plus"])
    pending = card_table(["이름", "터널 주소", "접속 조건", "태그", "남은 시간", ""], rows) if rows else \
        empty("기다리는 등록 코드가 없습니다.")
    return '%s<div class="grid2">%s<div><h2>기다리는 등록 <span class="muted">%d</span></h2>%s</div></div>' % (
        code, form, len(rows), pending)


def rule_line(rule):
    """acl_get 의 규칙 하나를 파일과 같은 한 줄로."""
    t = [rule.get("src"), rule.get("dst"), rule.get("proto"), rule.get("dport"), rule.get("action")]
    req = req_text(rule.get("require"))
    if req:
        t.append(req)
    u = rule.get("users") or {}
    t += ["user=" + n for n in u.get("users", [])] + ["group=" + n for n in u.get("groups", [])]
    t += ["tag=" + n for n in rule.get("tags", [])]
    return " ".join(str(x) for x in t)


def parse_rules(text):
    """편집한 줄들을 acl_set 의 규칙으로. (규칙들, 오류 글) — 검증 자체는 ztgate_ctl 이 한 번 더 한다."""
    rules = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tok = line.split()
        if len(tok) < 5:
            return None, "%d번째 줄: 출발지 목적지 프로토콜 포트 판정, 다섯 칸이 필요합니다" % n
        rule = {"src": tok[0], "dst": tok[1], "proto": tok[2], "dport": tok[3], "action": tok[4]}
        req, users, groups, tags = {}, [], [], []
        for t in tok[5:]:
            if t in ("firewall=on", "antivirus=on", "disk=on"):
                req[t.split("=")[0]] = True
            elif t.startswith("min-build=") and t[10:].isdigit():
                req["min_build"] = int(t[10:])
            elif t.startswith("user="):
                users.append(t[5:])
            elif t.startswith("group="):
                groups.append(t[6:])
            elif t.startswith("tag="):
                tags.append(t[4:])
            else:
                return None, "%d번째 줄: 모르는 조건 '%s'" % (n, t)
        if req:
            rule["require"] = req
        if users or groups:
            rule["users"] = {"users": users, "groups": groups}
        if tags:
            rule["tags"] = tags
        rules.append(rule)
    if not rules:
        return None, "규칙이 하나도 없습니다 (ACL 을 끄는 것은 이 화면에서 하지 않습니다)"
    return rules, None


def view_acl(c, csrf=None, draft=None):
    r = c.call("acl_get")
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    if not r.get("enabled"):
        return empty("ACL 이 꺼져 있습니다 (터널 대역 안까지만 닿습니다).")
    rows = []
    for i, rule in enumerate(r.get("rules") or []):
        u = rule.get("users") or {}
        who = "".join('<span class="chip">%s</span>' % e(n) for n in u.get("users", [])) + \
            "".join('<span class="chip">@%s</span>' % e(n) for n in u.get("groups", []))
        req = rule.get("require") or rule.get("requirements")
        cond = (req_chips(req) if req else "") + who + (tag_chips(rule.get("tags")) if rule.get("tags") else "")
        allow = rule.get("action") == "allow"
        rows.append('<tr><td class="muted">%d</td><td class="mono">%s</td><td class="mono">%s</td><td><span class="chip mono">%s</span>'
                    '</td><td class="mono">%s</td><td>%s</td><td>%s</td></tr>' % (
                        i + 1, e(rule.get("src")), e(rule.get("dst")), e(rule.get("proto")), e(rule.get("dport")),
                        badge("ok" if allow else "bad", "허용 allow" if allow else "거부 deny"),
                        cond or '<span class="muted">—</span>'))
    text = draft if draft is not None else "\n".join(rule_line(x) for x in r.get("rules") or [])
    edit = ('<h2>규칙 고치기</h2><div class="card pad"><form method="post" action="/acl/set"><input type="hidden" name="csrf" value="%s">'
            '<textarea name="rules" rows="%d" spellcheck="false">%s</textarea>'
            '<p class="help">한 줄에 규칙 하나, 파일과 같은 모양: <code>출발지 목적지 프로토콜 포트 allow|deny '
            '[firewall=on antivirus=on disk=on min-build=N user=이름 group=이름 tag=역할]</code>. 저장하면 서버가 '
            '바로 다시 읽습니다. 맨 끝에 <code>any any any any deny</code> 를 두는 것을 잊지 마세요.</p>'
            '<button class="btn primary">저장하고 적용</button></form></div>') % (
        e(csrf), max(6, text.count("\n") + 3), e(text)) if csrf else ""
    note = ""
    if r.get("restart_required"):
        note = '<div class="msg err">ACL 을 켜거나 끈 것은 서버를 다시 시작해야 반영됩니다.</div>'
    return "%s<h2>규칙 <span class=\"muted\">%d</span></h2>%s%s" % (
        note, len(rows), card_table(["#", "출발지", "목적지", "프로토콜", "포트", "판정", "조건"], rows), edit)


EVENTS = [("", "전체"), ("session_open", "세션 시작"), ("session_close", "세션 끝"), ("auth_denied", "인증 거절"),
          ("enrolled", "기기 등록"), ("access", "ACL 판정"), ("login", "사용자 로그인"), ("reload", "정책 다시 읽기")]
EVENT_KIND = {"session_open": "ok", "session_close": "idle", "auth_denied": "bad", "enrolled": "info",
              "access": "warn", "login": "info", "reload": "info"}


def view_audit(c, q):
    args = {"lines": 200}
    if q.get("event"):
        args["event"] = q["event"]
    r = c.call("audit", **args)
    if not r.get("ok"):
        return '<div class="msg err">%s</div>' % e(r.get("error"))
    cur = q.get("event", "")
    filters = "".join('<a href="/audit%s"%s>%s</a>' % ("?event=" + urllib.parse.quote(v) if v else "",
                                                       ' class="on"' if v == cur else "", e(n)) for v, n in EVENTS)
    names = dict(EVENTS)
    rows = []
    for ev in reversed(r.get("events", [])):
        kind = ev.get("event") or ""
        rest = "".join('<span class="kv"><i>%s</i> <code>%s</code></span>' % (
            e(k), e(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v))
            for k, v in ev.items() if k not in ("time", "event"))
        rows.append('<tr><td class="mono" style="white-space:nowrap">%s</td><td>%s<div class="id">%s</div></td><td>%s</td></tr>' % (
            e((ev.get("time") or "").replace("T", " ").rstrip("Z")), badge(EVENT_KIND.get(kind, "idle"), names.get(kind, kind)),
            e(kind), rest))
    table = card_table(["시각 (UTC)", "종류", "내용"], rows) if rows else empty("이 종류의 기록이 없습니다.")
    return '<div class="filters">%s</div>%s' % (filters, table)


def login_view(err=None):
    return ('<div class="card">%s<h1>ztgate 콘솔</h1><p class="lead">Zero Trust Gateway 관리</p>%s'
            '<form method="post" action="/login"><label class="field"><span>관리 토큰</span>'
            '<input type="password" name="token" autocomplete="current-password" autofocus></label>'
            '<button class="btn primary">들어가기</button></form>'
            '<p class="foot">서버에서 <code>sudo cat /etc/ztgate/console.token</code> 으로 읽습니다.</p></div>') % (
        LOGO % (48, 48), '<div class="msg err">%s</div>' % e(err) if err else "")


def bare(text):
    return '<div class="card" style="max-width:420px;padding:28px">%s<p>%s</p></div>' % (LOGO % (36, 36), e(text))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ztgate-console"
    console = None
    timeout = 30        # 요청을 끝까지 보내지 않고 붙잡고 있는 연결은 이만큼 뒤에 끊는다

    def setup(self):
        # TLS 핸드셰이크는 이 연결의 스레드에서 한다. 듣는 소켓에서 하면 accept 가 그 동안 멈춰, 연결만
        # 열고 아무것도 보내지 않는 상대 하나가 콘솔 전체를 세운다.
        self.request.settimeout(self.timeout)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

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
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.console.secure:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
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
            self.send(200 if url.path in ("/", "/login") else 401, page("/login", login_view()))
            return
        views = {"/": lambda: view_overview(c), "/devices": lambda: view_devices(c, csrf),
                 "/enroll": lambda: view_enroll(c, csrf), "/acl": lambda: view_acl(c, csrf), "/audit": lambda: view_audit(c, q)}
        if url.path not in views:
            self.send(404, page(url.path, empty("없는 페이지입니다."), csrf))
            return
        msg = None
        if q.get("ok"):
            msg = ("ok", q["ok"])
        elif q.get("err"):
            msg = ("err", q["err"])
        self.send(200, page(url.path, views[url.path](), csrf, msg))

    def do_POST(self):
        c = self.console
        # 음수면 read(-1) 이 연결이 닫힐 때까지 읽어 크기 제한을 비켜 간다.
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0:
            self.send(400, page("/", bare("Content-Length 가 맞지 않습니다.")))
            return
        if n > 16384:
            self.send(413, page("/", bare("요청이 너무 큽니다.")))
            return
        form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode("utf-8", "replace")))
        path = urllib.parse.urlsplit(self.path).path

        if path == "/login":
            sid = c.login(form.get("token", ""))
            if sid is None:
                self.send(403, page("/login", login_view("토큰이 맞지 않습니다.")))
                return
            flags = "HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s" % (SESSION_TTL, "; Secure" if c.secure else "")
            self.redirect("/", {"Set-Cookie": "ztgate_session=%s; %s" % (sid, flags)})
            return

        sid = self.cookie()
        csrf = c.check(sid)
        if csrf is None or not hmac.compare_digest(form.get("csrf", ""), csrf):
            self.send(403, page("/login", login_view("세션이 끝났거나 요청이 이 콘솔에서 온 것이 아닙니다.")))
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
        if path == "/acl/set":
            rules, err = parse_rules(form.get("rules", ""))
            if err is None:
                r = c.call("acl_set", rules=rules)
                if r.get("ok"):
                    self.redirect("/acl?" + urllib.parse.urlencode({"ok": "ACL 을 저장했습니다 (%d 규칙)" % len(rules)}))
                    return
                err = r.get("error") or "실패"
            # 고친 글을 잃지 않게 그대로 다시 보여 준다.
            self.send(400, page("/acl", view_acl(c, csrf, draft=form.get("rules", "")), csrf, ("err", err)))
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
        self.send(404, page(path, empty("없는 동작입니다."), csrf))

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
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    elif host not in ("127.0.0.1", "localhost", "::1"):
        print("console: listening on %s without TLS — the token and cookies cross the network in clear" % host,
              file=sys.stderr)
    print("console: http%s://%s/" % ("s" if a.tls_cert else "", a.listen), file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
