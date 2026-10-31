#!/usr/bin/env python3
"""ztgate 웹 관리 콘솔. 표준 라이브러리만 쓴다.

    ztgate_console.py [-l 127.0.0.1:9470] [--ctl /usr/sbin/ztgate_ctl] [--token-file /etc/ztgate-console/console.token]
                      [--users-file /etc/ztgate-console/console.users] [--tls-cert cert.pem --tls-key key.pem]
    ztgate_console.py user add <이름> --role admin|viewer [--totp] [--password-stdin]
    ztgate_console.py user del <이름>
    ztgate_console.py user list

브라우저로 지금 붙어 있는 세션, 기기 목록, 등록 코드, ACL, 감사 로그를 보고 기기 지우기 / 등록 코드
만들기와 거두기를 한다. 일은 모두 ztgate_ctl(관리 헬퍼, mcp/ctl.cjs)에 넘긴다 — 검증과 파일 잠금,
서버 다시 읽기가 한 곳에 있다. MCP 서버와 같은 길이다.

누가 들어오는가
  - 기본은 127.0.0.1 에서만 듣는다. 밖에서는 SSH 포워딩(ssh -L 9470:127.0.0.1:9470 서버)으로 들어오거나,
    --tls-cert / --tls-key 로 TLS 를 켜고 -l 0.0.0.0:9470 으로 연다.
  - 관리자마다 계정이 있다 (--users-file, `ztgate_console.py user add`). 토큰과 계정은 서버(ztgate 계정)가
    쓰는 /etc/ztgate 밖, root 만 여는 /etc/ztgate-console 에 둔다. 비밀번호는 scrypt 로만 남고,
    --totp 로 만든 계정은 인증 앱의 6자리 코드도 맞아야 한다. 역할은 admin(바꾸기)과 viewer(보기만).
    바꾸는 일은 감사 로그에 console:<이름> 으로 남는다 (ztgate_ctl 이 쓴다).
  - 계정이 하나도 없을 때만 토큰 하나로 들어온다 (처음 설치, 비상용). 처음 뜰 때 --token-file 에 무작위
    값을 만들어 둔다 (600, root 전용). 관리자는 `sudo cat /etc/ztgate-console/console.token` 으로 읽는다.
  - 세션 쿠키는 HttpOnly, SameSite=Strict (TLS 면 Secure). 바꾸는 요청(POST)은 세션마다의 CSRF 값이
    맞아야 받는다. 로그인 실패는 출발지 주소마다 1초에 한 번까지만 받는다.

ztgate_ctl 이 root 로만 돌므로 이 콘솔도 root 로 돈다 (tools/console/ztgate-console.service).
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import html
import http.server
import json
import os
import re
import secrets
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse

SESSION_TTL = 8 * 3600
CTL_TIMEOUT = 60
CTL_SILENT = "관리 도구(ztgate_ctl)가 답하지 않았습니다. 서버의 콘솔 로그(journalctl -u ztgate-console)를 보세요."

# ztgate_ctl 은 영어로 답한다 (MCP 와 같이 쓴다). 자주 나오는 것만 옮기고, 나머지는 원문을 그대로 붙인다.
CTL_ERRORS = [
    (r"tunnel_ip (\S+) is already assigned", "터널 주소 {0} 는 이미 다른 기기에 배정되어 있습니다."),
    (r"tunnel_ip (\S+) is reserved by a pending enrollment code", "터널 주소 {0} 는 기다리는 등록 코드가 맡아 두었습니다."),
    (r"tunnel_ip (\S+) is the server's own tunnel address", "터널 주소 {0} 는 서버 자신의 주소입니다."),
    (r"tunnel_ip must be an IPv4 address", "터널 주소는 10.0.0.5 같은 IPv4 주소로 적어 주세요."),
    (r"no free address left in the tunnel subnet", "터널 대역에 남은 주소가 없습니다."),
    (r"device list is full \(max (\d+)", "기기 목록이 가득 찼습니다 (기다리는 등록까지 최대 {0}대)."),
    (r"too many pending enrollments \(max (\d+)\)",
     "기다리는 등록 코드가 너무 많습니다 (최대 {0}개). 하나를 거두거나 만료되기를 기다리세요."),
    (r"the device files are being changed by the server", "서버가 기기 파일을 고치는 중입니다. 잠시 뒤에 다시 해 주세요."),
    (r"cannot lock the device files", "기기 파일을 잠그지 못했습니다. 잠시 뒤에 다시 해 주세요."),
    (r"this server takes its configuration from (.+); change it there",
     "이 서버는 {0} 의 설정을 받는 부 서버입니다. 설정은 주 서버에서 고칩니다."),
    (r"no device with this id", "이 ID 의 기기가 없습니다. 이미 지워졌을 수 있습니다."),
    (r"no pending enrollment with this id", "이 등록 코드가 없습니다. 이미 쓰였거나 만료됐을 수 있습니다."),
    (r"label must be", "이름은 영문, 숫자, 빈칸, _ . - 로 1~32자여야 합니다."),
    (r"too many rules \(max (\d+)\)", "규칙이 너무 많습니다 (최대 {0}개)."),
    (r"rule (\d+): (.+)", "{n}번째 규칙이 맞지 않습니다: {1}"),
    (r"sent SIGHUP but the server did not report a reload", "3초 안에 다시 읽었다는 기록이 없습니다."),
    (r"server rejected the device file", "서버가 기기 파일을 받아들이지 않고 이전 목록을 씁니다."),
    (r"server rejected the ACL file", "서버가 ACL 파일을 받아들이지 않고 이전 규칙을 씁니다."),
]
CTL_ERRORS = [(re.compile(rx), text) for rx, text in CTL_ERRORS]


def ko_error(text, lead="관리 도구가 거절했습니다: "):
    text = str(text or "").strip()
    for rx, ko in CTL_ERRORS:
        m = rx.match(text)
        if m:
            g = m.groups()
            return ko.format(*g, n=int(g[0]) + 1 if g and g[0].isdigit() else "")
    return lead + (text or "까닭을 알리지 않았습니다")


ROLES = {"admin": "관리자", "viewer": "조회 전용"}
NAME_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
SCRYPT = (16384, 8, 1)


def _b64(b):
    return base64.b64encode(b).decode()


def hash_password(password):
    salt = secrets.token_bytes(16)
    n, r, p = SCRYPT
    h = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(h))


def password_ok(password, stored):
    try:
        kind, n, r, p, salt, want = stored.split("$")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(base64.b64decode(want)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, base64.b64decode(want))


def totp(secret, when, step=0):
    """RFC 6238 (SHA-1, 30초, 6자리). 인증 앱이 보여 주는 코드."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(when // 30) + step), "sha1").digest()
    off = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7fffffff) % 1000000)


def totp_ok(secret, code, when):
    return any(hmac.compare_digest(totp(secret, when, step), code) for step in (-1, 0, 1))


def load_users(path):
    """{이름: (역할, 비밀번호 해시, TOTP 비밀 또는 "")}. 파일이 없으면 빈 dict."""
    users = {}
    try:
        with open(path) as f:
            for line in f:
                t = line.split("#", 1)[0].split()
                if len(t) in (3, 4) and NAME_RE.match(t[0]) and t[1] in ROLES:
                    users[t[0]] = (t[1], t[2], t[3] if len(t) == 4 else "")
    except FileNotFoundError:
        pass
    return users


def save_users(path, users):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# ztgate 콘솔 계정: 이름 역할(admin|viewer) 비밀번호(scrypt) [TOTP 비밀]\n")
        for name, (role, h, secret) in sorted(users.items()):
            f.write(" ".join(x for x in (name, role, h, secret) if x) + "\n")
    os.replace(tmp, path)


class Session:
    __slots__ = ("csrf", "expires", "user", "role", "by_token")

    def __init__(self, user, role, now, by_token=False):
        self.csrf = secrets.token_urlsafe(24)
        self.expires = now + SESSION_TTL
        self.user = user
        self.role = role
        self.by_token = by_token

    @property
    def admin(self):
        return self.role == "admin"

    @property
    def who(self):
        return "%s · %s" % (self.user, ROLES[self.role])


class Console:
    def __init__(self, ctl, token, secure, users_path=None):
        self.ctl = ctl
        self.token = token
        self.secure = secure
        self.users_path = users_path
        self.sessions = {}          # 쿠키 -> Session
        self.lock = threading.Lock()
        self.fails = {}             # 출발지 주소 -> 마지막 실패 시각

    def users(self):
        return load_users(self.users_path) if self.users_path else {}

    def call(self, cmd, actor=None, **args):
        """ztgate_ctl 에 명령 하나. 결과 dict (ok, error ...). actor 는 감사 로그에 남는 사람."""
        req = dict(args, cmd=cmd)
        if actor:
            req["actor"] = "console:" + actor
        try:
            p = subprocess.run([self.ctl], input=json.dumps(req), capture_output=True, text=True,
                               timeout=CTL_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as ex:
            sys.stderr.write("console: %s %s: %s\n" % (self.ctl, cmd, ex))
            return {"ok": False, "error": CTL_SILENT}
        if p.stderr.strip():
            sys.stderr.write("console: %s %s: %s\n" % (self.ctl, cmd, p.stderr.strip()))
        try:
            r = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            r = None
        if not isinstance(r, dict):
            return {"ok": False, "error": CTL_SILENT}
        if not r.get("ok"):
            r["error"] = ko_error(r.get("error"))
        return r

    def login(self, addr, form):
        """(쿠키 또는 None, 실패했을 때 보여 줄 글). 계정이 있으면 이름 / 비밀번호(/ 코드), 없으면 토큰."""
        now = time.time()
        with self.lock:
            if now - self.fails.get(addr, 0.0) < 1.0:
                return None, "잠시 뒤에 다시 해 주세요."
        users = self.users()
        who = None
        if users:
            u = users.get(form.get("name", "").strip())
            if u and password_ok(form.get("password", ""), u[1]) and \
                    (not u[2] or totp_ok(u[2], form.get("code", "").strip(), now)):
                who = (form["name"].strip(), u[0], False)
            err = "이름, 비밀번호 또는 인증 코드가 맞지 않습니다."
        else:
            if hmac.compare_digest(form.get("token", "").encode(), self.token.encode()):
                who = ("token", "admin", True)
            err = "토큰이 맞지 않습니다."
        with self.lock:
            if who is None:
                if len(self.fails) > 4096:
                    self.fails = {k: v for k, v in self.fails.items() if now - v < 1.0}
                self.fails[addr] = now
                return None, err
            sid = secrets.token_urlsafe(32)
            self.sessions = {k: v for k, v in self.sessions.items() if v.expires > now}
            self.sessions[sid] = Session(who[0], who[1], now, by_token=who[2])
            return sid, None

    def check(self, sid):
        """로그인한 세션이면 Session, 아니면 None."""
        # 계정 파일은 요청마다 다시 읽는다 (몇 줄이다). 지우거나 역할을 바꾼 계정의 세션이 8시간 동안
        # 예전 권한으로 남지 않게 하고, 계정이 하나라도 생기면 토큰으로 연 세션도 닫는다.
        users = self.users()
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s.expires < time.time() or \
                    (s.by_token or users.get(s.user, ("",))[0] != s.role if users else not s.by_token):
                self.sessions.pop(sid, None)
                return None
            return s

    def logout(self, sid):
        with self.lock:
            self.sessions.pop(sid, None)


# ---- 화면 -----------------------------------------------------------------------
# 색과 간격은 docs/design/tokens.md 를 따른다. 밖에서 받아 오는 파일(글꼴, 스크립트, 그림)은 없다.
# 어두운 테마의 --on-accent 는 짙은 글씨다. 밝아진 accent(#5B8FD6) 위의 흰 글씨는 대비가 3.3:1 밖에 안 된다.

CSS = """
:root{--navy-950:#0B1626;--navy-900:#0F1E36;--navy-800:#16294A;--bg:#F5F7FA;--surface:#FFFFFF;--surface-2:#EEF2F7;
--border:#DCE3EC;--text:#1A2333;--muted:#5B6678;--accent:#1E4E8C;--accent-hover:#173F73;--accent-soft:#E6EEF8;
--teal:#2A9D8F;--teal-text:#1F7A6F;--teal-soft:#E3F4F1;--warn:#C27C0E;--warn-soft:#FBF1DE;--danger:#B4232F;
--danger-soft:#FBE9EA;--idle:#8A95A8;--on-accent:#fff;--shadow:0 1px 2px rgba(15,30,54,.06),0 1px 8px rgba(15,30,54,.04);color-scheme:light}
:root[data-theme=dark]{--bg:#0B1626;--surface:#13233A;--surface-2:#1A2D48;--border:#24395A;--text:#E6ECF5;--muted:#9AA8BD;
--accent:#5B8FD6;--accent-hover:#78A5E2;--accent-soft:#1B3254;--teal:#3FBFAE;--teal-text:#3FBFAE;--teal-soft:#123A3A;
--warn:#E0A33A;--warn-soft:#3A2C12;--danger:#E5636D;--danger-soft:#3D1A20;--idle:#6F7D93;--on-accent:#0B1626;--shadow:none;
color-scheme:dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0B1626;--surface:#13233A;--surface-2:#1A2D48;
--border:#24395A;--text:#E6ECF5;--muted:#9AA8BD;--accent:#5B8FD6;--accent-hover:#78A5E2;--accent-soft:#1B3254;
--teal:#3FBFAE;--teal-text:#3FBFAE;--teal-soft:#123A3A;--warn:#E0A33A;--warn-soft:#3A2C12;--danger:#E5636D;
--danger-soft:#3D1A20;--idle:#6F7D93;--on-accent:#0B1626;--shadow:none;color-scheme:dark}}
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
.top{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:18px 32px;border-bottom:1px solid var(--border);background:var(--surface)}
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
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
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
.msg.warn{background:var(--warn-soft);color:var(--text);border-color:color-mix(in srgb,var(--warn) 45%,transparent)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
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
.callout .code{font:600 22px/1.2 ui-monospace,Consolas,monospace;letter-spacing:1.5px;color:var(--text);user-select:all;overflow-wrap:anywhere}
.callout p{margin:4px 0 0;color:var(--muted);font-size:13px}
textarea{width:100%;font-size:13px;line-height:1.6;padding:12px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2);color:var(--text);resize:vertical}
.help{color:var(--muted);font-size:12.5px;margin:10px 0 14px}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.filters a{padding:5px 12px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-decoration:none;font-size:12.5px}
.filters a.on{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
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
            "try{localStorage.setItem(k,n)}catch(x){}};window.ztCopy=function(el,id){var t=el.getAttribute('data-copy'),"
            "l=el.dataset.label||(el.dataset.label=el.textContent);function say(m){el.textContent=m;"
            "document.getElementById('live').textContent=m;clearTimeout(el.ztT);el.ztT=setTimeout(function(){"
            "el.textContent=l},2000)}function sel(){var r=document.createRange();r.selectNodeContents("
            "document.getElementById(id));var s=getSelection();s.removeAllRanges();s.addRange(r);"
            "say('골라 두었습니다. Ctrl+C 로 복사하세요')}if(navigator.clipboard&&isSecureContext)"
            "navigator.clipboard.writeText(t).then(function(){say('복사했습니다')},sel);else sel()}})();")

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


def note(kind, text):
    """kind 는 err, warn, ok."""
    return '<div class="msg %s" role="alert">%s</div>' % (kind, e(text))


def badge(kind, text):
    return '<span class="badge %s">%s</span>' % (kind, e(text))


def empty(text):
    return '<div class="card empty">%s%s</div>' % (ICONS["empty"], e(text))


def card_table(head, rows):
    return ('<div class="card scroll"><table class="tbl"><tr>%s</tr>%s</table></div>'
            % ("".join("<th%s>%s</th>" % (' class="num"' if h.startswith(">") else "", e(h.lstrip(">"))) for h in head),
               "".join(rows)))


def page(path, body, csrf=None, msg=None, who=""):
    top = note(msg[0], msg[1]) if msg else ""
    head = ('<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>ztgate 콘솔</title>'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">'
            '<style>%s</style><script>%s</script></head>') % (CSS, THEME_JS)
    if not csrf:
        return head + '<body><div class="login">%s%s</div></body></html>' % (top, body)
    nav = "".join('<a href="%s"%s>%s<span>%s</span></a>' % (
        p, ' class="on" aria-current="page"' if p == path else "", ICONS[p], n)
                  for p, n in PAGES)
    title = dict(PAGES).get(path, "없는 페이지")
    return head + (
        '<body><div class="app"><aside class="side"><div class="brand">%s<div><b>ztgate</b><small>Zero Trust Gateway</small>'
        '</div></div><nav class="nav">%s</nav><div class="side-foot">관리 콘솔 · 터널 안에서만</div></aside>'
        '<div class="main"><header class="top"><h1>%s</h1><span class="sub">%s</span><div class="right">'
        '<span class="muted" style="font-size:13px;margin-right:4px">%s</span>'
        '<button class="btn icon" type="button" onclick="ztTheme()" title="밝게 / 어둡게">%s</button>'
        '<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="%s">'
        '<button class="btn">%s로그아웃</button></form></div></header><main class="content">%s%s</main></div></div>'
        '<div id="live" class="sr" aria-live="polite"></div></body></html>') % (
            LOGO % (34, 34), nav, e(title), e(SUBTITLE.get(path, "")), e(who), ICONS["theme"], e(csrf),
            ICONS["logout"], top, body)


def posture_chips(p):
    out = []
    for key, name in (("firewall", "방화벽"), ("antivirus", "백신"), ("disk", "디스크")):
        v = p.get(key)
        cls = "ok" if v == "on" else "bad" if v == "off" else ""
        out.append('<span class="chip %s" title="%s=%s">%s</span>' % (cls, key, e(v), name))
    if p.get("os_build"):
        out.append('<span class="chip mono">build %s</span>' % e(p.get("os_build")))
    return "".join(out)


DENY_KINDS = [("deny_unknown_device", "모르는 기기"), ("deny_bad_auth", "인증"), ("deny_tun_ip", "터널 주소"),
              ("deny_posture", "포스처")]


def view_overview(c, st):
    if not st.get("ok"):
        return note("err", st.get("error"))
    cnt = st.get("counters", {})
    sessions = st.get("sessions", [])
    denied = sum(cnt.get(k, 0) for k, _ in DENY_KINDS)
    run = badge("ok", "실행 중") if st.get("running") else badge("bad", "멈춤")
    acl = st.get("acl", {})
    cards = [
        ("서버", run, "vpn_server", "hl"),
        ("연결된 세션", num(len(sessions)), "터널이 열린 기기", "hl"),
        ("등록된 기기", num(st.get("registered_devices")), "", ""),
        ("ACL 규칙", num(acl.get("rules", 0)), "첫 일치 · 기본 거부", "") if acl.get("enabled") else
        ("ACL", "꺼짐", "ACL 꺼짐 · 터널 대역 안은 모두 닿음", ""),
        ("핸드셰이크 성공", num(cnt.get("handshake_ok", 0)), "서버가 뜬 뒤", ""),
        ("거절", num(denied), " · ".join("%s %s" % (n, num(cnt.get(k, 0))) for k, n in DENY_KINDS),
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
    if rows:
        table = card_table(["터널 주소", "기기", "사용자", "출발지", "태그", "포스처", ">받음 / 보냄", ">연결된 지"], rows)
    elif not st.get("running"):
        table = empty("서버가 멈춰 있어 세션이 없습니다.")
    elif st.get("sessions_error"):
        table = note("err", "세션 정보를 받지 못했습니다 (서버가 상태 소켓에 답하지 않았습니다).")
    else:
        table = empty("붙어 있는 세션이 없습니다.")
    stopped = ""
    if not st.get("running"):
        stopped = note("err", "서버가 멈춰 있습니다" + (" (%s)" % st["last_result"] if st.get("last_result") else "") +
                       ". 서버에서 sudo systemctl start ztgate 로 다시 띄웁니다.")
    return '%s<div class="stats">%s</div><h2>세션 <span class="muted">%d</span></h2>%s' % (stopped, out, len(rows), table)


def confirm(text):
    """onsubmit 에 넣을 확인 창. 글은 JS 문자열로 만든 뒤 속성 값으로 한 번 더 escape 한다."""
    return 'return confirm(%s)' % json.dumps(text, ensure_ascii=False)


def view_devices(c, csrf, st):
    r = c.call("device_list")
    if not r.get("ok"):
        return note("err", r.get("error"))
    live = st.get("ok") and (not st.get("running") or "sessions" in st)
    online = {s.get("device_id") for s in st.get("sessions", [])} if live else set()
    rows = []
    for d in r.get("devices", []):
        on = d.get("id") in online
        key = "P-256" if d.get("key_type") == "p256" else "공유 키" if d.get("key_type") else ""
        ask = confirm("'%s' 기기를 지울까요? 다음 keepalive 에서 끊깁니다." % (d.get("label") or (d.get("id") or "")[:16]))
        actions = ('<a class="btn sm" href="/devices/edit?id=%s">편집</a> '
                   '<form class="inline" method="post" action="/devices/remove" onsubmit="%s">'
                   '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                   '<button class="btn sm danger">지우기</button></form>') % (
            e(d.get("id")), e(ask), e(csrf), e(d.get("id"))) if csrf else ""
        state = (badge("ok", "연결됨") if on else badge("idle", "끊김")) if live else badge("idle", "알 수 없음")
        rows.append('<tr><td style="white-space:nowrap"><span class="dot%s"></span><b>%s</b></td><td><span class="id" title="%s">%s…</span></td>'
                    '<td class="mono">%s</td><td>%s</td><td style="white-space:nowrap">%s</td><td>%s</td><td>%s</td>'
                    '<td class="num" style="white-space:nowrap">%s</td></tr>' % (
                        " on" if on else "", e(d.get("label") or "(이름 없음)"), e(d.get("id")), e((d.get("id") or "")[:16]),
                        e(d.get("tunnel_ip")), state, e(key), req_chips(d.get("requirements")), tag_chips(d.get("tags")), actions))
    add = ('<a class="btn primary" style="margin-left:auto" href="/enroll">%s새 기기 등록</a>' % ICONS["plus"]) if csrf else ""
    head = ('<div class="row" style="margin-bottom:14px"><h2 style="margin:0">기기 <span class="muted">%d</span></h2>'
            '%s</div>') % (len(rows), add)
    if not live:
        head += note("warn", "서버에서 세션 정보를 받지 못해 연결 상태를 보여 주지 못합니다.")
    table = card_table(["이름", "ID", "터널 주소", "상태", "키", "접속 조건", "태그", ""], rows) if rows else \
        empty("등록된 기기가 없습니다. [등록 코드]에서 코드를 만들어 기기에 넣으세요.")
    return head + table


def view_device_edit(c, csrf, dev_id, draft=None):
    """draft 는 저장에 실패한 양식. 있으면 그 값으로 채운다."""
    r = c.call("device_list")
    if not r.get("ok"):
        return note("err", r.get("error"))
    d = next((x for x in r.get("devices", []) if x.get("id") == dev_id), None)
    if d is None:
        return empty("이 ID 의 기기가 없습니다.")
    req = d.get("requirements") or {}
    label, tunnel_ip, tags = d.get("label") or "", d.get("tunnel_ip"), " ".join(d.get("tags") or [])
    if draft is not None:
        req = {k: bool(draft.get(k)) for k in ("firewall", "antivirus", "disk")}
        req["min_build"] = draft.get("min_build")
        label, tunnel_ip, tags = draft.get("label", ""), draft.get("tunnel_ip", ""), draft.get("tags", "")
    checks = "".join('<label><input type="checkbox" name="%s"%s> %s</label>' % (k, " checked" if req.get(k) else "", n)
                     for k, n in (("firewall", "방화벽"), ("antivirus", "백신"), ("disk", "디스크 암호화")))
    return ('<div class="card pad" style="max-width:560px"><h2>%s</h2><p class="id">%s</p>'
            '<form method="post" action="/devices/update"><input type="hidden" name="csrf" value="%s">'
            '<input type="hidden" name="id" value="%s">'
            '<label class="field"><span>이름</span><input name="label" value="%s"></label>'
            '<label class="field"><span>터널 주소</span><input name="tunnel_ip" value="%s"></label>'
            '<label class="field"><span>태그 (빈칸으로 나눔)</span><input name="tags" value="%s"></label>'
            '<div class="field"><span>접속 조건</span><div class="checks">%s</div></div>'
            '<label class="field"><span>최소 OS 빌드 (0 이면 보지 않음)</span><input type="number" name="min_build" value="%s" min="0"></label>'
            '<div class="row"><button class="btn primary">저장</button><a class="btn" href="/devices">취소</a></div>'
            '</form></div>') % (
        e(d.get("label") or "(이름 없음)"), e(dev_id), e(csrf), e(dev_id), e(label), e(tunnel_ip), e(tags), checks,
        e(req.get("min_build") or 0))


def view_enroll(c, csrf, made=None, draft=None):
    """made 는 방금 만든 코드(enroll_create 의 답), draft 는 만들지 못한 양식."""
    r = c.call("enroll_list")
    rows = []
    for p in r.get("pending", []) if r.get("ok") else []:
        left = max(0, p.get("expires_in_sec", 0))
        ask = confirm("'%s' 의 등록 코드를 거둘까요? 이 코드로는 더 등록할 수 없습니다." % (p.get("label") or p.get("tunnel_ip")))
        revoke = ('<form class="inline" method="post" action="/enroll/revoke" onsubmit="%s">'
                  '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">'
                  '<button class="btn sm danger">거두기</button></form>') % (e(ask), e(csrf), e(p.get("id"))) if csrf else ""
        rows.append('<tr><td><b>%s</b></td><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">%s</td></tr>' % (
                        e(p.get("label") or "(이름 없음)"), e(p.get("tunnel_ip")), req_chips(p.get("requirements")),
                        tag_chips(p.get("tags")), badge("warn" if left < 180 else "idle",
                                                        "%d분 남음" % (left // 60) if left >= 60 else "1분 안에 끝남"),
                        revoke))
    code = ""
    if made:
        code = ('<div class="callout"><div style="flex:1"><div class="muted" style="font-size:12.5px">등록 코드 · %s 에 배정</div>'
                '<div class="code" id="code">%s</div><p>한 번만 쓸 수 있고 곧 만료됩니다. 기기에서 '
                '<code>vpn_client enroll &lt;서버&gt; &lt;포트&gt; &lt;코드&gt;</code> 또는 GUI 의 [기기 등록]</p></div>'
                '<button class="btn" type="button" data-copy="%s" onclick="ztCopy(this,\'code\')">복사</button></div>') % (
            e(made.get("enrollment", {}).get("tunnel_ip")), e(made.get("code")), e(made.get("code")))
        link = made.get("invite")
        if link:
            code += ('<div class="callout"><div style="flex:1;min-width:0"><div class="muted" style="font-size:12.5px">초대 링크</div>'
                     '<div class="mono" id="invite" style="overflow-wrap:anywhere">%s</div><p>Windows 에서 누르면 서버와 코드가 채워진 '
                     '등록 창이 열립니다. 코드가 들어 있으니 그 사람에게만 보내세요.</p></div>'
                     '<button class="btn" type="button" data-copy="%s" onclick="ztCopy(this,\'invite\')">복사</button></div>') % (
                         e(link), e(link))
        elif made.get("invite_error"):
            code += note("warn", "초대 링크를 만들지 못했습니다. /etc/ztgate/server.env 의 PUBLIC_ADDRESS 는 이름이나 주소를 "
                         "쉼표로 넷까지 적습니다 (예: vpn.example.com). 코드는 그대로 쓸 수 있습니다.")
        else:
            code += ('<p class="muted">서버의 <code>/etc/ztgate/server.env</code> 에 <code>PUBLIC_ADDRESS=vpn.example.com</code> '
                     '을 적으면 누르기만 하면 되는 초대 링크도 함께 나옵니다.</p>')
    f = draft or {}
    checks = "".join('<label><input type="checkbox" name="%s"%s> %s</label>' % (k, " checked" if f.get(k) else "", n)
                     for k, n in (("firewall", "방화벽"), ("antivirus", "백신"), ("disk", "디스크 암호화")))
    form = ('<div class="card pad"><h2>새 등록 코드</h2><form method="post" action="/enroll/create">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label class="field"><span>이름</span><input name="label" placeholder="laptop-kim" value="%s"></label>'
            '<label class="field"><span>터널 주소</span><input name="tunnel_ip" placeholder="비우면 자동으로 배정" value="%s"></label>'
            '<label class="field"><span>태그 (빈칸으로 나눔)</span><input name="tags" placeholder="eng laptop" value="%s"></label>'
            '<div class="field"><span>접속 조건</span><div class="checks">%s</div></div>'
            '<label class="field"><span>유효 시간 (분)</span><input type="number" name="ttl" value="%s" min="1" max="1440"></label>'
            '<button class="btn primary">%s코드 만들기</button></form></div>') % (
        e(csrf), e(f.get("label", "")), e(f.get("tunnel_ip", "")), e(f.get("tags", "")), checks, e(f.get("ttl") or 15),
        ICONS["plus"]) if csrf else \
        '<div class="card pad"><h2>새 등록 코드</h2><p class="muted">이 계정이나 이 서버에서는 코드를 만들 수 없습니다.</p></div>'
    if not r.get("ok"):
        pending = note("err", r.get("error"))
    elif rows:
        pending = card_table(["이름", "터널 주소", "접속 조건", "태그", "남은 시간", ""], rows)
    else:
        pending = empty("기다리는 등록 코드가 없습니다.")
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
        return note("err", r.get("error"))
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
            '<label class="field"><span>규칙 (한 줄에 하나)</span>'
            '<textarea name="rules" rows="%d" spellcheck="false">%s</textarea></label>'
            '<p class="help">한 줄에 규칙 하나, 파일과 같은 모양: <code>출발지 목적지 프로토콜 포트 allow|deny '
            '[firewall=on antivirus=on disk=on min-build=N user=이름 group=이름 tag=역할]</code>. 저장하면 서버가 '
            '바로 다시 읽습니다. 맨 끝에 <code>any any any any deny</code> 를 두는 것을 잊지 마세요.</p>'
            '<button class="btn primary">저장하고 적용</button></form></div>') % (
        e(csrf), max(6, text.count("\n") + 3), e(text)) if csrf else ""
    restart = ""
    if r.get("restart_required"):
        restart = note("err", "ACL 을 켜거나 끈 것은 서버를 다시 시작해야 반영됩니다.")
    return "%s<h2>규칙 <span class=\"muted\">%d</span></h2>%s%s" % (
        restart, len(rows), card_table(["#", "출발지", "목적지", "프로토콜", "포트", "판정", "조건"], rows), edit)


EVENTS = [("", "전체"), ("session_open", "세션 시작"), ("session_close", "세션 끝"), ("auth_denied", "인증 거절"),
          ("enrolled", "기기 등록"), ("access", "ACL 판정"), ("login", "사용자 로그인"), ("logout", "사용자 로그아웃"),
          ("reload", "정책 다시 읽기"), ("admin", "관리 작업"), ("deploy", "배포")]
EVENT_KIND = {"session_open": "ok", "session_close": "idle", "auth_denied": "bad", "enrolled": "info",
              "access": "warn", "login": "info", "logout": "idle", "reload": "info", "admin": "info", "deploy": "info"}
# 배포 사건은 끝난 모양에 따라 (mcp/deploy.cjs 의 outcome).
DEPLOY_TONE = {"installed": "ok", "unchanged": "idle", "built": "info", "failed": "warn", "reverted": "warn",
               "interrupted": "warn", "broken": "bad"}


def audit_value(v):
    if isinstance(v, bool):
        return "성공" if v else "실패"
    return json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v


def view_audit(c, q):
    args = {"lines": 200}
    if q.get("event"):
        args["event"] = q["event"]
    r = c.call("audit", **args)
    if not r.get("ok"):
        return note("err", r.get("error"))
    cur = q.get("event", "")
    filters = "".join('<a href="/audit%s"%s>%s</a>' % ("?event=" + urllib.parse.quote(v) if v else "",
                                                       ' class="on"' if v == cur else "", e(n)) for v, n in EVENTS)
    names = dict(EVENTS)
    rows = []
    for ev in reversed(r.get("events", [])):
        kind = ev.get("event") or ""
        rest = "".join('<span class="kv"><i>%s</i> <code>%s</code></span>' % (e(k), e(audit_value(v)))
                       for k, v in ev.items() if k not in ("time", "event"))
        if kind == "admin" and ev.get("ok") is False:
            tone = "bad"
        elif kind == "deploy":
            tone = DEPLOY_TONE.get(ev.get("outcome"), "idle")
        else:
            tone = EVENT_KIND.get(kind, "idle")
        rows.append('<tr><td class="mono" style="white-space:nowrap">%s</td><td>%s<div class="id">%s</div></td><td>%s</td></tr>' % (
            e((ev.get("time") or "").replace("T", " ").rstrip("Z")), badge(tone, names.get(kind, kind)),
            e(kind), rest))
    table = card_table(["시각 (UTC)", "종류", "내용"], rows) if rows else empty("이 종류의 기록이 없습니다.")
    return '<div class="filters">%s</div>%s' % (filters, table)


def login_view(err=None, accounts=False):
    if accounts:
        fields = ('<label class="field"><span>이름</span><input name="name" autocomplete="username" autofocus></label>'
                  '<label class="field"><span>비밀번호</span><input type="password" name="password" autocomplete="current-password"></label>'
                  '<label class="field"><span>인증 코드 (설정한 계정만)</span><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>')
        foot = '계정은 서버에서 <code>ztgate_console.py user add</code> 로 만듭니다.'
    else:
        fields = ('<label class="field"><span>관리 토큰</span>'
                  '<input type="password" name="token" autocomplete="current-password" autofocus></label>')
        foot = ('서버에서 <code>sudo cat /etc/ztgate-console/console.token</code> 으로 읽습니다. 관리자 계정을 만들면 '
                '(<code>ztgate_console.py user add</code>) 토큰 로그인은 닫힙니다.')
    return ('<div class="card">%s<h1>ztgate 콘솔</h1><p class="lead">Zero Trust Gateway 관리</p>%s'
            '<form method="post" action="/login">%s<button class="btn primary">들어가기</button></form>'
            '<p class="foot">%s</p></div>') % (LOGO % (48, 48), note("err", err) if err else "",
                                              fields, foot)


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
        s = c.check(self.cookie())
        if s is None:
            self.send(200 if url.path in ("/", "/login") else 401,
                      page("/login", login_view(accounts=bool(c.users()))))
            return
        st, edit, banner = self.state(s, url.path)
        views = {"/": lambda: view_overview(c, st), "/devices": lambda: view_devices(c, edit, st),
                 "/enroll": lambda: view_enroll(c, edit), "/acl": lambda: view_acl(c, edit), "/audit": lambda: view_audit(c, q)}
        if url.path == "/devices/edit" and edit:
            self.send(200, page("/devices", view_device_edit(c, s.csrf, q.get("id", "")), s.csrf, who=s.who))
            return
        if url.path not in views:
            self.send(404, page(url.path, empty("없는 페이지입니다."), s.csrf, who=s.who))
            return
        msg = next(((k, q[k]) for k in ("err", "warn", "ok") if q.get(k)), None)
        self.send(200, page(url.path, banner + views[url.path](), s.csrf, msg, who=s.who))

    def state(self, s, path):
        """(status 의 답, 바꾸는 양식에 넣을 CSRF 값 또는 None, 화면 위에 붙일 알림).

        조회 전용 계정과 부 서버에서는 바꾸는 단추와 양식을 그리지 않는다. 부 서버의 ztgate_ctl 은 어차피
        거절하고, 고쳐 봐야 다음 동기화가 덮는다."""
        st = self.console.call("status") if path != "/audit" else {}
        primary = st.get("sync_primary")
        if primary:
            return st, None, note("warn", "이 서버는 %s 의 설정을 받는 부 서버입니다. 설정은 주 서버에서 고칩니다." % primary)
        return st, s.csrf if s.admin else None, ""

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
            sid, err = c.login(self.client_address[0], form)
            if sid is None:
                self.send(403, page("/login", login_view(err, accounts=bool(c.users()))))
                return
            flags = "HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s" % (SESSION_TTL, "; Secure" if c.secure else "")
            self.redirect("/", {"Set-Cookie": "ztgate_session=%s; %s" % (sid, flags)})
            return

        sid = self.cookie()
        s = c.check(sid)
        if s is None or not hmac.compare_digest(form.get("csrf", ""), s.csrf):
            self.send(403, page("/login", login_view("세션이 끝났거나 요청이 이 콘솔에서 온 것이 아닙니다.",
                                                     accounts=bool(c.users()))))
            return
        csrf, who = s.csrf, s.who

        if path == "/logout":
            c.logout(sid)
            self.redirect("/", {"Set-Cookie": "ztgate_session=; Max-Age=0; Path=/"})
            return
        if not s.admin:
            self.send(403, page("/", empty("조회 전용 계정은 바꿀 수 없습니다."), csrf, who=who))
            return
        if path == "/devices/remove":
            r = c.call("device_remove", actor=s.user, id=form.get("id", ""))
            self.done("/devices", r, "기기를 지웠습니다")
            return
        if path == "/devices/update":
            args = {"id": form.get("id", ""), "label": form.get("label", "").strip(), "tags": form.get("tags", "").split(),
                    "requirements": {k: True for k in ("firewall", "antivirus", "disk") if form.get(k)}}
            try:
                if int(form.get("min_build") or 0) > 0:
                    args["requirements"]["min_build"] = int(form["min_build"])
            except ValueError:
                pass
            if form.get("tunnel_ip", "").strip():
                args["tunnel_ip"] = form["tunnel_ip"].strip()
            r = c.call("device_update", actor=s.user, **args)
            if not r.get("ok"):
                self.send(400, page("/devices", view_device_edit(c, csrf, args["id"], draft=form), csrf,
                                    ("err", r["error"]), who=who))
                return
            self.done("/devices", r, "기기를 고쳤습니다")
            return
        if path == "/enroll/revoke":
            r = c.call("enroll_revoke", actor=s.user, id=form.get("id", ""))
            self.done("/enroll", r, "등록 코드를 거뒀습니다")
            return
        if path == "/acl/set":
            rules, err = parse_rules(form.get("rules", ""))
            if err is None:
                r = c.call("acl_set", actor=s.user, rules=rules)
                if r.get("ok"):
                    self.done("/acl", r, "ACL 을 저장했습니다 (%d 규칙)" % len(rules))
                    return
                err = r.get("error") or "실패"
            # 고친 글을 잃지 않게 그대로 다시 보여 준다.
            self.send(400, page("/acl", view_acl(c, csrf, draft=form.get("rules", "")), csrf, ("err", err), who=who))
            return
        if path == "/enroll/create":
            args = {"requirements": {k: True for k in ("firewall", "antivirus", "disk") if form.get(k)}}
            for k in ("label", "tunnel_ip"):
                if form.get(k, "").strip():
                    args[k] = form[k].strip()
            if form.get("tags", "").strip():
                args["tags"] = form["tags"].split()
            try:
                args["ttl_minutes"] = int(form.get("ttl") or 15)
            except ValueError:
                args["ttl_minutes"] = 15
            r = c.call("enroll_create", actor=s.user, **args)
            if not r.get("ok"):
                self.send(400, page("/enroll", view_enroll(c, csrf, draft=form), csrf, ("err", r["error"]), who=who))
                return
            # 코드는 이 답에서 한 번만 나온다. 서버가 다시 읽지 못했어도 파일에는 들어갔으니 보여 준다.
            self.send(200, page("/enroll", view_enroll(c, csrf, made=r), csrf, reload_warning(r), who=who))
            return
        self.send(404, page(path, empty("없는 동작입니다."), csrf, who=who))

    def done(self, where, r, ok_text):
        key, text = reload_warning(r) or (("ok", ok_text) if r.get("ok") else ("err", r.get("error") or "실패"))
        self.redirect("%s?%s" % (where, urllib.parse.urlencode({key: text})))


def reload_warning(r):
    """파일은 바꿨지만 서버가 다시 읽지 못한 답이면 ("warn", 글), 아니면 None."""
    if r.get("ok") and r.get("reload_error"):
        return "warn", "저장했지만 서버가 다시 읽지 못했습니다: %s" % ko_error(r["reload_error"], lead="")
    return None


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


def user_command(argv):
    """ztgate_console.py user add|del|list. 비밀번호는 터미널에서 두 번 묻는다 (--password-stdin 이면 표준 입력의 첫 줄)."""
    ap = argparse.ArgumentParser(prog="ztgate_console.py user")
    ap.add_argument("action", choices=("add", "del", "list"))
    ap.add_argument("name", nargs="?")
    ap.add_argument("--role", choices=tuple(ROLES), default="admin")
    ap.add_argument("--totp", action="store_true", help="인증 앱의 6자리 코드도 받는다")
    ap.add_argument("--password-stdin", action="store_true")
    ap.add_argument("--users-file", default="/etc/ztgate-console/console.users")
    a = ap.parse_args(argv)
    users = load_users(a.users_file)
    if a.action == "list":
        for name, (role, _, secret) in sorted(users.items()):
            print("%-20s %-7s%s" % (name, role, "  totp" if secret else ""))
        return 0
    if not a.name or not NAME_RE.match(a.name):
        sys.exit("name: 1-32 of a-z 0-9 _ . -")
    if a.action == "del":
        if users.pop(a.name, None) is None:
            sys.exit("no such user: %s" % a.name)
        save_users(a.users_file, users)
        return 0
    if a.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("password: ")
        if pw != getpass.getpass("again: "):
            sys.exit("the passwords differ")
    if len(pw) < 10:
        sys.exit("password: at least 10 characters")
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=") if a.totp else ""
    users[a.name] = (a.role, hash_password(pw), secret)
    save_users(a.users_file, users)
    if secret:
        print("add this to an authenticator app:")
        print("otpauth://totp/ztgate:%s?secret=%s&issuer=ztgate" % (a.name, secret))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "user":
        sys.exit(user_command(sys.argv[2:]))
    ap = argparse.ArgumentParser(description="ztgate web console")
    ap.add_argument("-l", "--listen", default="127.0.0.1:9470")
    ap.add_argument("--ctl", default="/usr/sbin/ztgate_ctl" if os.path.exists("/usr/sbin/ztgate_ctl") else "/usr/local/sbin/ztgate_ctl")
    ap.add_argument("--token-file", default="/etc/ztgate-console/console.token")
    ap.add_argument("--users-file", default="/etc/ztgate-console/console.users")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    a = ap.parse_args()

    host, _, port = a.listen.rpartition(":")
    Handler.console = Console(a.ctl, load_token(a.token_file), bool(a.tls_cert), a.users_file)
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
