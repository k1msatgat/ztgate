#!/usr/bin/env python3
"""웹 콘솔(tools/console/ztgate_console.py) 시험. root 도 서버도 없이 돈다.

ztgate_ctl 자리에 가짜(정해진 답을 하고 받은 명령을 파일에 적는 스크립트)를 두고 콘솔을 띄워, 로그인,
세션과 CSRF, 화면, 바꾸는 요청이 ztgate_ctl 에 무엇으로 가는지를 본다. 가짜의 답은 FAKE_OVER 파일로
명령마다 바꿀 수 있다 (실패, 멈춘 서버, 부 서버, "crash" 는 아무것도 답하지 않고 죽기).

    python3 test/console_check.py
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONSOLE = os.path.join(ROOT, "tools", "console", "ztgate_console.py")

FAKE = r'''#!/usr/bin/env python3
import json, sys, os
req = json.load(sys.stdin)
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(req) + "\n")
answers = {
    "status": {"ok": True, "running": True, "registered_devices": 2, "acl": {"enabled": True, "rules": 3},
               "sync_primary": None,
               "counters": {"handshake_ok": 7, "deny_posture": 1},
               "sessions": [{"tunnel_ip": "10.0.0.3", "device_id": "ab" * 16, "endpoint": "198.51.100.7:4500",
                             "age_sec": 600, "rx_bytes": 2048, "tx_bytes": 4096, "tags": ["eng"],
                             "posture": {"firewall": "on", "antivirus": "on", "disk": "off", "os_build": 26200},
                             "user": {"name": "alice<script>"}}]},
    "device_list": {"ok": True, "devices": [{"id": "ab" * 16, "label": "laptop", "tunnel_ip": "10.0.0.3",
                                             "key_type": "p256", "requirements": {"firewall": True}}]},
    "enroll_list": {"ok": True, "pending": []},
    "enroll_create": {"ok": True, "code": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "enrollment": {"tunnel_ip": "10.0.0.9"},
                      "invite": "ztgate://enroll?server=vpn.example.com&port=9000&code=AAAAA-BBBBB-CCCCC-DDDDD-EEEEE&x=<b>"},
    "device_remove": {"ok": True, "removed": req.get("id")},
    "device_update": {"ok": True, "device": {"id": req.get("id")}},
    "acl_get": {"ok": True, "enabled": True, "rules": [{"src": "10.0.0.0/24", "dst": "10.0.0.1", "proto": "icmp",
                                                        "dport": "any", "action": "allow",
                                                        "require": {"firewall": True}, "tags": ["eng"]}]},
    "acl_set": {"ok": True, "enabled": True, "rules": req.get("rules", [])},
    "audit": {"ok": True, "events": [{"time": "2026-10-25T00:00:00Z", "event": "session_open", "device": "ab" * 16}]},
}
try:
    with open(os.environ["FAKE_OVER"]) as f:
        answers.update(json.load(f))
except FileNotFoundError:
    pass
answer = answers.get(req["cmd"], {"ok": False, "error": "unknown command"})
if answer == "crash":
    sys.stderr.write("Traceback (most recent call last): boom\n")
    sys.exit(1)
print(json.dumps(answer))
'''

failed = 0


def expect(name, got, want):
    global failed
    ok = got == want
    print("%-4s %-60s %s%s" % ("ok" if ok else "FAIL", name, got, "" if ok else "   (want %s)" % (want,)))
    failed += not ok


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    work = tempfile.mkdtemp()
    fake = os.path.join(work, "ztgate_ctl")
    with open(fake, "w") as f:
        f.write(FAKE.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
    os.chmod(fake, 0o755)
    log = os.path.join(work, "ctl.log")
    token_file = os.path.join(work, "console.token")
    port = free_port()
    over = os.path.join(work, "over.json")
    env = dict(os.environ, FAKE_LOG=log, FAKE_OVER=over)
    users_file = os.path.join(work, "console.users")
    proc = subprocess.Popen([sys.executable, CONSOLE, "-l", "127.0.0.1:%d" % port, "--ctl", fake,
                             "--token-file", token_file, "--users-file", users_file], env=env, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        def req(method, path, body=None, cookie=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            h = {}
            if cookie:
                h["Cookie"] = "ztgate_session=" + cookie
            if body is not None:
                body = urllib.parse.urlencode(body)
                h["Content-Type"] = "application/x-www-form-urlencoded"
            c.request(method, path, body, h)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read().decode()

        def ctl_cmds():
            try:
                with open(log) as f:
                    return [json.loads(x) for x in f]
            except FileNotFoundError:
                return []

        def answer(**cmds):
            with open(over, "w") as f:
                json.dump(cmds, f)

        def get(path, cookie):
            st, _, body = req("GET", path, cookie=cookie)
            return st, body

        expect("token file is made with mode 600", oct(os.stat(token_file).st_mode & 0o777), "0o600")
        token = open(token_file).read().strip()

        st, _, body = req("GET", "/")
        expect("not logged in: the login page", (st, "관리 토큰" in body), (200, True))
        st, _, _ = req("GET", "/devices")
        expect("not logged in: other pages are refused", st, 401)
        expect("...and nothing reached ztgate_ctl", len(ctl_cmds()), 0)

        st, _, _ = req("POST", "/login", {"token": "wrong"})
        expect("wrong token", st, 403)
        time.sleep(1.1)
        st, h, _ = req("POST", "/login", {"token": token})
        sid = re.search(r"ztgate_session=([^;]+)", h.get("Set-Cookie", ""))
        expect("right token: a session cookie", (st, bool(sid)), (303, True))
        sid = sid.group(1)
        expect("the cookie is HttpOnly and SameSite=Strict",
               "HttpOnly" in h["Set-Cookie"] and "SameSite=Strict" in h["Set-Cookie"], True)

        st, h, body = req("GET", "/", cookie=sid)
        expect("overview: the session is listed", (st, "10.0.0.3" in body and "198.51.100.7:4500" in body), (200, True))
        expect("overview: values are escaped", ("alice&lt;script&gt;" in body, "alice<script>" in body), (True, False))
        expect("pages forbid framing", h.get("X-Frame-Options"), "DENY")
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)

        st, _, body = req("GET", "/devices", cookie=sid)
        expect("devices page", (st, "laptop" in body and "firewall=on" in body), (200, True))
        for path, word in (("/acl", "10.0.0.0/24"), ("/audit", "session_open"), ("/enroll", "새 등록 코드")):
            st, _, body = req("GET", path, cookie=sid)
            expect("page %s" % path, (st, word in body), (200, True))

        n = len(ctl_cmds())
        st, _, _ = req("POST", "/devices/remove", {"id": "ab" * 16}, cookie=sid)
        expect("a change without the CSRF value is refused", st, 403)
        st, _, _ = req("POST", "/devices/remove", {"id": "ab" * 16, "csrf": "x" * 32}, cookie=sid)
        expect("a change with a wrong CSRF value is refused", st, 403)
        expect("...and neither reached ztgate_ctl", len(ctl_cmds()), n)

        st, h, _ = req("POST", "/devices/remove", {"id": "ab" * 16, "csrf": csrf}, cookie=sid)
        expect("remove a device, as the token login", (st, ctl_cmds()[-1]),
               (303, {"id": "ab" * 16, "cmd": "device_remove", "actor": "console:token"}))

        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": "kim", "tags": "eng laptop",
                                                    "firewall": "on", "disk": "on", "ttl": "30"}, cookie=sid)
        expect("make an enrollment code: shown", (st, "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE" in body), (200, True))
        expect("...with the invite link, escaped",
               ("ztgate://enroll?server=vpn.example.com&amp;port=9000&amp;code=AAAAA-BBBBB-CCCCC-DDDDD-EEEEE&amp;x=&lt;b&gt;" in body,
                "PUBLIC_ADDRESS=" in body), (True, False))
        expect("...with what was filled in", ctl_cmds()[-2] if ctl_cmds()[-1]["cmd"] == "enroll_list" else ctl_cmds()[-1],
               {"requirements": {"firewall": True, "disk": True}, "label": "kim", "tags": ["eng", "laptop"],
                "ttl_minutes": 30, "cmd": "enroll_create", "actor": "console:token"})

        st, _, body = req("GET", "/acl", cookie=sid)
        expect("acl: the editor shows the rules as file lines",
               "10.0.0.0/24 10.0.0.1 icmp any allow firewall=on tag=eng" in body, True)
        text = ("10.0.0.0/24 10.0.0.1 tcp 22 allow firewall=on disk=on group=ops tag=eng  # ssh\n"
                "\n# 주석만 있는 줄\nany any any any deny\n")
        st, _, _ = req("POST", "/acl/set", {"csrf": csrf, "rules": text}, cookie=sid)
        expect("acl: save", (st, ctl_cmds()[-1]["cmd"]), (303, "acl_set"))
        expect("acl: ...the lines became rules", ctl_cmds()[-1]["rules"], [
            {"src": "10.0.0.0/24", "dst": "10.0.0.1", "proto": "tcp", "dport": "22", "action": "allow",
             "require": {"firewall": True, "disk": True}, "users": {"users": [], "groups": ["ops"]}, "tags": ["eng"]},
            {"src": "any", "dst": "any", "proto": "any", "dport": "any", "action": "deny"}])
        n = len(ctl_cmds())
        st, _, body = req("POST", "/acl/set", {"csrf": csrf, "rules": "any any any any allow firewal=on"}, cookie=sid)
        expect("acl: a misspelled condition is refused before ztgate_ctl", (st, len(ctl_cmds()) - n), (400, 1))
        expect("...and the text is kept", "firewal=on" in body, True)

        st, _, body = req("GET", "/devices/edit?id=" + "ab" * 16, cookie=sid)
        expect("device edit: the form is filled in", (st, 'value="laptop"' in body, "checked" in body), (200, True, True))
        st, _, _ = req("POST", "/devices/update", {"csrf": csrf, "id": "ab" * 16, "label": "laptop-2", "tags": "eng ops",
                                                  "firewall": "on", "min_build": "22000", "tunnel_ip": "10.0.0.4"}, cookie=sid)
        expect("device edit: what goes to ztgate_ctl", (st, ctl_cmds()[-1]), (303, {
            "id": "ab" * 16, "label": "laptop-2", "tags": ["eng", "ops"], "tunnel_ip": "10.0.0.4",
            "requirements": {"firewall": True, "min_build": 22000}, "cmd": "device_update", "actor": "console:token"}))

        dev = {"csrf": csrf, "id": "ab" * 16, "label": "laptop-2", "tags": "eng ops", "tunnel_ip": "10.0.0.9"}
        answer(device_update={"ok": True, "device": {"id": "ab" * 16}, "reloaded": False,
                              "reload_error": "sent SIGHUP but the server did not report a reload within 3s"})
        st, h, _ = req("POST", "/devices/update", dev, cookie=sid)
        _, body = get(h.get("Location", "/"), sid)
        expect("reload failed after the write: a warning, not an error",
               (st, 'class="msg warn"' in body, "저장했지만 서버가 다시 읽지 못했습니다: 3초 안에" in body), (303, True, True))
        answer(enroll_create={"ok": True, "code": "FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK", "enrollment": {"tunnel_ip": "10.0.0.9"},
                              "reloaded": False, "reload_error": "server rejected the device file and kept the previous list"})
        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": "kim"}, cookie=sid)
        expect("reload failed after enroll_create: the code is still shown, with a warning",
               (st, "FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK" in body, "저장했지만 서버가 다시 읽지 못했습니다" in body), (200, True, True))
        answer(enroll_create={"ok": True, "code": "LLLLL-MMMMM-NNNNN-PPPPP-QQQQQ", "enrollment": {"tunnel_ip": "10.0.0.9"},
                              "invite_error": "PUBLIC_ADDRESS in /etc/ztgate/server.env is not a list ..."})
        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": "kim"}, cookie=sid)
        expect("bad PUBLIC_ADDRESS: the code is shown, with a warning about the link",
               (st, "LLLLL-MMMMM-NNNNN-PPPPP-QQQQQ" in body, "초대 링크를 만들지 못했습니다" in body), (200, True, True))

        answer(device_update={"ok": False, "error": "tunnel_ip 10.0.0.9 is already assigned"})
        st, _, body = req("POST", "/devices/update", dev, cookie=sid)
        expect("device update refused: in Korean, the form keeps what was typed",
               (st, "터널 주소 10.0.0.9 는 이미 다른 기기에 배정되어 있습니다." in body, 'value="laptop-2"' in body,
                'value="10.0.0.9"' in body), (400, True, True, True))
        answer(enroll_create={"ok": False, "error": "too many pending enrollments (max 256); revoke one or wait for it to expire"})
        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": "  kim  ", "tags": "eng", "disk": "on", "ttl": "30"},
                          cookie=sid)
        expect("enroll create refused: in Korean, the form keeps what was typed",
               (st, "기다리는 등록 코드가 너무 많습니다 (최대 256개)" in body, 'value="  kim  "' in body, 'value="30"' in body),
               (400, True, True, True))
        answer(enroll_create={"ok": False, "error": "something new went wrong"}, enroll_list={"ok": False, "error": "boom"})
        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": " kim ", "tunnel_ip": " 10.0.0.7 "}, cookie=sid)
        expect("enroll create: label and tunnel_ip are trimmed",
               {k: v for k, v in ctl_cmds()[-2].items() if k in ("label", "tunnel_ip")}, {"label": "kim", "tunnel_ip": "10.0.0.7"})
        expect("an unknown ctl error keeps its text after a Korean lead",
               "관리 도구가 거절했습니다: something new went wrong" in body, True)
        expect("enroll_list failing is shown, not 'no pending codes'",
               ("관리 도구가 거절했습니다: boom" in body, "기다리는 등록 코드가 없습니다" in body), (True, False))
        answer(device_list={"ok": False, "error": "boom"})
        _, body = get("/devices/edit?id=" + "ab" * 16, sid)
        expect("device_list failing on the edit page is shown, not 'no such device'",
               ("boom" in body, "이 ID 의 기기가 없습니다" in body), (True, False))

        answer(status={"ok": True, "running": False, "state": "failed/failed", "last_result": "exit-code (exit status 1)",
                       "registered_devices": 2, "acl": {"enabled": False, "rules": 0}, "sync_primary": None})
        _, body = get("/", sid)
        expect("stopped server: said so, with the last result",
               ("서버가 멈춰 있습니다 (exit-code (exit status 1))" in body, "붙어 있는 세션이 없습니다" in body), (True, False))
        expect("acl off: the overview says 꺼짐", ("ACL 꺼짐" in body, "첫 일치 · 기본 거부" in body), (True, False))
        _, body = get("/devices", sid)
        expect("stopped server: devices show as 끊김", ("끊김" in body, "알 수 없음" in body), (True, False))
        live = {"ok": True, "running": True, "registered_devices": 2, "acl": {"enabled": True, "rules": 3}, "sync_primary": None}
        answer(status=dict(live, sessions_error="the server did not answer on its status socket"))
        _, body = get("/", sid)
        expect("no answer on the status socket: not 'no sessions'",
               ("세션 정보를 받지 못했습니다" in body, "붙어 있는 세션이 없습니다" in body), (True, False))
        answer(status=dict(live, sessions=[], counters={"deny_tun_ip": 4, "deny_posture": 1}))
        _, body = get("/", sid)
        expect("the rejected total counts deny_tun_ip", re.search(r'거절</div><div class="v">([^<]*)<', body).group(1), "5")
        answer(status="crash")
        _, body = get("/", sid)
        expect("ztgate_ctl dying shows a Korean fallback",
               ("관리 도구(ztgate_ctl)가 답하지 않았습니다" in body, "IndexError" in body), (True, False))

        answer(status=dict(live, sessions=[], sync_primary="vpn-a.example.com"))
        banner = "이 서버는 vpn-a.example.com 의 설정을 받는 부 서버입니다. 설정은 주 서버에서 고칩니다."
        _, body = get("/devices", sid)
        expect("secondary: the banner, and no edit controls on devices",
               (banner in body, "지우기" in body, "/devices/edit" in body, "새 기기 등록" in body), (True, False, False, False))
        _, body = get("/enroll", sid)
        expect("secondary: no enroll form", (banner in body, 'action="/enroll/create"' in body), (True, False))
        _, body = get("/acl", sid)
        expect("secondary: no acl editor", (banner in body, "<textarea" in body), (True, False))
        st, _ = get("/devices/edit?id=" + "ab" * 16, sid)
        expect("secondary: the edit page is not there", st, 404)
        answer()

        with open(os.path.join(ROOT, "server", "src", "audit.c"), encoding="utf-8") as f:
            written = set(re.findall(r'begin\("(\w+)"\)', f.read())) | {"admin"}
        with open(os.path.join(ROOT, "mcp", "ctl.cjs"), encoding="utf-8") as f:
            ctl_events = set(re.findall(r"'(\w+)'", re.search(r"const AUDIT_EVENTS = \[([^\]]*)\]", f.read()).group(1)))
        _, body = get("/audit", sid)
        chips = set(re.findall(r'href="/audit\?event=(\w+)"', body))
        expect("every event the server writes can be asked of ztgate_ctl", sorted(written - ctl_events), [])
        # 서버 말고도 감사 로그에 쓰는 것이 있다 (배포기의 deploy). ztgate_ctl 이 받는 사건이면 모두 단추가 있어야 한다.
        expect("...and every event ztgate_ctl takes has a filter chip", sorted(ctl_events - chips), [])
        for event in ("login", "logout"):
            get("/audit?event=" + event, sid)
            expect("audit filter %s reaches ztgate_ctl" % event, ctl_cmds()[-1], {"lines": 200, "event": event, "cmd": "audit"})
        answer(audit={"ok": True, "events": [{"time": "2026-10-25T00:00:00Z", "event": "admin", "actor": "console:x",
                                               "cmd": "device_remove", "ok": False, "error": "no device with this id"}]})
        _, body = get("/audit", sid)
        expect("audit: a failed admin event is a bad badge, ok:false reads 실패",
               ('badge bad">관리 작업' in body, "<code>실패</code>" in body, "<code>False</code>" in body), (True, True, False))
        answer(audit={"ok": True, "events": [
            {"time": "2026-10-25T00:00:00Z", "event": "deploy", "job": "d-1", "outcome": "installed"},
            {"time": "2026-10-25T00:01:00Z", "event": "deploy", "job": "d-2", "outcome": "broken"}]})
        _, body = get("/audit", sid)
        expect("audit: deploy reads 배포, colored by its outcome",
               ('badge ok">배포' in body, 'badge bad">배포' in body), (True, True))
        answer()

        st, h, _ = req("POST", "/login", {"token": token})
        tsid = re.search(r"ztgate_session=([^;]+)", h.get("Set-Cookie", "")).group(1)
        st, _, _ = req("POST", "/logout", {"csrf": csrf}, cookie=sid)
        expect("log out", st, 303)
        st, _, _ = req("GET", "/devices", cookie=sid)
        expect("the old cookie no longer works", st, 401)

        # 관리자 계정. 계정이 생기면 토큰으로는 들어오지 못한다.
        def add_user(name, role, *extra):
            r = subprocess.run([sys.executable, CONSOLE, "user", "add", name, "--role", role, "--password-stdin",
                                "--users-file", users_file] + list(extra),
                               input="correct horse battery\n", capture_output=True, text=True)
            return r.returncode, r.stdout
        expect("user add: admin", add_user("alice", "admin")[0], 0)
        expect("user add: viewer", add_user("bob", "viewer")[0], 0)
        rc, out = add_user("carol", "admin", "--totp")
        secret = out.split("secret=")[1].split("&")[0] if "secret=" in out else ""
        expect("user add --totp prints an otpauth uri", (rc, len(secret) >= 16), (0, True))
        expect("users file: mode 600, no password in clear",
               (oct(os.stat(users_file).st_mode & 0o777), "battery" in open(users_file).read()), ("0o600", False))

        expect("with accounts: a token session that was open is closed", get("/devices", tsid)[0], 401)
        st, _, body = req("GET", "/")
        expect("with accounts: the login asks for a name", (st, 'name="name"' in body, 'name="token"' in body),
               (200, True, False))
        time.sleep(1.1)
        st, _, _ = req("POST", "/login", {"token": token})
        expect("with accounts: the token no longer logs in", st, 403)
        time.sleep(1.1)
        st, _, _ = req("POST", "/login", {"name": "alice", "password": "wrong password"})
        expect("wrong password", st, 403)
        st, _, _ = req("POST", "/login", {"name": "alice", "password": "correct horse battery"})
        expect("a second try within a second from the same address is refused", st, 403)
        time.sleep(1.1)

        def login(name, **extra):
            st, h, _ = req("POST", "/login", dict({"name": name, "password": "correct horse battery"}, **extra))
            m = re.search(r"ztgate_session=([^;]+)", h.get("Set-Cookie", ""))
            return st, m.group(1) if m else None

        st, alice = login("alice")
        expect("alice logs in", (st, bool(alice)), (303, True))
        _, _, body = req("GET", "/devices", cookie=alice)
        acsrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        expect("the top bar shows who is logged in", "alice · 관리자" in body, True)
        req("POST", "/devices/remove", {"id": "ab" * 16, "csrf": acsrf}, cookie=alice)
        expect("alice's change carries her name to ztgate_ctl", ctl_cmds()[-1].get("actor"), "console:alice")

        st, bob = login("bob")
        _, _, body = req("GET", "/devices", cookie=bob)
        bcsrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        expect("viewer: no remove or edit buttons", ("지우기" in body, "/devices/edit" in body), (False, False))
        n = len(ctl_cmds())
        st, _, _ = req("POST", "/devices/remove", {"id": "ab" * 16, "csrf": bcsrf}, cookie=bob)
        expect("viewer: a change is refused before ztgate_ctl", (st, len(ctl_cmds()) - n), (403, 0))

        time.sleep(1.1)
        st, _ = login("carol")
        expect("totp: without the code, refused", st, 403)
        time.sleep(1.1)
        key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        mac = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
        o = mac[-1] & 15
        code = "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7fffffff) % 1000000)
        st, carol = login("carol", code=code)
        expect("totp: with the current code, in", (st, bool(carol)), (303, True))

        expect("carol's session works", get("/devices", carol)[0], 200)
        add_user("carol", "viewer")
        expect("a demoted user's session ends", get("/devices", carol)[0], 401)
        subprocess.run([sys.executable, CONSOLE, "user", "del", "alice", "--users-file", users_file], check=True)
        expect("a deleted user's session ends", get("/devices", alice)[0], 401)
        expect("bob, untouched, is still in", get("/devices", bob)[0], 200)

        def raw(text):
            s = socket.create_connection(("127.0.0.1", port), 5)
            s.sendall(text.encode())
            try:
                data = s.recv(200).decode(errors="replace")
            except socket.timeout:
                data = "timeout"
            s.close()
            return data.split(" ", 2)[1] if data.startswith("HTTP/") else data

        # 음수 길이를 그대로 read() 에 넘기면 연결이 닫힐 때까지 기다린다 (그러면 recv 가 5초 뒤 실패한다).
        expect("a negative Content-Length is refused at once", raw("POST /login HTTP/1.0\r\nContent-Length: -1\r\n\r\n"), "400")
        expect("a Content-Length that is not a number is refused", raw("POST /login HTTP/1.0\r\nContent-Length: x\r\n\r\n"), "400")
    finally:
        proc.terminate()
        _, err = proc.communicate()
    expect("ztgate_ctl's stderr reaches the console's log", "boom" in err.decode(errors="replace"), True)

    # TLS: 연결만 열고 핸드셰이크를 하지 않는 상대가 있어도 다른 사람은 들어온다.
    cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-subj", "/CN=localhost", "-days", "1", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    port = free_port()
    proc = subprocess.Popen([sys.executable, CONSOLE, "-l", "127.0.0.1:%d" % port, "--ctl", fake,
                             "--token-file", token_file, "--tls-cert", cert, "--tls-key", key],
                            env=env, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        idle = socket.create_connection(("127.0.0.1", port), 5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            c = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ctx)
            c.request("GET", "/")
            r = c.getresponse()
            got = (r.status, r.getheader("Strict-Transport-Security"))
        except OSError as ex:
            got = type(ex).__name__
        expect("tls: a silent connection does not hold up the next one", got, (200, "max-age=31536000"))
        idle.close()
    finally:
        proc.terminate()
        proc.wait()

    print()
    print("all passed" if failed == 0 else "%d FAILED" % failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
