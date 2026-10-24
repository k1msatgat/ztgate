#!/usr/bin/env python3
"""웹 콘솔(tools/console/ztgate_console.py) 시험. root 도 서버도 없이 돈다.

ztgate_ctl 자리에 가짜(정해진 답을 하고 받은 명령을 파일에 적는 스크립트)를 두고 콘솔을 띄워, 로그인,
세션과 CSRF, 화면, 바꾸는 요청이 ztgate_ctl 에 무엇으로 가는지를 본다.

    python3 test/console_check.py
"""

import http.client
import json
import os
import re
import socket
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
    "status": {"ok": True, "running": True, "registered_devices": 2, "acl": {"rules": 3},
               "counters": {"handshake_ok": 7, "deny_posture": 1},
               "sessions": [{"tunnel_ip": "10.0.0.3", "device_id": "ab" * 16, "endpoint": "198.51.100.7:4500",
                             "age_sec": 600, "rx_bytes": 2048, "tx_bytes": 4096, "tags": ["eng"],
                             "posture": {"firewall": "on", "antivirus": "on", "disk": "off", "os_build": 26200},
                             "user": {"name": "alice<script>"}}]},
    "device_list": {"ok": True, "devices": [{"id": "ab" * 16, "label": "laptop", "tunnel_ip": "10.0.0.3",
                                             "key_type": "p256", "requirements": {"firewall": True}}]},
    "enroll_list": {"ok": True, "pending": []},
    "enroll_create": {"ok": True, "code": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "enrollment": {"tunnel_ip": "10.0.0.9"}},
    "device_remove": {"ok": True, "removed": req.get("id")},
    "acl_get": {"ok": True, "enabled": True, "rules": [{"src": "10.0.0.0/24", "dst": "10.0.0.1", "proto": "icmp",
                                                        "dport": "any", "action": "allow"}]},
    "audit": {"ok": True, "events": [{"time": "2026-10-25T00:00:00Z", "event": "session_open", "device": "ab" * 16}]},
}
print(json.dumps(answers.get(req["cmd"], {"ok": False, "error": "unknown command"})))
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
    env = dict(os.environ, FAKE_LOG=log)
    proc = subprocess.Popen([sys.executable, CONSOLE, "-l", "127.0.0.1:%d" % port, "--ctl", fake,
                             "--token-file", token_file], env=env, stderr=subprocess.PIPE)
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
        expect("remove a device", (st, ctl_cmds()[-1]), (303, {"id": "ab" * 16, "cmd": "device_remove"}))

        st, _, body = req("POST", "/enroll/create", {"csrf": csrf, "label": "kim", "tags": "eng laptop",
                                                    "firewall": "on", "disk": "on", "ttl": "30"}, cookie=sid)
        expect("make an enrollment code: shown", (st, "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE" in body), (200, True))
        expect("...with what was filled in", ctl_cmds()[-2] if ctl_cmds()[-1]["cmd"] == "enroll_list" else ctl_cmds()[-1],
               {"requirements": {"firewall": True, "disk": True}, "label": "kim", "tags": ["eng", "laptop"],
                "ttl_minutes": 30, "cmd": "enroll_create"})

        st, _, _ = req("POST", "/logout", {"csrf": csrf}, cookie=sid)
        expect("log out", st, 303)
        st, _, _ = req("GET", "/devices", cookie=sid)
        expect("the old cookie no longer works", st, 401)
    finally:
        proc.terminate()
        proc.wait()

    print()
    print("all passed" if failed == 0 else "%d FAILED" % failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
