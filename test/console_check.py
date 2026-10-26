#!/usr/bin/env python3
"""웹 콘솔(tools/console/ztgate_console.py) 시험. root 도 서버도 없이 돈다.

ztgate_ctl 자리에 가짜(정해진 답을 하고 받은 명령을 파일에 적는 스크립트)를 두고 콘솔을 띄워, 로그인,
세션과 CSRF, 화면, 바꾸는 요청이 ztgate_ctl 에 무엇으로 가는지를 본다.

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
    "device_update": {"ok": True, "device": {"id": req.get("id")}},
    "acl_get": {"ok": True, "enabled": True, "rules": [{"src": "10.0.0.0/24", "dst": "10.0.0.1", "proto": "icmp",
                                                        "dport": "any", "action": "allow",
                                                        "require": {"firewall": True}, "tags": ["eng"]}]},
    "acl_set": {"ok": True, "enabled": True, "rules": req.get("rules", [])},
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
        proc.wait()

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
