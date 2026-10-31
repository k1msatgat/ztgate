#!/usr/bin/env python3
"""운영자 명령(tools/cli/ztgate) 시험. root 도 서버도 없이 돈다.

ztgate_ctl 자리에 가짜(정해진 답을 하고 받은 명령을 파일에 적는 스크립트)를 두고, 명령마다 무엇을
ztgate_ctl 에 보내는지, 표에 무엇이 나오는지, 색을 언제 넣는지를 본다.

    python3 test/cli_check.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "tools", "cli", "ztgate")
DEV = "ab" * 16

FAKE = r'''#!/usr/bin/env python3
import json, sys, os
req = json.load(sys.stdin)
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(req) + "\n")
if os.environ.get("FAKE_FAIL"):
    print(json.dumps({"ok": False, "error": "server is not running"}))
    sys.exit(0)
DEV = "ab" * 16
answers = {
    "status": {"ok": True, "running": True, "registered_devices": 2, "acl": {"rules": 3},
               "counters": {"handshake_ok": 1284, "deny_posture": 1, "acl_denied": 4},
               "sessions": [{"tunnel_ip": "10.0.0.3", "device_id": DEV, "endpoint": "198.51.100.7:4500",
                             "age_sec": 3720, "rx_bytes": 2048, "tx_bytes": 4096, "tags": ["eng"],
                             "posture": {"firewall": "on", "antivirus": "on", "disk": "off"},
                             "user": {"name": "alice"}}]},
    "device_list": {"ok": True, "devices": [
        {"id": DEV, "label": "laptop", "tunnel_ip": "10.0.0.3", "key_type": "p256", "requirements": {"firewall": True}},
        {"id": "cd" * 16, "label": "노트북-김", "tunnel_ip": "10.0.0.5", "key_type": "p256", "tags": ["eng"]}]},
    "enroll_list": {"ok": True, "pending": [{"label": "kim", "tunnel_ip": "10.0.0.9", "expires_in_sec": 120}]},
    "acl_get": {"ok": True, "enabled": True, "rules": [
        {"src": "10.0.0.0/24", "dst": "10.0.0.1", "proto": "tcp", "dport": "22", "action": "allow",
         "require": {"firewall": True}, "users": {"users": [], "groups": ["ops"]}},
        {"src": "any", "dst": "any", "proto": "any", "dport": "any", "action": "deny"}]},
    "audit": {"ok": True, "events": [{"time": "2026-10-25T00:00:00Z", "event": "session_open", "device": "abab"}]},
}
print(json.dumps(answers.get(req["cmd"], {"ok": False, "error": "unknown command"})))
'''

failed = 0


def cells(s):
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def expect(name, got, want):
    global failed
    ok = got == want
    print("%-4s %-62s %s%s" % ("ok" if ok else "FAIL", name, got, "" if ok else "   (want %s)" % (want,)))
    failed += not ok


def main():
    work = tempfile.mkdtemp()
    fake = os.path.join(work, "ztgate_ctl")
    with open(fake, "w") as f:
        f.write(FAKE.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
    os.chmod(fake, 0o755)
    log = os.path.join(work, "ctl.log")
    env = dict(os.environ, FAKE_LOG=log, ZTGATE_CTL_NO_SUDO="1")
    env.pop("NO_COLOR", None)

    def run(*args, extra=None):
        p = subprocess.run([sys.executable, CLI, "--ctl", fake] + list(args), capture_output=True, text=True,
                           env=dict(env, **(extra or {})), timeout=30)
        return p.returncode, p.stdout, p.stderr

    def last():
        with open(log) as f:
            return json.loads(f.readlines()[-1])

    code, out, _ = run("status")
    expect("status: exits 0", code, 0)
    expect("status: the session row", all(w in out for w in ("10.0.0.3", "alice", "198.51.100.7:4500", "1시간 2분")), True)
    expect("status: counters on one line", "핸드셰이크 1,284" in out and "ACL 차단 4" in out, True)
    expect("status: no colour when stdout is not a terminal", "\033[" in out, False)

    code, out, _ = run("--color", "always", "status")
    expect("--color always: teal for running, red for the posture miss",
           "\033[36m● 실행 중\033[0m" in out and "\033[31m디스크\033[0m" in out, True)
    code, out, _ = run("--color", "never", "status")
    expect("--color never: the posture miss is marked in text", "방화벽 백신 디스크✗" in out, True)
    code, out, _ = run("--color", "always", "status", extra={"NO_COLOR": "1"})
    expect("--color always wins over NO_COLOR", "\033[" in out, True)

    code, out, _ = run("--json", "status")
    expect("--json: ztgate_ctl's answer as it is", (code, json.loads(out).get("registered_devices")), (0, 2))

    code, out, _ = run("devices")
    expect("devices: asks ztgate_ctl for the list and for status", [x["cmd"] for x in map(json.loads, open(log).readlines()[-2:])],
           ["device_list", "status"])
    lines = [x for x in out.splitlines() if "laptop" in x or "노트북" in x]
    expect("devices: the connected one is marked", "연결됨" in lines[0] and "끊김" in lines[1], True)
    expect("devices: Korean names keep the columns aligned",
           cells(lines[0][:lines[0].index("10.0.0.3")]) == cells(lines[1][:lines[1].index("10.0.0.5")]), True)

    code, out, _ = run("acl")
    expect("acl: rules with conditions", "firewall=on group=ops" in out and "deny" in out, True)

    code, out, _ = run("enroll")
    expect("enroll: time left", "2분 남음" in out, True)

    code, out, _ = run("audit", "-n", "5", "-e", "session_open")
    expect("audit: what goes to ztgate_ctl", last(), {"lines": 5, "event": "session_open", "cmd": "audit"})
    expect("audit: one line per event", "session_open" in out and "device=abab" in out, True)

    code, out, err = run("status", extra={"FAKE_FAIL": "1"})
    expect("an error from ztgate_ctl: exit 1 and the reason on stderr",
           (code, "server is not running" in err, out), (1, True, ""))

    code, out, _ = run()
    expect("no command means status", "ztgate 서버" in out, True)

    print()
    print("all passed" if failed == 0 else "%d FAILED" % failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
