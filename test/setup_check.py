#!/usr/bin/env python3
"""처음 설정(ztgate setup, tools/cli/ztgate-setup) 시험. root 도 systemd 도 없이 Linux 에서 돈다.

/etc/ztgate, /sys/class/net, /proc/net/route 자리는 임시 폴더로 바꾸고(ZTGATE_ETC 등), systemctl,
firewall-cmd, ufw, ztgate_ctl 자리에 받은 명령을 적고 상태를 파일에 두는 가짜를 둔다. 무엇을 고치는지,
주석과 모르는 줄을 두는지, 같은 값으로 다시 돌리면 아무것도 하지 않는지, 방화벽마다 무엇을 여는지를 본다.

    python3 test/setup_check.py
"""

import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, "tools", "cli", "ztgate-setup")
CLI = os.path.join(ROOT, "tools", "cli", "ztgate")

# packaging/postinst.sh 가 처음 만드는 server.env
FRESH = ("PORT=9000\nTUN_IP=10.0.0.1\nPREFIX=24\nMTU=1400\n# FORWARD_OUT=eth0\n# SESSION_LIFETIME=3600\n"
         "# TCP_PORT=9000\n# WORKERS=1\n# STATEFUL=1\n# PUBLIC_ADDRESS=vpn.example.com\n")

STUB_HEAD = r'''#!PYTHON
import json, os, sys
W = os.environ["FAKE_DIR"]
def log(name):
    with open(os.path.join(W, "calls.log"), "a") as f:
        f.write(json.dumps([name] + sys.argv[1:]) + "\n")
def load(name, default):
    try:
        with open(os.path.join(W, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
def save(name, v):
    with open(os.path.join(W, name), "w") as f:
        json.dump(v, f)
'''

SYSTEMCTL = STUB_HEAD + r'''
log("systemctl")
st = load("unit.json", {"active": False, "enabled": False})
verb = sys.argv[1]
if verb == "is-active":
    sys.exit(0 if st["active"] else 3)
if verb == "is-enabled":
    sys.exit(0 if st["enabled"] else 1)
if verb in ("start", "restart") or (verb == "enable" and "--now" in sys.argv):
    if os.environ.get("FAKE_START_FAIL"):
        print("Job for ztgate.service failed.", file=sys.stderr)
        st["failed"] = True
        save("unit.json", st)
        sys.exit(1)
    st["active"] = True
if verb == "enable":
    st["enabled"] = True
save("unit.json", st)
'''

FIREWALL_CMD = STUB_HEAD + r'''
log("firewall-cmd")
args = sys.argv[1:]
if os.environ.get("FAKE_FW") != "firewalld":
    print("not running")
    sys.exit(252)
if args == ["--state"]:
    print("running")
    sys.exit(0)
scope = "permanent" if "--permanent" in args else "runtime"
ports = load("firewalld.json", {"permanent": [], "runtime": []})
op = [a for a in args if a != "--permanent"][0]
port = op.split("=", 1)[1]
if op.startswith("--query-port="):
    sys.exit(0 if port in ports[scope] else 1)
if op.startswith("--add-port="):
    ports[scope].append(port)
    save("firewalld.json", ports)
    print("success")
'''

UFW = STUB_HEAD + r'''
log("ufw")
if sys.argv[1] == "status":
    print("Status: active" if os.environ.get("FAKE_FW") == "ufw" else "Status: inactive")
    sys.exit(0)
rules = load("ufw.json", [])
if sys.argv[1] == "allow":
    if sys.argv[2] in rules:
        print("Skipping adding existing rule\nSkipping adding existing rule (v6)")
    else:
        rules.append(sys.argv[2])
        save("ufw.json", rules)
        print("Rule added\nRule added (v6)")
'''

CTL = STUB_HEAD + r'''
req = json.load(sys.stdin)
log("ctl " + json.dumps(req, sort_keys=True))
st = load("unit.json", {"active": False})
if req["cmd"] == "status":
    if st.get("failed"):
        print(json.dumps({"ok": True, "running": False, "state": "failed/failed", "last_result": "exit-code (exit status 1)",
                          "last_log": ["FORWARD_OUT=eth9: no such interface"]}))
    else:
        print(json.dumps({"ok": True, "running": st["active"], "state": "active/running" if st["active"] else "inactive/dead",
                          "tunnel": {"device": "tun0", "up": True}}))
elif req["cmd"] == "enroll_create":
    env = dict(l.split("=", 1) for l in open(os.path.join(os.environ["ZTGATE_ETC"], "server.env")).read().splitlines()
               if l and not l.startswith("#"))
    r = {"ok": True, "code": "ABCDE-FGHJK-MNPQR-STVWX-YZ012"}
    if env.get("PUBLIC_ADDRESS"):
        r["invite"] = "ztgate://enroll?server=%s&port=%s&code=%s" % (env["PUBLIC_ADDRESS"], env["PORT"], r["code"])
    print(json.dumps(r))
'''

failed = 0


def expect(name, got, want):
    global failed
    ok = got == want
    shown = repr(got) if len(repr(got)) < 70 else repr(got)[:67] + "..."
    print("%-4s %-66s %s%s" % ("ok" if ok else "FAIL", name, shown, "" if ok else "   (want %r)" % (want,)))
    failed += not ok


class World:
    """가짜 서버 한 대. 시험마다 새로 만든다."""

    def __init__(self, env_text=FRESH, fw="none", systemd=True):
        self.dir = tempfile.mkdtemp(prefix="ztgate-setup-")
        self.etc = os.path.join(self.dir, "etc")
        os.mkdir(self.etc)
        with open(os.path.join(self.etc, "server.env"), "w") as f:
            f.write(env_text)
        os.chmod(os.path.join(self.etc, "server.env"), 0o600)
        net = os.path.join(self.dir, "net")
        for dev in ("lo", "eth0", "ens3"):
            os.makedirs(os.path.join(net, dev))
        with open(os.path.join(self.dir, "route"), "w") as f:
            f.write("Iface\tDestination\tGateway\nens3\t0000A8C0\t00000000\nens3\t00000000\t0100A8C0\n")
        if systemd:
            os.mkdir(os.path.join(self.dir, "systemd"))
        self.bin = os.path.join(self.dir, "bin")
        os.mkdir(self.bin)
        for name, text in (("systemctl", SYSTEMCTL), ("firewall-cmd", FIREWALL_CMD), ("ufw", UFW), ("ztgate_ctl", CTL)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(text.replace("PYTHON", sys.executable, 1))
            os.chmod(path, 0o755)
        self.env = {"PATH": self.bin, "FAKE_DIR": self.dir, "FAKE_FW": fw, "ZTGATE_ETC": self.etc,
                    "ZTGATE_SYS_NET": net, "ZTGATE_PROC_ROUTE": os.path.join(self.dir, "route"),
                    "ZTGATE_SYSTEMD_DIR": os.path.join(self.dir, "systemd"), "ZTGATE_SETUP_ANY_USER": "1",
                    "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}

    def run(self, *args, extra=None, prog=SETUP, stdin=subprocess.DEVNULL):
        self.mark = len(self.calls())
        p = subprocess.run([sys.executable, prog] + list(args) + ["--ctl", os.path.join(self.bin, "ztgate_ctl")],
                           capture_output=True, text=True, env=dict(self.env, **(extra or {})), timeout=60, stdin=stdin)
        return p.returncode, p.stdout, p.stderr

    def calls(self):
        try:
            with open(os.path.join(self.dir, "calls.log")) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def new_calls(self, name=None):
        return [c for c in self.calls()[self.mark:] if name is None or c[0] == name]

    def changes(self):
        """systemctl 에 보낸 것 중 상태를 바꾸는 것만."""
        return [" ".join(c[1:]) for c in self.new_calls("systemctl") if c[1] not in ("is-active", "is-enabled")]

    def read(self, name="server.env"):
        with open(os.path.join(self.etc, name)) as f:
            return f.read()

    def exists(self, name):
        return os.path.exists(os.path.join(self.etc, name))

    def done(self):
        shutil.rmtree(self.dir)


def main():
    w = World()
    code, out, err = w.run("--yes", extra={"ZTGATE_SETUP_ANY_USER": ""})
    if os.geteuid() != 0:
        expect("not root: exit 2 and says to use sudo", (code, "sudo ztgate setup" in err), (2, True))

    code, out, err = w.run("--yes")
    expect("fresh defaults: exit 0", (code, err), (0, ""))
    expect("fresh defaults: server.env untouched", w.read(), FRESH)
    expect("fresh defaults: enables and starts the service", w.changes(), ["enable --now ztgate.service"])
    expect("fresh defaults: no firewall, prints the commands to open udp/9000",
           "sudo firewall-cmd --permanent --add-port=9000/udp" in out and "sudo ufw allow 9000/udp" in out, True)
    expect("fresh defaults: summary shows port, tunnel device, missing public address",
           all(x in out for x in ("실행 중", "9000/udp", "10.0.0.1/24 (tun0)", "공개 주소   없음")), True)

    code, out, _ = w.run("--yes")
    expect("rerun: nothing written, nothing restarted", (code, w.read(), w.changes()), (0, FRESH, []))
    expect("rerun: says so", "설정은 그대로입니다" in out and "그대로 두었습니다" in out, True)

    code, out, err = w.run("--yes", "--public-address", "VPN.example.com,203.0.113.5", "--port", "9443",
                           "--tcp-port", "9443", "--tunnel", "10.8.0.1/16", "--forward-out", "eth0",
                           "--session-lifetime", "7200", "--dns-server", "10.101.0.53", "--dns-domain", "Corp.Example.")
    lines = w.read().splitlines()
    expect("every key: exit 0", (code, err), (0, ""))
    expect("every key: PORT, TUN_IP, PREFIX edited in place", lines[:4], ["PORT=9443", "TUN_IP=10.8.0.1", "PREFIX=16", "MTU=1400"])
    expect("every key: commented hints become the setting where they were",
           lines[4:], ["FORWARD_OUT=eth0", "SESSION_LIFETIME=7200", "TCP_PORT=9443", "# WORKERS=1", "# STATEFUL=1",
                       "PUBLIC_ADDRESS=vpn.example.com,203.0.113.5"])
    expect("every key: dns.conf with normalised domain",
           [x for x in w.read("dns.conf").splitlines() if not x.startswith("#")], ["server 10.101.0.53", "domain corp.example"])
    expect("every key: files stay 600", [oct(os.stat(os.path.join(w.etc, n)).st_mode & 0o777) for n in ("server.env", "dns.conf")],
           ["0o600", "0o600"])
    expect("every key: restarts the running server", w.changes(), ["restart ztgate.service"])
    expect("every key: summary lists both ports", "9443/udp, 9443/tcp" in out, True)

    code, out, _ = w.run("--yes", "--public-address", "vpn.example.com,203.0.113.5", "--port", "9443",
                         "--tunnel", "10.8.0.1/16", "--dns-domain", "corp.example")
    expect("same values again: no write, no restart", (code, w.changes(), "설정은 그대로입니다" in out), (0, [], True))

    before = w.read()
    code, out, _ = w.run("--yes", "--public-address", "vpn2.example.com")
    expect("public address only: no restart (only ztgate_ctl reads it)", (code, w.changes()), (0, []))
    expect("public address only: one line changed",
           [a for a, b in zip(before.splitlines(), w.read().splitlines()) if a != b], ["PUBLIC_ADDRESS=vpn.example.com,203.0.113.5"])

    w.run("--yes", "--dns-server", "10.101.0.54")
    expect("dns server changed: reload, not restart", w.changes(), ["reload ztgate.service"])
    w.run("--yes", "--dns-server", "none", "--dns-domain", "none")
    expect("dns off: dns.conf removed and restarted", (w.exists("dns.conf"), w.changes()), (False, ["restart ztgate.service"]))
    w.run("--yes", "--tcp-port", "none", "--forward-out", "none")
    lines = w.read().splitlines()
    expect("none comments the line out where it was", (lines[4], lines[6]), ("# FORWARD_OUT=eth0", "# TCP_PORT=9443"))
    w.done()

    odd = ("# 우리 회사 VPN\nPORT=9000\n  # 들여쓴 주석\nTUN_IP=10.0.0.1\nPREFIX=24\nMTU=1380\nPUBLIC_PORT=443\nWORKERS=2\n"
           "SOMETHING_ELSE=keep me\n\nPUBLIC_ADDRESS=\"vpn.example.com\"\n")
    w = World(odd)
    code, out, _ = w.run("--yes", "--public-address", "vpn.example.com", "--port", "9001")
    expect("comments, blank and unknown lines kept; quoted value read as the same value",
           w.read(), odd.replace("PORT=9000", "PORT=9001"))
    w.done()

    w = World("# 손으로 만든 파일\nPORT=9000\n")
    code, out, _ = w.run("--yes")
    expect("missing required keys are added with the defaults", w.read().splitlines(),
           ["# 손으로 만든 파일", "PORT=9000", "TUN_IP=10.0.0.1", "PREFIX=24", "MTU=1400"])
    w.done()

    w = World()
    bad = [
        (["--port", "70000"], "포트는 1 부터 65535"),
        (["--port", "x"], "포트는"),
        (["--tunnel", "10.0.0.0/24"], "브로드캐스트"),
        (["--tunnel", "10.0.0.1/31"], "8 부터 30"),
        (["--tunnel", "300.1.1.1/24"], "주소/길이"),
        (["--forward-out", "eth9"], "eth9 라는 인터페이스가 없습니다"),
        (["--forward-out", "../etc"], "인터페이스가 없습니다"),
        (["--public-address", "bad_name!"], "이름이나 IP 주소가 아닙니다"),
        (["--public-address", "1.2.3.999"], "이름이나 IP 주소가 아닙니다"),
        (["--public-address", "a.com,b.com,c.com,d.com,e.com"], "넷까지"),
        (["--dns-domain", "corp.example"], "서버와 도메인을 함께"),
        (["--dns-server", "10.0.0.53,10.0.0.54,10.0.0.55", "--dns-domain", "corp.example"], "둘까지"),
        (["--dns-server", "dns.corp", "--dns-domain", "corp.example"], "IPv4"),
        (["--session-lifetime", "1"], "2 부터 604800"),
    ]
    for args, why in bad:
        code, out, err = w.run("--yes", *args)
        expect("rejected: %s" % " ".join(args)[:48], (code, why in err, w.read(), w.changes()), (1, True, FRESH, []))
    w.done()

    w = World(fw="firewalld")
    code, out, _ = w.run("--yes", "--tcp-port", "9000")
    expect("firewalld: udp and tcp opened permanently and now", json.load(open(os.path.join(w.dir, "firewalld.json"))),
           {"permanent": ["9000/udp", "9000/tcp"], "runtime": ["9000/udp", "9000/tcp"]})
    expect("firewalld: summary", "firewalld: 9000/udp, 9000/tcp 를 열었습니다" in out, True)
    expect("firewalld: no ufw when firewalld runs", w.new_calls("ufw"), [])
    code, out, _ = w.run("--yes")
    expect("firewalld rerun: only queries", [c[1:] for c in w.new_calls("firewall-cmd") if any("--add" in x for x in c)], [])
    expect("firewalld rerun: says already open", "이미 열려 있습니다" in out, True)
    code, out, _ = w.run("--yes", "--port", "9443", "--tcp-port", "none")
    expect("firewalld: new port opened, old one left with the command to close it",
           ("9443/udp" in json.load(open(os.path.join(w.dir, "firewalld.json")))["runtime"],
            "sudo firewall-cmd --permanent --remove-port=9000/udp" in out), (True, True))
    w.done()

    w = World(fw="ufw")
    code, out, _ = w.run("--yes")
    expect("ufw: allow udp/9000", (json.load(open(os.path.join(w.dir, "ufw.json"))), "ufw: 9000/udp 를 열었습니다" in out),
           (["9000/udp"], True))
    code, out, _ = w.run("--yes")
    expect("ufw rerun: already open", "ufw: 9000/udp 는 이미 열려 있습니다" in out, True)
    code, out, _ = w.run("--yes", "--no-firewall", "--port", "9001")
    expect("--no-firewall: neither tool is called", (w.new_calls("ufw"), w.new_calls("firewall-cmd"), "--no-firewall" in out),
           ([], [], True))
    w.done()

    w = World()
    code, out, _ = w.run("--yes", "--no-start", "--port", "9001")
    expect("--no-start: server.env written, service untouched", ("PORT=9001" in w.read(), w.new_calls("systemctl")), (True, []))
    w.done()

    w = World(systemd=False)
    code, out, _ = w.run("--yes")
    expect("no systemd: says so and exits 0", (code, "systemd 가 없어" in out, w.new_calls("systemctl")), (0, True, []))
    w.done()

    w = World()
    code, out, err = w.run("--yes", "--forward-out", "eth0", extra={"FAKE_START_FAIL": "1"})
    expect("start fails: exit 1 with the server's last log", (code, "FORWARD_OUT=eth9: no such interface" in out), (1, True))
    w.done()

    w = World()
    code, out, err = w.run("--yes", "--public-address", "vpn.example.com", "--enroll", "first-pc")
    ctl = [json.loads(c[0][4:]) for c in w.new_calls() if c[0].startswith("ctl ") and "enroll" in c[0]]
    expect("--enroll: one enroll_create as actor setup", ctl, [{"actor": "setup", "cmd": "enroll_create", "label": "first-pc"}])
    expect("--enroll: code and invite link, marked secret",
           all(x in out for x in ("비밀", "ABCDE-FGHJK-MNPQR-STVWX-YZ012",
                                  "ztgate://enroll?server=vpn.example.com&port=9000&code=ABCDE-FGHJK-MNPQR-STVWX-YZ012")), True)
    w.done()

    w = World()
    code, out, _ = w.run("--yes", "--enroll", "pc")
    expect("--enroll without public address: the manual command instead", "vpn_client.exe enroll <서버 주소> 9000" in out, True)
    w.done()

    w = World()
    code, out, _ = w.run("setup", "--yes", "--port", "9002", prog=CLI)
    expect("ztgate setup runs ztgate-setup", (code, "PORT=9002" in w.read()), (0, True))
    w.done()

    # 터미널에서: 비운 답은 지금 값, 틀린 답은 다시 묻는다.
    w = World()
    master, slave = pty.openpty()
    answers = ["vpn.example.com", "", "99999", "9100", "", "", "", "", ""]
    os.write(master, ("\n".join(answers) + "\n").encode())
    code, out, err = w.run(stdin=slave)
    os.close(slave)
    os.close(master)
    expect("interactive: exit 0", (code, err), (0, ""))
    expect("interactive: shows current values and the default-route hint",
           all(x in out for x in ("UDP 포트 [9000]", "터널 주소/길이 [10.0.0.1/24]", "기본 경로는 ens3")), True)
    expect("interactive: wrong answer asked again", "포트는 1 부터 65535" in out, True)
    expect("interactive: answers applied, blanks kept",
           [x for x in w.read().splitlines() if not x.startswith("#")],
           ["PORT=9000", "TUN_IP=10.0.0.1", "PREFIX=24", "MTU=1400", "TCP_PORT=9100", "PUBLIC_ADDRESS=vpn.example.com"])
    w.done()

    print()
    print("all passed" if failed == 0 else "%d FAILED" % failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
