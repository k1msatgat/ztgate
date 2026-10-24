#!/usr/bin/env python3
"""터널 안에 두는 시험용 사내 서비스. 터널을 지나온 요청을 실제로 받는 목적지다.

    sudo python3 tools/intranet/intranet.py [-b 10.0.0.1] [-p 8080] [-p 8081]
                 [-s /run/ztgate/status.sock] [-d devices.conf] [-l intranet.log]

서버는 클라이언트가 보낸 패킷을 풀어 tun 에 쓰기만 하고, 그 뒤는 커널이 받는다. 지금까지
그 패킷의 목적지는 ping 에 답하는 커널뿐이라 "닿는다 / 막힌다"까지만 볼 수 있었다. 이
서비스는 서버의 터널 주소에서 HTTP 로 듣고, 요청마다 다음을 한다.

- 요청한 쪽의 터널 주소로 서버의 상태 소켓에서 세션을 찾아, 어느 기기(라벨)가 어떤 포스처로
  붙어 있고 누가 로그인했는지 페이지로 돌려준다. 브라우저로 열면 "사내 포털"처럼 보인다.
- 요청을 한 줄씩 시간순으로 남긴다. 시나리오 시험에서 "그 시각에 그 기기의 요청이 여기까지
  왔는가"의 판정 근거가 된다. 서버의 감사 로그는 ACL 판정을, 이 로그는 실제 도착을 보여 준다.

포트를 둘 열고 ACL 에서 하나만 허용하면, 같은 브라우저에서 한쪽은 열리고 다른 쪽은 시간이
초과되는 것으로 ACL 을 보여 준다.

페이지는 /whoami 를 2초마다 다시 읽는다. 포스처가 정책에 못 미쳐 서버가 세션을 내리면 그
요청이 더는 오지 않으므로, 페이지가 "끊김"으로 바뀌는 순간이 곧 서버가 끊은 순간이다.

보여 주는 것은 요청한 기기 자신의 것뿐이다 — 그 세션의 트래픽, ACL 에 막힌 횟수, 그 기기에
걸린 포스처 조건, 이 서비스가 받은 그 기기의 최근 요청. 다른 기기의 목록이나 감사 로그는
보여 주지 않는다. 터널 안의 아무 기기나 그것을 볼 수 있으면 내부 구조를 알려 주는 셈이다.
그런 것은 서버에서 상태 소켓과 감사 로그로 본다. 실제 사내 앱은 VPN 의 세션 정보를 아예
모른다. 이 페이지가 그것을 보여 주는 것은 서버와 같은 장비에 둔 시험 도구라서다.

터널 주소에만 바인드한다. 0.0.0.0 에서 들으면 인터넷 쪽 주소로도 열려 터널을 지나지 않은
요청이 섞인다. 그래서 서버가 tun 에 주소를 붙인 뒤에 띄워야 한다.

상태 소켓과 기기 목록은 600 이라 root 로 돌린다. 파이썬 표준 라이브러리만 쓴다 (3.9 이상).
페이지가 쓰는 것(CSS, 스크립트)은 전부 이 파일 안에 있다 — 터널 안에서는 인터넷의 CDN 에
닿는다는 보장이 없다.
"""

import argparse
import collections
import datetime
import http.server
import json
import socket
import socketserver
import sys
import threading

RECENT = 8		# 기기마다 기억해 두는 최근 요청 수
POSTURE_KEYS = ("firewall", "antivirus", "disk", "min-build")


def read_status(path):
    """상태 소켓에 붙어 JSON 한 덩어리를 받는다. 서버는 다 쓰면 닫는다 (server/include/status.h)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(path)
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    finally:
        s.close()
    return json.loads(b"".join(chunks))


def read_devices(path):
    """기기 목록에서 id -> {label, require}.

    줄 형식은 '<id> <key> <tun-ip> [조건 ...]  # label' 이다. 라벨은 서버가 등록할 때 붙이는
    주석이고, 조건 중 포스처에 관한 것(firewall= / antivirus= / disk= / min-build=)만 가져온다."""
    devices = {}
    if not path:
        return devices
    try:
        with open(path) as f:
            for line in f:
                body, _, comment = line.partition("#")
                fields = body.split()
                if len(fields) < 3:
                    continue
                require = {}
                for opt in fields[3:]:
                    k, _, v = opt.partition("=")
                    if k in POSTURE_KEYS:
                        require[k] = v
                devices[fields[0].lower()] = {"label": comment.strip() or None, "require": require}
    except OSError as e:
        print("intranet: cannot read %s: %s" % (path, e), file=sys.stderr)
    return devices


class Recent:
    """출발지 주소별 최근 요청. 페이지의 2초 갱신(/whoami?poll)은 넣지 않는다."""

    def __init__(self):
        self.lock = threading.Lock()
        self.by_ip = collections.defaultdict(lambda: collections.deque(maxlen=RECENT))

    def add(self, ip, entry):
        with self.lock:
            self.by_ip[ip].appendleft(entry)

    def get(self, ip):
        with self.lock:
            return list(self.by_ip.get(ip, ()))


class Lookup:
    """요청마다 상태 소켓을 다시 읽는다. 세션은 몇 초 만에 바뀔 수 있고 (거절, 재연결),
    요청은 사람이 누르는 속도로 오므로 캐시할 이유가 없다."""

    def __init__(self, status_path, devices_path):
        self.status_path = status_path
        self.devices_path = devices_path

    def who(self, ip):
        info = {"tunnel_ip": ip, "session": None, "label": None, "require": {}, "error": None}
        try:
            st = read_status(self.status_path)
        except (OSError, ValueError) as e:
            info["error"] = "status socket: %s" % e
            return info
        for sess in st.get("sessions", []):
            if sess.get("tunnel_ip") == ip:
                info["session"] = sess
                dev = read_devices(self.devices_path).get(sess.get("device_id", ""), {})
                info["label"] = dev.get("label")
                info["require"] = dev.get("require", {})
                break
        return info


class Log:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.f = open(path, "a", buffering=1) if path else None

    def write(self, line):
        with self.lock:
            print(line, flush=True)
            if self.f:
                self.f.write(line + "\n")


def make_handler(port, lookup, log, recent):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ip = self.client_address[0]
            path, _, query = self.path.partition("?")
            poll = path == "/whoami" and query == "poll"
            now = datetime.datetime.now().isoformat(timespec="seconds")

            if path == "/favicon.ico":
                self.reply(204, b"", "image/x-icon")
                return

            info = lookup.who(ip)
            if not poll:
                sess = info["session"]
                log.write("%s port=%d src=%s device=%s user=%s %s %s" % (
                    now, port, ip,
                    (info["label"] or sess["device_id"]) if sess else "-",
                    sess["user"]["name"] if sess and sess.get("user") else "-",
                    self.command, self.path))
                recent.add(ip, {"time": now, "port": port, "method": self.command, "path": self.path})

            data = dict(info, port=port, time=now, recent=recent.get(ip))
            if path == "/whoami":
                self.reply(200, json.dumps(data).encode(), "application/json")
            else:
                # 처음 그릴 값을 페이지에 넣어 보낸다. 스크립트가 /whoami 를 한 번 더 기다리는
                # 동안 빈 화면이 보이지 않게. '</' 는 스크립트 블록을 닫지 못하게 바꾼다.
                seed = json.dumps(data).replace("</", "<\\/")
                self.reply(200, PAGE.replace("__SEED__", seed).encode(), "text/html; charset=utf-8")

        def reply(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass	# 요청 로그는 위에서 한 줄로 남긴다

    return Handler


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


PAGE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ztgate 사내 포털</title>
<style>
:root {
  --bg: #f5f6f8; --surface: #ffffff; --border: #e3e6ea; --text: #1b1f24; --muted: #667080;
  --accent: #2f6fed; --ok: #1a8f4c; --ok-bg: #e5f5ec; --bad: #c8372d; --bad-bg: #fbe9e7;
  --warn: #a56a00; --warn-bg: #fdf2dc;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111418; --surface: #1a1e24; --border: #2a3039; --text: #e6e9ee; --muted: #8c96a5;
    --accent: #6c9bff; --ok: #4cc883; --ok-bg: #16301f; --bad: #ff7a6e; --bad-bg: #3a1d1a;
    --warn: #f0b545; --warn-bg: #352a12;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 "Segoe UI", "Malgun Gothic", "Apple SD Gothic Neo", system-ui, sans-serif;
}
header {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 0 24px; height: 56px; display: flex; align-items: center; gap: 12px;
}
.logo { width: 28px; height: 28px; border-radius: 7px; background: var(--accent);
  color: #fff; display: grid; place-items: center; font-weight: 700; }
.brand { font-weight: 600; font-size: 15px; }
.brand small { color: var(--muted); font-weight: 400; margin-left: 6px; }
.pill { margin-left: auto; display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.pill::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.pill.ok { color: var(--ok); background: var(--ok-bg); }
.pill.bad { color: var(--bad); background: var(--bad-bg); }
main { max-width: 1040px; margin: 0 auto; padding: 28px 24px 40px; }
.hero h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; }
.hero p { margin: 0 0 24px; color: var(--muted); }
.banner { display: none; margin: 0 0 20px; padding: 12px 16px; border-radius: 8px;
  background: var(--bad-bg); color: var(--bad); font-weight: 500; }
.banner.show { display: block; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
.card h2 { margin: 0 0 14px; font-size: 13px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: .04em; }
.wide { grid-column: 1 / -1; }
dl { margin: 0; display: grid; grid-template-columns: 110px 1fr; row-gap: 8px; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
.mono { font-family: "Cascadia Mono", Consolas, ui-monospace, monospace; font-size: 13px; }
.checks { list-style: none; margin: 0; padding: 0; }
.checks li { display: flex; align-items: center; justify-content: space-between;
  padding: 9px 0; border-top: 1px solid var(--border); }
.checks li:first-child { border-top: 0; padding-top: 0; }
.tag { font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 6px; }
.tag.ok { color: var(--ok); background: var(--ok-bg); }
.tag.bad { color: var(--bad); background: var(--bad-bg); }
.tag.na { color: var(--muted); background: var(--bg); }
.sub { color: var(--muted); font-size: 12px; margin-left: 6px; }
.stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
.stat .n { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; }
.stat .l { color: var(--muted); font-size: 12px; }
.stat.alert .n { color: var(--warn); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 6px; border-top: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; font-size: 12px; border-top: 0; }
td { font-variant-numeric: tabular-nums; }
.empty { color: var(--muted); padding: 8px 0; }
footer { margin-top: 28px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header>
  <div class="logo">z</div>
  <div class="brand">ztgate<small>사내 포털</small></div>
  <span id="pill" class="pill ok">연결됨</span>
</header>
<main>
  <section class="hero">
    <h1 id="hello">안녕하세요</h1>
    <p id="lead">이 페이지는 터널을 지나 사내망에서 열렸습니다.</p>
  </section>
  <div id="banner" class="banner"></div>
  <div class="grid">
    <section class="card">
      <h2>내 기기</h2>
      <dl>
        <dt>기기</dt><dd id="dev"></dd>
        <dt>기기 ID</dt><dd id="devid" class="mono"></dd>
        <dt>터널 주소</dt><dd id="tip" class="mono"></dd>
        <dt>바깥 주소</dt><dd id="ep" class="mono"></dd>
        <dt>사용자</dt><dd id="user"></dd>
      </dl>
    </section>
    <section class="card">
      <h2>보안 상태</h2>
      <ul id="checks" class="checks"></ul>
    </section>
    <section class="card">
      <h2>내 세션</h2>
      <div class="stats">
        <div class="stat"><div class="n" id="age">-</div><div class="l">연결 시간</div></div>
        <div class="stat" id="deniedbox"><div class="n" id="denied">-</div><div class="l">정책에 막힌 패킷</div></div>
        <div class="stat"><div class="n" id="tx">-</div><div class="l">보낸 데이터</div></div>
        <div class="stat"><div class="n" id="rx">-</div><div class="l">받은 데이터</div></div>
      </div>
    </section>
    <section class="card wide">
      <h2>이 서비스가 받은 내 최근 요청</h2>
      <table>
        <thead><tr><th>시각</th><th>포트</th><th>요청</th></tr></thead>
        <tbody id="recent"></tbody>
      </table>
    </section>
  </div>
  <footer id="foot"></footer>
</main>
<script>
const SEED = __SEED__;
let lastOk = Date.now();

const $ = (id) => document.getElementById(id);
const text = (id, v) => { $(id).textContent = v; };

function bytes(n) {
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}
function dur(s) {
  if (s < 60) return s + "초";
  if (s < 3600) return Math.floor(s / 60) + "분 " + (s % 60) + "초";
  return Math.floor(s / 3600) + "시간 " + Math.floor(s % 3600 / 60) + "분";
}
function hhmmss(iso) { return iso.slice(11, 19); }

/* 서버가 이 기기에 요구하는 조건과 마지막으로 보고된 값을 나란히 둔다.
 * 조건이 없는 항목은 "요구 없음"이고, 판정은 서버가 한다 — 여기서는 보여 주기만 한다. */
function checks(p, req) {
  const state = { on: "켜짐", off: "꺼짐", unknown: "알 수 없음" };
  const rows = [
    ["방화벽", state[p.firewall], req.firewall ? p.firewall === req.firewall : null, req.firewall && "켜짐 필요"],
    ["백신", state[p.antivirus], req.antivirus ? p.antivirus === req.antivirus : null, req.antivirus && "켜짐 필요"],
    ["디스크 암호화", state[p.disk] || state.unknown, req.disk ? p.disk === req.disk : null, req.disk && "켜짐 필요"],
    ["OS 빌드", String(p.os_build), req["min-build"] ? p.os_build >= +req["min-build"] : null,
      req["min-build"] && req["min-build"] + " 이상 필요"],
  ];
  const ul = $("checks");
  ul.replaceChildren();
  for (const [name, val, pass, need] of rows) {
    const li = document.createElement("li");
    const left = document.createElement("span");
    left.textContent = name;
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = val + (need ? " · " + need : "");
    left.append(sub);
    const tag = document.createElement("span");
    tag.className = "tag " + (pass === null ? "na" : pass ? "ok" : "bad");
    tag.textContent = pass === null ? "요구 없음" : pass ? "충족" : "미달";
    li.append(left, tag);
    ul.append(li);
  }
}

function render(d) {
  const s = d.session;
  text("tip", d.tunnel_ip);
  if (!s) {
    text("hello", "세션을 찾지 못했습니다");
    text("lead", d.error || "서버에 이 주소의 세션이 없습니다.");
    return;
  }
  const name = d.label || "이름 없는 기기";
  text("hello", "안녕하세요, " + (s.user ? s.user.name : name) + " 님");
  text("lead", "이 페이지는 터널을 지나 사내망(" + location.host + ")에서 열렸습니다.");
  text("dev", name);
  text("devid", s.device_id);
  text("ep", s.endpoint);
  text("user", s.user ? s.user.name + (s.user.groups.length ? " (" + s.user.groups.join(", ") + ")" : "")
                      : "로그인하지 않음 (기기 인증만)");
  checks(s.posture, d.require || {});
  text("age", dur(s.age_sec));
  text("denied", s.acl_denied.toLocaleString());
  $("deniedbox").classList.toggle("alert", s.acl_denied > 0);
  text("tx", bytes(s.rx_bytes));	/* 서버가 받은 것 = 내가 보낸 것 */
  text("rx", bytes(s.tx_bytes));

  const tb = $("recent");
  tb.replaceChildren();
  if (!d.recent.length) {
    tb.innerHTML = '<tr><td colspan="3" class="empty">아직 없습니다</td></tr>';
  }
  for (const r of d.recent) {
    const tr = document.createElement("tr");
    for (const v of [hhmmss(r.time), r.port, r.method + " " + r.path]) {
      const td = document.createElement("td");
      td.textContent = v;
      tr.append(td);
    }
    tb.append(tr);
  }
  text("foot", "세션 " + s.session_idx + " · 마지막 갱신 " + hhmmss(d.time) +
       " · 시험용 사내 서비스입니다. 실제 사내 앱은 VPN 세션 정보를 알지 못합니다.");
}

function setLink(ok) {
  const pill = $("pill");
  pill.className = "pill " + (ok ? "ok" : "bad");
  pill.textContent = ok ? "연결됨" : "끊김";
  const b = $("banner");
  b.classList.toggle("show", !ok);
  if (!ok) {
    b.textContent = "사내망에 닿지 않습니다 (마지막 응답 " +
      Math.round((Date.now() - lastOk) / 1000) + "초 전). 클라이언트의 연결 상태와 보안 상태를 확인하세요.";
  }
}

/* 응답이 오지 않는 것이 곧 끊긴 것이다. 서버가 세션을 내리거나 ACL 이 막으면 패킷은
 * 조용히 버려지므로 오류가 아니라 시간 초과로 나타난다. */
async function poll() {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 3000);
  try {
    const r = await fetch("/whoami?poll", { signal: ctl.signal, cache: "no-store" });
    const d = await r.json();
    lastOk = Date.now();
    render(d);
    setLink(!!d.session);
  } catch (e) {
    setLink(false);
  } finally {
    clearTimeout(t);
  }
}

render(SEED);
setLink(!!SEED.session);
setInterval(poll, 2000);
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="ztgate test intranet service")
    ap.add_argument("-b", "--bind", default="10.0.0.1", help="server tunnel address")
    ap.add_argument("-p", "--port", type=int, action="append", help="repeatable, default 8080")
    ap.add_argument("-s", "--status", default="/run/ztgate/status.sock")
    ap.add_argument("-d", "--devices", help="device file, for labels and posture requirements")
    ap.add_argument("-l", "--log", help="also append request lines here")
    a = ap.parse_args()

    lookup = Lookup(a.status, a.devices)
    log = Log(a.log)
    recent = Recent()
    servers = []
    for port in a.port or [8080]:
        try:
            servers.append(Server((a.bind, port), make_handler(port, lookup, log, recent)))
        except OSError as e:
            sys.exit("intranet: cannot listen on %s:%d: %s (is the server up?)" % (a.bind, port, e))
        log.write("intranet: listening on %s:%d" % (a.bind, port))

    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
