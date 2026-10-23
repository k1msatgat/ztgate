#!/usr/bin/env python3
"""IdP 의 공개키 묶음(JWKS)을 받아 서버의 jwks 파일을 갈아 끼운다.

    sudo tools/idp/ztgate_jwks.py /etc/ztgate/idp.conf [--reload systemd|pid:<n>|none]

서버는 IdP 와 통신하지 않는다 — 단일 스레드 루프가 HTTPS 응답을 기다리는 동안 모든 터널이
멈추기 때문이다(README 의 "사용자 로그인"). 그래서 IdP 가 서명 키를 바꾸면 관리자가 새 JWKS 를
받아 두고 SIGHUP 을 보내야 했고, 잊으면 새 키로 서명된 토큰이 모두 거절된다. 이 도구가 그 일을
서버 밖에서 한다. ztgate-jwks.timer 가 15분마다 부른다.

    1. idp.conf 의 issuer 에서 OIDC 설정 문서(/.well-known/openid-configuration)를 받고 그
       issuer 가 같은지 본다 (OIDC Discovery 4.3).
    2. 거기 적힌 jwks_uri 에서 묶음을 받는다.
    3. 서명에 쓸 수 있는 키가 하나도 없거나 형식이 틀리면 아무것도 바꾸지 않는다 — 깨진 묶음을
       깔면 모든 로그인이 막힌다.
    4. 지금 파일과 같으면 그대로 둔다. 다르면 옆에 새 파일을 쓰고 이름을 바꾼 뒤 서버에 다시
       읽게 한다 (서버는 깨진 파일이면 이전 키를 그대로 쓴다).

https 만 받는다. 127.0.0.1 / localhost 의 http 는 시험용 IdP 를 위해 받는다. 표준 라이브러리만 쓴다.
"""

import argparse
import json
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

MAX_BYTES = 1 << 20
TIMEOUT = 10


def read_conf(path):
    """idp.conf 의 issuer 와 jwks 파일 경로 (상대 경로는 그 파일 기준, server/src/idp.c 와 같다)."""
    conf = {}
    with open(path) as f:
        for line in f:
            words = line.split("#", 1)[0].split()
            if len(words) >= 2:
                conf[words[0]] = words[1]
    if "issuer" not in conf or "jwks" not in conf:
        sys.exit("%s: issuer and jwks are required" % path)
    jwks = conf["jwks"]
    if not os.path.isabs(jwks):
        jwks = os.path.join(os.path.dirname(os.path.abspath(path)), jwks)
    return conf["issuer"].rstrip("/") if conf["issuer"] != "/" else conf["issuer"], conf["issuer"], jwks


def allowed(url):
    u = urllib.parse.urlsplit(url)
    return u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"))


def get_json(url):
    if not allowed(url):
        raise ValueError("refusing %s (https only, http only for 127.0.0.1)" % url)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("%s: larger than %d bytes" % (url, MAX_BYTES))
    return json.loads(body.decode())


def signing_keys(jwks):
    """서버가 쓸 수 있는 키의 kid 들 (server/src/idp.c 와 같은 기준: RSA / P-256, 서명용, kid 있음)."""
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ValueError("not a JWKS (no keys list)")
    kids = []
    for k in jwks["keys"]:
        if not isinstance(k, dict) or not k.get("kid") or k.get("use", "sig") != "sig":
            continue
        if k.get("kty") == "RSA" and k.get("n") and k.get("e"):
            kids.append(k["kid"])
        elif k.get("kty") == "EC" and k.get("crv") == "P-256" and k.get("x") and k.get("y"):
            kids.append(k["kid"])
    return kids


def reload_server(how):
    if how == "none":
        return
    if how == "systemd":
        subprocess.run(["systemctl", "reload", "ztgate"], check=True)
        return
    if how.startswith("pid:"):
        os.kill(int(how[4:]), signal.SIGHUP)
        return
    raise ValueError("--reload must be systemd, pid:<n> or none")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("conf", help="the server's idp.conf")
    ap.add_argument("--reload", default="systemd", help="systemd (systemctl reload ztgate), pid:<n> (SIGHUP) or none")
    a = ap.parse_args()

    base, issuer, path = read_conf(a.conf)
    try:
        disc = get_json(base + "/.well-known/openid-configuration")
        if disc.get("issuer") != issuer:
            raise ValueError("the discovery document's issuer %r is not %r" % (disc.get("issuer"), issuer))
        if not disc.get("jwks_uri"):
            raise ValueError("the discovery document has no jwks_uri")
        jwks = get_json(disc["jwks_uri"])
        kids = signing_keys(jwks)
        if not kids:
            raise ValueError("no signing keys in %s" % disc["jwks_uri"])
    except (OSError, ValueError) as e:
        # 받지 못했으면 지금 파일을 그대로 둔다. 서버는 그 키로 계속 받는다.
        print("ztgate_jwks: keeping %s: %s" % (path, e), file=sys.stderr)
        return 1

    new = json.dumps(jwks, indent=2, sort_keys=True) + "\n"
    try:
        with open(path) as f:
            if json.load(f) == jwks:
                print("ztgate_jwks: unchanged (%s)" % ", ".join(kids))
                return 0
    except (OSError, ValueError):
        pass

    fd, tmp = tempfile.mkstemp(prefix=".jwks.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        os.unlink(tmp)
        raise

    print("ztgate_jwks: updated %s (%s)" % (path, ", ".join(kids)))
    reload_server(a.reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
