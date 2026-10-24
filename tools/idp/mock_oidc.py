#!/usr/bin/env python3
"""시험용 OIDC 서버. 로그인 도구들의 흐름을 IdP 없이 끝까지 돌려 보려고 만든다.

    tools/idp/mock_oidc.py <keys-dir> <port> <user> [--groups ops] [--ttl 600]
                           [--issuer URL] [--auto-approve]

mint.py keys 로 만든 키로 토큰을 발급한다. 127.0.0.1 에서만 듣는다. 두 가지 로그인을 받는다.

- 기기 인가 (RFC 8628, client/ztgate_login): 첫 번째 폴링에 "아직"(authorization_pending)을 한
  번 돌려준 뒤 승인된 것으로 친다 — 사람이 브라우저에서 로그인한 것처럼.
- 인가 코드 + PKCE (RFC 7636 / 8252, Windows GUI): /authorize 가 로그인 버튼 하나짜리 화면을
  보여 주고, 누르면 브라우저를 앱의 redirect_uri 로 돌려보낸다. --auto-approve 면 화면 없이
  바로 돌려보낸다 (자동 시험). 토큰을 줄 때 code_verifier 의 SHA-256 이 처음 받은
  code_challenge 와 같은지, redirect_uri 와 client_id 가 같은지 본다. 코드는 한 번만 쓰인다.

refresh token 으로 새 토큰도 준다 (한 번 쓴 refresh token 은 버린다). /revoke 는 RFC 7009 대로
refresh token 을 버린다.

시험용 어긋남:
- --refresh-delay SEC: refresh 요청에 늦게 답한다 (갱신 중에 로그아웃하는 경우).
- --exp-offset SEC: 토큰의 exp 를 그만큼 옮긴다. 음수로 주면 서버의 시계보다 앞서 끝난 토큰,
  곧 PC 와 서버의 시계가 어긋난 경우가 된다.

--issuer: 설정 문서와 토큰의 iss. 기본은 mint.ISSUER. Windows GUI 는 설정한 발급자 주소와
설정 문서의 issuer 가 같은지 보므로(OIDC Discovery 4.3) 그때는 이 서버의 주소
(http://127.0.0.1:<port>)를 준다. 서버의 idp.conf 의 issuer 도 같은 값이어야 한다.

실제 IdP 와의 호환은 이것으로 확인되지 않는다. 확인되는 것은 로그인 도구가 각 RFC 의
순서대로 움직이는지다.
"""

import argparse
import base64
import hashlib
import html
import http.server
import json
import os
import secrets
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint  # noqa: E402


def loopback_redirect(uri):
    """앱이 돌려받을 주소는 이 PC 안(127.0.0.1 / localhost)의 http 여야 한다 (RFC 8252 7.3)."""
    u = urllib.parse.urlsplit(uri)
    return u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost") and u.port is not None


def s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("keys")
    p.add_argument("port", type=int)
    p.add_argument("user")
    p.add_argument("--groups", default="")
    p.add_argument("--ttl", type=int, default=600)
    p.add_argument("--issuer", default=mint.ISSUER)
    p.add_argument("--auto-approve", action="store_true")
    p.add_argument("--refresh-delay", type=float, default=0)
    p.add_argument("--exp-offset", type=int, default=0)
    a = p.parse_args()

    base = "http://127.0.0.1:%d" % a.port
    groups = [g for g in a.groups.split(",") if g]
    state = {"polls": 0, "refresh": set(), "issued": 0, "codes": {}, "pending": {}}

    def issue(jkt=None):
        state["issued"] += 1
        rt = secrets.token_urlsafe(16)
        state["refresh"].add(rt)
        now = int(time.time())
        tok = mint.token(a.keys, a.user, groups=groups, ttl=a.ttl, iss=a.issuer,
                         exp=now + a.ttl + a.exp_offset, now=now,
                         claims={"cnf": {"jkt": jkt}} if jkt else None)
        return {"access_token": tok, "token_type": "DPoP" if jkt else "Bearer", "expires_in": a.ttl, "refresh_token": rt}

    def dpop_jkt(proof, htu):
        """DPoP 헤더의 증명이 이 토큰 엔드포인트에 대한 것이면 그 키의 지문. 시험용이라 서명은 보지
        않는다 (실제 IdP 가 하는 일이다) — 서버가 LOGIN 에서 서명을 보므로, 남의 키를 적은 증명으로
        받은 토큰은 그 키 없이는 쓸 수 없다."""
        try:
            head, body, _ = proof.split(".")
            h = json.loads(base64.urlsafe_b64decode(head + "=="))
            b = json.loads(base64.urlsafe_b64decode(body + "=="))
        except ValueError:
            return None
        if h.get("typ") != "dpop+jwt" or b.get("htm") != "POST" or b.get("htu") != htu:
            return None
        j = h.get("jwk", {})
        canon = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (j.get("crv"), j.get("kty"), j.get("x"), j.get("y"))
        return mint.b64url(hashlib.sha256(canon.encode()).digest())

    def approved(req):
        """인가 요청 하나를 승인한다. 코드를 만들고 앱으로 돌아갈 주소를 돌려준다."""
        code = secrets.token_urlsafe(24)
        state["codes"][code] = req
        q = urllib.parse.urlencode({"code": code, "state": req["state"]})
        return req["redirect_uri"] + ("&" if "?" in req["redirect_uri"] else "?") + q

    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def page(self, code, title, body):
            data = ("<!doctype html><meta charset=utf-8><title>mock IdP</title>"
                    "<body style=\"font-family:sans-serif;max-width:420px;margin:80px auto\">"
                    "<h2>%s</h2>%s</body>" % (html.escape(title), body)).encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def redirect(self, location):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            # 질의에 코드와 state 가 실린다. 경로만 남긴다.
            print("mock_oidc: " + (fmt % args).split("?", 1)[0], flush=True)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if u.path == "/.well-known/openid-configuration":
                return self.reply(200, {"issuer": a.issuer, "token_endpoint": base + "/token",
                                        "authorization_endpoint": base + "/authorize",
                                        "device_authorization_endpoint": base + "/device",
                                        "revocation_endpoint": base + "/revoke",
                                        "jwks_uri": base + "/jwks",
                                        "code_challenge_methods_supported": ["S256"]})
            if u.path == "/jwks":
                # 키 폴더의 jwks.json 을 그대로 (mint.py keys). 갱신 도구(tools/idp/ztgate_jwks.py)가 받아 간다.
                with open(os.path.join(a.keys, "jwks.json")) as f:
                    return self.reply(200, json.load(f))
            if u.path == "/authorize":
                if (q.get("response_type") != "code" or not q.get("client_id") or not q.get("state")
                        or q.get("code_challenge_method") != "S256" or len(q.get("code_challenge", "")) != 43
                        or not loopback_redirect(q.get("redirect_uri", ""))):
                    return self.page(400, "잘못된 인가 요청", "<p>response_type=code, S256 PKCE, "
                                     "127.0.0.1 의 redirect_uri 가 있어야 합니다.</p>")
                req = {k: q[k] for k in ("client_id", "redirect_uri", "state", "code_challenge")}
                if a.auto_approve:
                    return self.redirect(approved(req))
                rid = secrets.token_urlsafe(12)
                state["pending"][rid] = req
                return self.page(200, "mock IdP 로그인",
                                 "<p><b>%s</b> 로 로그인합니다 (그룹: %s).</p>"
                                 "<form action=/approve><input type=hidden name=r value=%s>"
                                 "<button style=\"font-size:16px;padding:8px 20px\">로그인</button></form>"
                                 % (html.escape(a.user), html.escape(",".join(groups) or "없음"), rid))
            if u.path == "/approve":
                req = state["pending"].pop(q.get("r", ""), None)
                if req is None:
                    return self.page(400, "끝난 요청", "<p>앱에서 다시 로그인하세요.</p>")
                return self.redirect(approved(req))
            self.reply(404, {})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
            if self.path == "/revoke":
                gone = form.get("token") in state["refresh"]
                state["refresh"].discard(form.get("token"))
                print("mock_oidc: revoked %s" % ("a live refresh token" if gone else "an unknown token"), flush=True)
                return self.reply(200, {})
            if self.path == "/device":
                return self.reply(200, {"device_code": "dc", "user_code": "WDJB-MJHT",
                                        "verification_uri": base + "/activate", "interval": 1, "expires_in": 60})
            if self.path != "/token":
                return self.reply(404, {})
            grant = form.get("grant_type")
            jkt = None
            if self.headers.get("DPoP"):
                jkt = dpop_jkt(self.headers["DPoP"], base + "/token")
                if jkt is None:
                    return self.reply(400, {"error": "invalid_dpop_proof"})
                print("mock_oidc: a DPoP-bound token for jkt %s" % jkt, flush=True)
            if grant == "urn:ietf:params:oauth:grant-type:device_code":
                state["polls"] += 1
                if state["polls"] == 1:
                    return self.reply(400, {"error": "authorization_pending"})
                return self.reply(200, issue(jkt))
            if grant == "authorization_code":
                req = state["codes"].pop(form.get("code", ""), None)     # 코드는 한 번만
                if (req is None or form.get("client_id") != req["client_id"]
                        or form.get("redirect_uri") != req["redirect_uri"]):
                    return self.reply(400, {"error": "invalid_grant"})
                if s256(form.get("code_verifier", "")) != req["code_challenge"]:
                    return self.reply(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                return self.reply(200, issue(jkt))
            if grant == "refresh_token" and a.refresh_delay:
                print("mock_oidc: holding a refresh for %gs" % a.refresh_delay, flush=True)
                time.sleep(a.refresh_delay)
            if grant == "refresh_token" and form.get("refresh_token") in state["refresh"]:
                state["refresh"].discard(form["refresh_token"])     # 한 번 쓴 refresh token 은 버린다
                return self.reply(200, issue(jkt))
            self.reply(400, {"error": "invalid_grant"})

    http.server.ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
