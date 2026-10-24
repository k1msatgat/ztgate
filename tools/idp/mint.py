#!/usr/bin/env python3
"""IdP 없이 사용자 토큰(JWT)을 만들어 보는 도구. 시험과 데모에 쓴다.

실제 IdP(Keycloak, Entra ID, Okta ...)가 하는 일 중 서버가 보는 부분만 한다 — 서명 키를
만들어 공개키 묶음(JWKS)으로 내놓고, 그 키로 토큰에 서명한다. 서버(vpn_server -u)는
토큰이 이 도구에서 왔는지 실제 IdP 에서 왔는지 구분하지 않는다.

    tools/idp/mint.py keys <dir>
        <dir>/rs256.pem, <dir>/es256.pem (개인키), <dir>/jwks.json (공개키),
        <dir>/idp.conf (서버의 -u 에 줄 설정) 를 만든다.

    tools/idp/mint.py token <dir> <user> [--groups dev,ops] [--ttl 600] [--alg RS256|ES256]
        표준 출력으로 토큰 한 줄. 시험을 위해 클레임을 틀리게 만드는 옵션이 있다
        (--iss, --aud, --exp, --nbf, --kid, --header-alg, --claim k=v). --dpop-key <pem> 이면 그 키에
        묶인 토큰(cnf.jkt)을 만든다.

    tools/idp/mint.py dpop-key <pem>              기기의 DPoP 키(P-256)를 만들고 지문(jkt)을 찍는다
    tools/idp/mint.py dpop-proof <pem> <token>    LOGIN 에 실을 증명 한 줄 (proto.h 의 "DPoP")

표준 라이브러리와 openssl 명령만 쓴다. 서명은 `openssl dgst -sign` 이 하고, ES256 은 그
결과(DER)를 JWS 의 r | s 형식으로 바꾼다.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

ISSUER = "https://idp.example.test/realms/ztgate"
AUDIENCE = "ztgate"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def openssl(*args, data=None):
    return subprocess.run(["openssl"] + list(args), input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def der_items(der):
    """DER SEQUENCE 안의 원소들 (tag, 값). 길이는 짧은 형식과 긴 형식 모두."""
    assert der[0] == 0x30
    i, out = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F), []
    while i < len(der):
        tag, n = der[i], der[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(der[i:i + k], "big")
            i += k
        out.append((tag, der[i:i + n]))
        i += n
    return out


def ec_point(pem):
    """P-256 개인키 파일의 공개키 (X, Y)."""
    point = openssl("ec", "-in", pem, "-pubout", "-outform", "DER")[-65:]
    return point[1:33], point[33:65]


def dpop_jwk(pem):
    x, y = ec_point(pem)
    return {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y)}


def dpop_jkt(pem):
    """RFC 7638 지문: 정해진 키들만, 사전 순서로, 공백 없이 쓴 JSON 의 SHA-256."""
    j = dpop_jwk(pem)
    canon = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (j["crv"], j["kty"], j["x"], j["y"])
    return b64url(hashlib.sha256(canon.encode()).digest())


def es256_sign(pem, signing_input):
    der = openssl("dgst", "-sha256", "-sign", pem, data=signing_input)
    r, s = (v for _, v in der_items(der))
    return int.from_bytes(r, "big").to_bytes(32, "big") + int.from_bytes(s, "big").to_bytes(32, "big")


def dpop_proof(pem, tok, htm="LOGIN", htu="ztgate:login", iat=None, jti=None, ath=None, jwk=None, typ="dpop+jwt"):
    header = {"typ": typ, "alg": "ES256", "jwk": jwk or dpop_jwk(pem)}
    body = {"htm": htm, "htu": htu, "iat": int(time.time()) if iat is None else iat,
            "jti": jti or b64url(os.urandom(16)),
            "ath": ath or b64url(hashlib.sha256(tok.encode()).digest())}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     b64url(json.dumps(body, separators=(",", ":")).encode())).encode()
    return (signing_input + b"." + b64url(es256_sign(pem, signing_input)).encode()).decode()


def rsa_jwk(pem, kid):
    modulus = openssl("rsa", "-in", pem, "-noout", "-modulus").decode().strip().split("=", 1)[1]
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64url(bytes.fromhex(modulus)), "e": b64url((65537).to_bytes(3, "big"))}


def ec_jwk(pem, kid):
    point = openssl("ec", "-in", pem, "-pubout", "-outform", "DER")[-65:]   # 0x04 | X | Y
    assert point[0] == 4
    return {"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
            "x": b64url(point[1:33]), "y": b64url(point[33:65])}


def make_keys(d):
    os.makedirs(d, exist_ok=True)
    rs, es = os.path.join(d, "rs256.pem"), os.path.join(d, "es256.pem")
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rs)
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", es)
    os.chmod(rs, 0o600)
    os.chmod(es, 0o600)

    # IdP 가 실제로 내놓는 묶음처럼 서명에 쓰지 않는 키도 하나 섞는다 (서버는 건너뛰어야 한다).
    enc = dict(rsa_jwk(rs, "enc-1"), use="enc", alg="RSA-OAEP")
    jwks = {"keys": [rsa_jwk(rs, "rs-1"), ec_jwk(es, "es-1"), enc]}
    with open(os.path.join(d, "jwks.json"), "w") as f:
        json.dump(jwks, f, indent=2)
    with open(os.path.join(d, "idp.conf"), "w") as f:
        f.write("# tools/idp/mint.py 가 만든 시험용 IdP\n")
        f.write("issuer        %s\naudience      %s\njwks          jwks.json\n" % (ISSUER, AUDIENCE))
        f.write("user-claim    preferred_username\ngroups-claim  groups\n")


def sign(d, alg, signing_input):
    if alg == "RS256":
        return openssl("dgst", "-sha256", "-sign", os.path.join(d, "rs256.pem"), data=signing_input)
    der = openssl("dgst", "-sha256", "-sign", os.path.join(d, "es256.pem"), data=signing_input)
    r, s = (int.from_bytes(v, "big") for _, v in der_items(der))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def token(d, user, groups=(), ttl=600, alg="RS256", iss=ISSUER, aud=AUDIENCE, exp=None, nbf=None,
          kid=None, header_alg=None, claims=None, now=None):
    now = int(time.time()) if now is None else now
    header = {"alg": header_alg or alg, "typ": "JWT", "kid": kid or ("rs-1" if alg == "RS256" else "es-1")}
    body = {"iss": iss, "aud": aud, "sub": "id-" + user, "preferred_username": user,
            "iat": now, "exp": now + ttl if exp is None else exp}
    if groups:
        body["groups"] = list(groups)
    if nbf is not None:
        body["nbf"] = nbf
    body.update(claims or {})
    body = {k: v for k, v in body.items() if v is not None}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     b64url(json.dumps(body, separators=(",", ":")).encode())).encode()
    return (signing_input + b"." + b64url(sign(d, alg, signing_input)).encode()).decode()


def raw_token(d, payload_json, alg="RS256"):
    """페이로드를 JSON 문자열 그대로 서명한다. dict 로는 만들 수 없는 것(같은 키 두 번)을
    시험할 때 쓴다."""
    header = {"alg": alg, "typ": "JWT", "kid": "rs-1" if alg == "RS256" else "es-1"}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     b64url(payload_json.encode())).encode()
    return (signing_input + b"." + b64url(sign(d, alg, signing_input)).encode()).decode()


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keys")
    k.add_argument("dir")
    t = sub.add_parser("token")
    t.add_argument("dir")
    t.add_argument("user")
    t.add_argument("--groups", default="")
    t.add_argument("--ttl", type=int, default=600)
    t.add_argument("--alg", choices=["RS256", "ES256"], default="RS256")
    t.add_argument("--iss", default=ISSUER)
    t.add_argument("--aud", default=AUDIENCE)
    t.add_argument("--exp", type=int)
    t.add_argument("--nbf", type=int)
    t.add_argument("--kid")
    t.add_argument("--header-alg")
    t.add_argument("--claim", action="append", default=[], help="k=v (v 는 JSON 이면 JSON 으로)")
    t.add_argument("--dpop-key", help="이 키(P-256 PEM)에 묶는다 (cnf.jkt)")
    dk = sub.add_parser("dpop-key")
    dk.add_argument("pem")
    dp = sub.add_parser("dpop-proof")
    dp.add_argument("pem")
    dp.add_argument("token")
    a = p.parse_args()

    if a.cmd == "keys":
        make_keys(a.dir)
        print("keys, jwks.json and idp.conf written to %s" % a.dir)
        return
    if a.cmd == "dpop-key":
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", a.pem)
        os.chmod(a.pem, 0o600)
        print(dpop_jkt(a.pem))
        return
    if a.cmd == "dpop-proof":
        print(dpop_proof(a.pem, a.token))
        return

    claims = {}
    for kv in a.claim:
        key, val = kv.split("=", 1)
        try:
            claims[key] = json.loads(val)
        except ValueError:
            claims[key] = val
    if a.dpop_key:
        claims["cnf"] = {"jkt": dpop_jkt(a.dpop_key)}
    print(token(a.dir, a.user, [g for g in a.groups.split(",") if g], a.ttl, a.alg, a.iss, a.aud,
                a.exp, a.nbf, a.kid, a.header_alg, claims))


if __name__ == "__main__":
    sys.exit(main())
