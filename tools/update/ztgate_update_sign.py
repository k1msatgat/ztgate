#!/usr/bin/env python3
"""Windows 자동 업데이트의 매니페스트에 서명한다 (windows/core/update.h).

서비스는 정책 UpdatePublicKey 에 적힌 공개키로 서명이 맞는 매니페스트만 따른다. 업데이트 서버를
차지한 쪽도 서명 키가 없으면 PC 에 아무것도 설치시키지 못한다. 서명 키는 업데이트 서버에 두지 않는다.

    tools/update/ztgate_update_sign.py genkey <key.pem>
        서명 키(P-256)를 만들고(600), 정책 UpdatePublicKey 에 넣을 공개키(128 hex)를 찍는다.

    tools/update/ztgate_update_sign.py pubkey <key.pem>
        그 키의 공개키(128 hex).

    tools/update/ztgate_update_sign.py manifest <key.pem> <version> <msi 파일> <msi 주소>
        표준 출력으로 서명한 매니페스트:
        {"version": ..., "msi": ..., "sha256": ..., "sig": <128 hex>}

    tools/update/ztgate_update_sign.py verify <공개키 hex> <manifest.json>
        서명이 맞으면 "ok" 와 0, 아니면 "bad signature" 와 1.

서명하는 것은 "ztgate update v1\\n" + version + "\\n" + sha256(소문자 hex) 이다 (ECDSA P-256, SHA-256,
r | s 64바이트). MSI 의 주소는 서명하지 않는다 — 해시가 내용을 정하므로 다른 곳에 올려 두어도 된다.

표준 라이브러리와 openssl 명령만 쓴다.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

LABEL = b"ztgate update v1\n"
# P-256 공개키의 SubjectPublicKeyInfo 머리 (DER). 뒤에 04 | X | Y 가 붙는다.
SPKI_P256 = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def openssl(*args, data=None):
    return subprocess.run(["openssl"] + list(args), input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def der_ints(der):
    """ECDSA 서명(DER SEQUENCE { r, s })의 두 정수."""
    assert der[0] == 0x30
    i, out = 2, []
    while i < len(der):
        n = der[i + 1]
        out.append(int.from_bytes(der[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return out


def der_int(v):
    b = v.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if b[0] & 0x80:
        b = b"\0" + b
    return b"\x02" + bytes([len(b)]) + b


def pubkey(pem):
    point = openssl("ec", "-in", pem, "-pubout", "-outform", "DER")[-65:]
    assert point[0] == 4
    return point[1:].hex()


def message(version, sha256):
    return LABEL + version.encode() + b"\n" + sha256.encode()


def valid_version(v):
    return re.fullmatch(r"\d{1,5}(\.\d{1,5}){0,3}", v) is not None and all(int(p) <= 0xFFFF for p in v.split("."))


def sign(pem, msg):
    r, s = der_ints(openssl("dgst", "-sha256", "-sign", pem, data=msg))
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verify(pub_hex, msg, sig_hex):
    pub, sig = bytes.fromhex(pub_hex), bytes.fromhex(sig_hex)
    if len(pub) != 64 or len(sig) != 64:
        return False
    der = der_int(int.from_bytes(sig[:32], "big")) + der_int(int.from_bytes(sig[32:], "big"))
    der = b"\x30" + bytes([len(der)]) + der
    with tempfile.TemporaryDirectory() as d:
        key, sigf = os.path.join(d, "pub.der"), os.path.join(d, "sig.der")
        with open(key, "wb") as f:
            f.write(SPKI_P256 + b"\x04" + pub)
        with open(sigf, "wb") as f:
            f.write(der)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", key, "-keyform", "DER", "-signature", sigf],
                           input=msg, capture_output=True)
    return r.returncode == 0


def main():
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "genkey":
        old = os.umask(0o077)
        try:
            openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", a[1])
        finally:
            os.umask(old)
        print(pubkey(a[1]))
        return 0
    if len(a) == 2 and a[0] == "pubkey":
        print(pubkey(a[1]))
        return 0
    if len(a) == 5 and a[0] == "manifest":
        pem, version, msi, url = a[1:]
        if not valid_version(version):
            print("version must be up to four numbers like 0.9.3", file=sys.stderr)
            return 2
        with open(msi, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        print(json.dumps({"version": version, "msi": url, "sha256": sha, "sig": sign(pem, message(version, sha))}))
        return 0
    if len(a) == 3 and a[0] == "verify":
        with open(a[2]) as f:
            m = json.load(f)
        ok = verify(a[1], message(m["version"], m["sha256"]), m.get("sig", ""))
        print("ok" if ok else "bad signature")
        return 0 if ok else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
