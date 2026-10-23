#!/usr/bin/env python3
"""서버의 기기 인증과 세션 암호화를 프로토콜 수준에서 확인한다.

임시 기기 목록으로 vpn_server 를 띄우고, 클라이언트인 척 UDP 패킷을 직접 만들어
보내 응답을 본다. 서버의 tun 에 10.0.0.1/24 를 붙여 터널로 들어간 ping 에 커널이
답하게 하므로, 다른 vpn_server 가 돌고 있는 동안에는 쓸 수 없다.
TUN 을 만들고 주소를 붙여야 해서 root 로 돌린다.

    sudo python3 test/auth_check.py [port] [-v]      (-v: 서버 로그도 출력)

와이어 포맷은 lib/common/include/proto.h 의 주석과, 세션 키를 뽑는 방법은
lib/common/include/secure.h 의 주석과 같아야 한다. 여기서는 그 둘을 서버의 코드를
거치지 않고 따로 구현한다 — 같은 코드를 불러 쓰면 양쪽이 같은 방식으로 틀려도
맞는 것으로 나온다.

ECDH 와 AES-GCM 은 파이썬 표준 라이브러리에 없다. 서버가 이미 링크하는 libcrypto 를
ctypes 로 직접 부른다. 패키지를 따로 설치하지 않아도 되고, 서버가 도는 곳이면
어디서나 돈다.
"""

import base64
import ctypes
import ctypes.util
import hashlib
import json
import hmac
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "server", "bin", "vpn_server")
PORT = int(next((a for a in sys.argv[1:] if a.isdigit()), 19000))
VERSION = 6

REQ_HANDSHAKE, RES_HANDSHAKE, DATA, KEEPALIVE, CHALLENGE, AUTH, DENY, ENROLL, LOGIN, DISCONNECT = range(1, 11)
DISCONNECT_CLIENT_EXIT, DISCONNECT_SERVER_SHUTDOWN = 1, 2
DENY_UNKNOWN_DEVICE, DENY_BAD_AUTH, DENY_TUN_IP, DENY_POSTURE = range(1, 5)
STATE_UNKNOWN, STATE_OFF, STATE_ON = range(3)
TYPE_NAME = {RES_HANDSHAKE: "RES_HANDSHAKE", DATA: "DATA", KEEPALIVE: "KEEPALIVE",
             CHALLENGE: "CHALLENGE", DENY: "DENY", ENROLL: "ENROLL", LOGIN: "LOGIN",
             DISCONNECT: "DISCONNECT"}

HDR_LEN, PUB_LEN, TAG_LEN, MAC_LEN = 8, 64, 16, 32

DEV_ID = bytes(range(0x10, 0x20))
DEV_KEY = bytes(range(0x40, 0x60))
TUN_IP = socket.inet_aton("10.0.0.3")

# 포스처 조건이 걸린 기기
DEV2_ID = bytes(range(0x20, 0x30))
DEV2_KEY = bytes(range(0x60, 0x80))
TUN2_IP = socket.inet_aton("10.0.0.4")

failed = 0


# ---- libcrypto ------------------------------------------------------------------

def _load_libcrypto():
    for name in (ctypes.util.find_library("crypto"), "libcrypto.so.3"):
        if name:
            try:
                return ctypes.CDLL(name)
            except OSError:
                pass
    sys.exit("libcrypto not found (vpn_server links it as well)")


_lib = _load_libcrypto()
_ptr, _int, _size, _buf = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_char_p


def _fn(name, restype, *argtypes):
    f = getattr(_lib, name)
    f.restype, f.argtypes = restype, argtypes
    return f


# 포인터를 돌려주는 함수는 restype 을 적어야 한다. 적지 않으면 ctypes 가 int 로 받아
# 64비트 주소의 위쪽 절반을 잘라 버린다.
_pkey_ctx_new_id = _fn("EVP_PKEY_CTX_new_id", _ptr, _int, _ptr)
_pkey_ctx_new = _fn("EVP_PKEY_CTX_new", _ptr, _ptr, _ptr)
_pkey_ctx_free = _fn("EVP_PKEY_CTX_free", None, _ptr)
_keygen_init = _fn("EVP_PKEY_keygen_init", _int, _ptr)
_set_curve = _fn("EVP_PKEY_CTX_set_ec_paramgen_curve_nid", _int, _ptr, _int)
_keygen = _fn("EVP_PKEY_keygen", _int, _ptr, ctypes.POINTER(_ptr))
_pkey_new = _fn("EVP_PKEY_new", _ptr)
_pkey_free = _fn("EVP_PKEY_free", None, _ptr)
_copy_params = _fn("EVP_PKEY_copy_parameters", _int, _ptr, _ptr)
_set_pub = _fn("EVP_PKEY_set1_encoded_public_key", _int, _ptr, _buf, _size)
_get_octets = _fn("EVP_PKEY_get_octet_string_param", _int, _ptr, _buf, _buf, _size, ctypes.POINTER(_size))
_derive_init = _fn("EVP_PKEY_derive_init", _int, _ptr)
_derive_set_peer = _fn("EVP_PKEY_derive_set_peer", _int, _ptr, _ptr)
_derive = _fn("EVP_PKEY_derive", _int, _ptr, _buf, ctypes.POINTER(_size))

_cipher_ctx_new = _fn("EVP_CIPHER_CTX_new", _ptr)
_cipher_ctx_free = _fn("EVP_CIPHER_CTX_free", None, _ptr)
_cipher_ctrl = _fn("EVP_CIPHER_CTX_ctrl", _int, _ptr, _int, _int, _buf)
_aes_256_gcm = _fn("EVP_aes_256_gcm", _ptr)
_enc_init = _fn("EVP_EncryptInit_ex", _int, _ptr, _ptr, _ptr, _buf, _buf)
_enc_update = _fn("EVP_EncryptUpdate", _int, _ptr, _buf, ctypes.POINTER(_int), _buf, _int)
_enc_final = _fn("EVP_EncryptFinal_ex", _int, _ptr, _buf, ctypes.POINTER(_int))
_dec_init = _fn("EVP_DecryptInit_ex", _int, _ptr, _ptr, _ptr, _buf, _buf)
_dec_update = _fn("EVP_DecryptUpdate", _int, _ptr, _buf, ctypes.POINTER(_int), _buf, _int)
_dec_final = _fn("EVP_DecryptFinal_ex", _int, _ptr, _buf, ctypes.POINTER(_int))

EVP_PKEY_EC, NID_P256 = 408, 415
GCM_GET_TAG, GCM_SET_TAG = 0x10, 0x11


def _must(ok, what):
    if not ok or ok <= 0:
        raise RuntimeError("libcrypto: %s failed" % what)


class Ecdh:
    """한 번 쓰고 버리는 P-256 키 쌍. pub 은 와이어 형식 X(32) | Y(32)."""

    def __init__(self):
        ctx = _pkey_ctx_new_id(EVP_PKEY_EC, None)
        self.key = _ptr()
        _must(_keygen_init(ctx), "keygen_init")
        _must(_set_curve(ctx, NID_P256), "set_curve")
        _must(_keygen(ctx, ctypes.byref(self.key)), "keygen")
        _pkey_ctx_free(ctx)

        point = ctypes.create_string_buffer(1 + PUB_LEN)
        n = _size(0)
        _must(_get_octets(self.key, b"pub", point, len(point), ctypes.byref(n)), "get pub")
        assert n.value == 1 + PUB_LEN and point.raw[0] == 4
        self.pub = point.raw[1:]

    def secret(self, peer_pub):
        """SHA-256(공유점의 X 좌표). 상대의 점이 곡선 위에 없으면 예외."""
        peer = _pkey_new()
        _must(_copy_params(peer, self.key), "copy_parameters")
        _must(_set_pub(peer, b"\x04" + peer_pub, 1 + PUB_LEN), "set peer public key")
        ctx = _pkey_ctx_new(self.key, None)
        _must(_derive_init(ctx), "derive_init")
        _must(_derive_set_peer(ctx, peer), "derive_set_peer")
        x = ctypes.create_string_buffer(32)
        n = _size(32)
        _must(_derive(ctx, x, ctypes.byref(n)), "derive")
        _pkey_ctx_free(ctx)
        _pkey_free(peer)
        return hashlib.sha256(x.raw[:n.value]).digest()


def gcm_seal(key, nonce, aad, plain):
    ctx = _cipher_ctx_new()
    out = ctypes.create_string_buffer(len(plain) + 16)
    tag = ctypes.create_string_buffer(TAG_LEN)
    n = _int(0)
    _must(_enc_init(ctx, _aes_256_gcm(), None, key, nonce), "EncryptInit")
    _must(_enc_update(ctx, None, ctypes.byref(n), aad, len(aad)), "aad")
    if plain:
        _must(_enc_update(ctx, out, ctypes.byref(n), plain, len(plain)), "EncryptUpdate")
    _must(_enc_final(ctx, tag, ctypes.byref(n)), "EncryptFinal")
    _must(_cipher_ctrl(ctx, GCM_GET_TAG, TAG_LEN, tag), "get tag")
    _cipher_ctx_free(ctx)
    return out.raw[:len(plain)] + tag.raw


def gcm_open(key, nonce, aad, sealed):
    """평문, tag 가 맞지 않으면 None."""
    if len(sealed) < TAG_LEN:
        return None
    body, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    ctx = _cipher_ctx_new()
    out = ctypes.create_string_buffer(len(body) + 16)
    n = _int(0)
    _must(_dec_init(ctx, _aes_256_gcm(), None, key, nonce), "DecryptInit")
    _must(_dec_update(ctx, None, ctypes.byref(n), aad, len(aad)), "aad")
    if body:
        _must(_dec_update(ctx, out, ctypes.byref(n), body, len(body)), "DecryptUpdate")
    _must(_cipher_ctrl(ctx, GCM_SET_TAG, TAG_LEN, tag), "set tag")
    ok = _dec_final(ctx, tag, ctypes.byref(n)) > 0
    _cipher_ctx_free(ctx)
    return out.raw[:len(body)] if ok else None


# ---- 프로토콜 ---------------------------------------------------------------------

def header(msg_type, session_idx=0):
    return struct.pack("!BBHI", VERSION, msg_type, 0, session_idx)


def posture(build=26200, firewall=STATE_ON, antivirus=STATE_ON):
    return struct.pack("!IBB2x", build, firewall, antivirus)


def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def session_keys(dev_key, secret, auth_pkt, res_head):
    """(C->S 키, S->C 키, RES_HANDSHAKE 키). secure.h 의 "세션 키"."""
    info = b"ztgate v6 session" + hashlib.sha256(auth_pkt + res_head).digest()
    prk = mac(dev_key, secret)                  # HKDF-Extract(salt = 기기 키, ikm = secret)
    okm, block = b"", b""
    for i in (1, 2, 3):                         # HKDF-Expand, 96 바이트
        block = mac(prk, block + info + bytes([i]))
        okm += block
    return okm[0:32], okm[32:64], okm[64:96]


def config(raw):
    """net_config 를 읽기 쉬운 글로: "10.0.0.3/24 mtu 1400 routes 10.20.0.0/16,..." (proto.h).

    형식이 맞지 않으면 "malformed". 길이는 경로 개수와 정확히 맞아야 한다."""
    if raw is None or len(raw) < 8:
        return "malformed"
    tun_ip, prefix, count, mtu = struct.unpack("!4sBBH", raw[:8])
    if len(raw) != 8 + count * 5:
        return "malformed"
    routes = ["%s/%d" % (socket.inet_ntoa(raw[o:o + 4]), raw[o + 4]) for o in range(8, len(raw), 5)]
    return "%s/%d mtu %d routes %s" % (socket.inet_ntoa(tun_ip), prefix, mtu, ",".join(routes) or "-")


def nonce(counter):
    return bytes(4) + struct.pack("!Q", counter)


# 열린 세션: idx -> [C->S 키, S->C 키, 다음에 보낼 counter]. 서버는 한 세션의 데이터와
# keepalive 를 같은 counter 로 세므로 여기서도 세션마다 하나로 센다.
SESSIONS = {}


def seal(msg_type, idx, plain, counter=None, key=None, as_idx=None):
    """세션 패킷 한 개: 헤더(8) | counter(8) | 암호문 | tag(16).

    counter 를 주지 않으면 그 세션의 다음 값을 쓴다. key 는 다른 키로 감싼 패킷을,
    as_idx 는 헤더의 세션 번호만 다른 패킷을 만들 때 준다."""
    sess = SESSIONS.get(idx)
    if counter is None:
        counter = sess[2]
    if sess is not None:
        sess[2] = max(sess[2], counter + 1)
    head = header(msg_type, idx if as_idx is None else as_idx) + struct.pack("!Q", counter)
    return head + gcm_seal(key or sess[0], nonce(counter), head, plain)


def unseal(pkt):
    """서버가 보낸 세션 패킷의 평문. 모르는 세션이거나 tag 가 맞지 않으면 None."""
    idx = struct.unpack("!I", pkt[4:8])[0]
    sess = SESSIONS.get(idx)
    if sess is None or len(pkt) < 16 + TAG_LEN:
        return None
    counter = struct.unpack("!Q", pkt[8:16])[0]
    return gcm_open(sess[1], nonce(counter), pkt[:16], pkt[16:])


class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.addr = ("127.0.0.1", PORT)
        self.raw = b""          # 마지막으로 받은 패킷 그대로
        self.auth_tag = b""     # 마지막으로 보낸 AUTH 의 mac

    def send(self, pkt):
        self.sock.sendto(pkt, self.addr)

    def recv(self):
        """(type, session_idx, body) 또는 응답이 없으면 None.

        세션 패킷은 세션 키로 풀어 평문을 body 에 준다. 열리지 않으면 body 는 None 이다 —
        서버가 보낸 것이라고 볼 수 없는 패킷이다."""
        try:
            self.raw, _ = self.sock.recvfrom(2048)
        except socket.timeout:
            return None
        version, msg_type, _, idx = struct.unpack("!BBHI", self.raw[:HDR_LEN])
        if idx != 0 and msg_type in (DATA, KEEPALIVE, DENY, ENROLL, LOGIN, DISCONNECT):
            return msg_type, idx, unseal(self.raw)
        return msg_type, idx, self.raw[HDR_LEN:]

    def drain(self):
        self.sock.setblocking(False)
        try:
            while True:
                self.sock.recvfrom(2048)
        except BlockingIOError:
            pass
        self.sock.settimeout(1.0)

    def request(self, dev_id=DEV_ID):
        self.send(header(REQ_HANDSHAKE) + dev_id)
        return self.recv()

    def auth(self, challenge, key=DEV_KEY, dev_id=DEV_ID, post=None, tamper=None, pub=None):
        """AUTH 를 보내고 답을 받는다. 수락이면 세션 키를 뽑아 SESSIONS 에 넣는다.

        수락의 tag 가 맞지 않으면 body 를 None 으로 돌려준다. 진짜 클라이언트는 그런
        수락을 받지 않는다."""
        ecdh = Ecdh()
        signed = header(AUTH) + dev_id + challenge + (pub or ecdh.pub) + (post or posture())
        self.auth_tag = mac(key, signed)
        if tamper:
            signed = tamper(signed)
        pkt = signed + self.auth_tag
        self.send(pkt)

        r = self.recv()
        if r is None or r[0] != RES_HANDSHAKE:
            return r

        head, rest = self.raw[:HDR_LEN + PUB_LEN], self.raw[HDR_LEN + PUB_LEN:]
        try:
            c2s, s2c, res_key = session_keys(key, ecdh.secret(head[HDR_LEN:]), pkt, head)
        except RuntimeError:
            return r[0], r[1], None
        sealed = gcm_open(res_key, bytes(12), head, rest)
        if sealed is None:
            return r[0], r[1], None
        SESSIONS[r[1]] = [c2s, s2c, 0]
        self.config = config(sealed)    # 서버가 이 기기에 정해 준 터널 설정
        return r

    def handshake(self, **kw):
        r = self.request()
        assert r and r[0] == CHALLENGE, "no challenge: %r" % (r,)
        return self.auth(r[2], **kw)

    def deny_mac_ok(self, r, key=DEV_KEY):
        """핸드셰이크 중의 DENY 에 붙은 mac 이 이 기기의 키로 확인되는가."""
        want = mac(key, b"ztgate deny" + r[2][:1] + self.auth_tag)
        return hmac.compare_digest(r[2][1:1 + MAC_LEN], want)


def describe(r):
    if r is None:
        return "no response"
    msg_type, idx, body = r
    name = TYPE_NAME.get(msg_type, "type %d" % msg_type)
    if body is None:
        return name + "(bad tag)"
    if msg_type in (DENY, ENROLL, LOGIN):
        return "%s(%d)" % (name, body[0])
    if msg_type == DENY:
        return "DENY(%d)" % body[0]
    if msg_type == RES_HANDSHAKE:
        return "RES_HANDSHAKE" if idx else "RES_HANDSHAKE(idx=0)"
    return name


def check(name, got, want):
    global failed
    text = describe(got)
    ok = text == want
    print("%-4s %-52s %s%s" % ("ok" if ok else "FAIL", name, text, "" if ok else "   (want %s)" % want))
    failed += not ok


def expect(name, got, want):
    global failed
    ok = got == want
    print("%-4s %-52s %s%s" % ("ok" if ok else "FAIL", name, got, "" if ok else "   (want %s)" % (want,)))
    failed += not ok


def handshake_tests():
    c = Client()

    check("unknown device id", c.request(dev_id=bytes(16)), "DENY(1)")
    check("request too short", (c.send(header(REQ_HANDSHAKE) + DEV_ID[:8]), c.recv())[1], "no response")
    check("old client (tunnel ip only, no device id)", (c.send(header(REQ_HANDSHAKE) + TUN_IP), c.recv())[1], "no response")
    c.send(struct.pack("!BBHI", 3, REQ_HANDSHAKE, 0, 0) + TUN_IP + DEV_ID)
    check("previous protocol version", c.recv(), "no response")
    check("registered device gets a challenge", c.request(), "CHALLENGE")

    check("correct key (and the server's answer verifies)", c.handshake(), "RES_HANDSHAKE")
    check("wrong key", c.handshake(key=bytes(32)), "DENY(2)")

    r = c.request()
    challenge = r[2]
    check("first AUTH with this nonce", c.auth(challenge), "RES_HANDSHAKE")
    check("same nonce used again (replay)", c.auth(challenge), "DENY(2)")

    check("AUTH with a nonce the server never issued", (c.request(), c.auth(os.urandom(16)))[1], "DENY(2)")

    r = c.request()
    time.sleep(6.5)
    check("AUTH after the nonce expired (6.5s)", c.auth(r[2]), "DENY(2)")

    flip = lambda s: s[:-8] + posture(firewall=STATE_OFF)
    check("posture changed after signing", c.handshake(tamper=flip), "DENY(2)")

    # 사이에 낀 쪽이 일회용 공개키를 자기 것으로 바꿔 끼운 경우. mac 이 공개키까지 덮는다.
    swap = lambda s: s[:HDR_LEN + 32] + Ecdh().pub + s[HDR_LEN + 32 + PUB_LEN:]
    check("ephemeral key replaced after signing", c.handshake(tamper=swap), "DENY(2)")

    # 서명은 맞는데 공개키가 곡선 위의 점이 아니다. 계산해 주지 않는다.
    check("ephemeral key that is not on the curve", c.handshake(pub=bytes(PUB_LEN - 1) + b"\x01"), "no response")

    # 터널 주소는 클라이언트가 대지 않는다. 기기 목록에 적힌 것을 서버가 수락에 실어 준다.
    # 이 서버는 ACL 없이 떴으므로 터널 대역 밖으로 가는 경로는 없다.
    c.handshake()
    expect("the server assigns the tunnel configuration", c.config, "10.0.0.3/24 mtu 1400 routes -")
    strict(c)
    expect("each device gets its own address", c.config, "10.0.0.4/24 mtu 1400 routes -")

    r = c.handshake(key=bytes(32))
    expect("a denial before authentication carries no mac",
           "zeros" if r[2][1:1 + MAC_LEN] == bytes(MAC_LEN) else "present", "zeros")

    c.send(header(AUTH) + DEV_ID)
    check("AUTH too short", c.recv(), "no response")

    # 세션 키는 핸드셰이크마다 새로 뽑힌다.
    a = SESSIONS[c.handshake()[1]]
    b = SESSIONS[c.handshake()[1]]
    expect("two handshakes of one device, session keys", "differ" if a[0] != b[0] and a[1] != b[1] else "same", "differ")
    expect("the two directions of one session, keys", "differ" if a[0] != a[1] else "same", "differ")


def disruption_tests():
    """기기 ID 만 아는 제3자가 진짜 기기의 핸드셰이크를 깨뜨릴 수 없는지."""
    victim, attacker = Client(), Client()

    r = victim.request()
    again = attacker.request()
    expect("REQ from elsewhere does not replace a live nonce",
           "same nonce" if again[2] == r[2] else "nonce replaced", "same nonce")
    check("victim's AUTH after 20 foreign REQs",
          ([attacker.request() for _ in range(20)], victim.auth(r[2]))[1], "RES_HANDSHAKE")

    r = victim.request()
    check("garbage AUTH from elsewhere", attacker.auth(r[2], key=bytes(32)), "DENY(2)")
    check("victim's AUTH after the garbage AUTH", victim.auth(r[2]), "RES_HANDSHAKE")

    # 재사용은 서명이 맞는 AUTH 가 올 때까지만이다. 한 번 쓰인 nonce 는 다시 나오지 않는다.
    after = victim.request()
    expect("a used nonce is not handed out again",
           "new nonce" if after[2] != r[2] else "same nonce", "new nonce")

    # 서명은 맞지만 거절된 AUTH 도 nonce 를 쓴 것이다 (엿들은 AUTH 의 재전송 방지).
    # 포스처 조건이 걸린 두 번째 기기로 본다.
    strict_auth = lambda challenge, **post: victim.auth(challenge, key=DEV2_KEY, dev_id=DEV2_ID, post=posture(**post))
    r = victim.request(dev_id=DEV2_ID)
    check("properly signed AUTH that the policy rejects", strict_auth(r[2], firewall=STATE_OFF), "DENY(4)")
    check("the same nonce, now with a posture that would pass", strict_auth(r[2]), "DENY(2)")


def strict(c, **post):
    """포스처 조건이 걸린 두 번째 기기로 핸드셰이크한다."""
    r = c.request(dev_id=DEV2_ID)
    assert r and r[0] == CHALLENGE, "no challenge: %r" % (r,)
    return c.auth(r[2], key=DEV2_KEY, dev_id=DEV2_ID, post=posture(**post))


def posture_tests():
    c = Client()

    # 두 번째 기기: firewall=on antivirus=on min-build=22000
    check("strict device, everything on", strict(c), "RES_HANDSHAKE")
    r = strict(c, firewall=STATE_OFF)
    check("strict device, firewall off", r, "DENY(4)")
    expect("that denial is signed with the device key", c.deny_mac_ok(r, DEV2_KEY), True)
    check("strict device, firewall unknown", strict(c, firewall=STATE_UNKNOWN), "DENY(4)")
    check("strict device, antivirus off", strict(c, antivirus=STATE_OFF), "DENY(4)")
    check("strict device, build below minimum", strict(c, build=19045), "DENY(4)")
    check("strict device, build exactly minimum", strict(c, build=22000), "RES_HANDSHAKE")
    check("strict device, build unknown (0)", strict(c, build=0), "DENY(4)")

    # 첫 번째 기기에는 조건이 없다. 정책은 기기마다 따로다.
    check("device without requirements, firewall off",
          c.handshake(post=posture(firewall=STATE_OFF, antivirus=STATE_OFF, build=0)), "RES_HANDSHAKE")


def keepalive(idx, counter=None, key=None, post=None, tamper=None, as_idx=None):
    """KEEPALIVE: header | counter(8) | 세션 키로 감싼 posture(8) | tag(16)."""
    pkt = seal(KEEPALIVE, idx, post or posture(), counter, key, as_idx)
    return tamper(pkt) if tamper else pkt


def session(c, strict_dev=False):
    r = strict(c) if strict_dev else c.handshake()
    assert r and r[0] == RES_HANDSHAKE and r[2] is not None, "handshake failed: %s" % describe(r)
    return r[1]


def keepalive_tests():
    c = Client()
    ka = lambda pkt: (c.send(pkt), c.recv())[1]

    idx = session(c)
    check("keepalive, counter 0 (and the answer verifies)", ka(keepalive(idx, 0)), "KEEPALIVE")
    check("keepalive, counter 5", ka(keepalive(idx, 5)), "KEEPALIVE")
    good = keepalive(idx, 6)
    check("keepalive, counter 6", ka(good), "KEEPALIVE")
    check("the same packet again (replay)", ka(good), "no response")
    check("older counter (3), properly sealed", ka(keepalive(idx, 3)), "no response")
    check("header only, nothing sealed", ka(header(KEEPALIVE, idx)), "no response")
    check("sealed with a key the server never agreed to", ka(keepalive(idx, 7, key=bytes(32))), "no response")
    other = SESSIONS[session(Client(), strict_dev=True)]
    check("sealed with another session's key", ka(keepalive(idx, 7, key=other[0])), "no response")
    check("sealed with this session's other direction", ka(keepalive(idx, 7, key=SESSIONS[idx][1])), "no response")
    flip = lambda p: p[:16] + bytes([p[16] ^ 0x01]) + p[17:]
    check("one bit of the sealed posture changed", ka(keepalive(idx, 7, tamper=flip)), "no response")
    check("session survives the forged packets", ka(keepalive(idx, 7)), "KEEPALIVE")

    # 다른 세션 번호를 적어 끼워 넣기: tag 가 헤더까지 덮으므로 통하지 않는다.
    check("keepalive under another session idx", ka(keepalive(idx, 8, as_idx=idx ^ 0x100)), "no response")
    retype = lambda p: p[:1] + bytes([DATA]) + p[2:]
    check("keepalive relabelled as DATA", ka(keepalive(idx, 8, tamper=retype)), "no response")

    # 다시 인증하면 새 세션이다. idx 와 키가 바뀌고 counter 는 0 부터 다시 받는다.
    old = SESSIONS[idx]
    idx2 = session(c)
    expect("re-authentication opens a new session", "new idx" if idx2 != idx else "same idx", "new idx")
    check("new session accepts counter 0", ka(keepalive(idx2, 0)), "KEEPALIVE")
    check("old session idx no longer answers", ka(keepalive(idx, 9)), "no response")
    check("old session's key under the new idx", ka(keepalive(idx2, 1, key=old[0])), "no response")

    # 세션 중에 포스처가 나빠진 경우 (포스처 조건이 걸린 기기)
    sidx = session(c, strict_dev=True)
    sk = lambda **post: ka(keepalive(sidx, post=posture(**post)))
    check("strict device, keepalive with everything on", sk(), "KEEPALIVE")
    check("strict device, keepalive reports firewall off (sealed denial)", sk(firewall=STATE_OFF), "DENY(4)")
    check("that session is gone", sk(), "no response")
    sidx = session(c, strict_dev=True)
    check("strict device can come back once the posture is fine", sk(), "KEEPALIVE")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def echo_request(src, dst, seq):
    """IPv4 + ICMP echo request 한 개."""
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x4d56, seq) + b"ztgate auth_check"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


def data(idx, counter, inner, key=None, tamper=None):
    """DATA: header | counter(8) | 세션 키로 감싼 inner 패킷 | tag(16)."""
    pkt = seal(DATA, idx, inner, counter, key)
    return tamper(pkt) if tamper else pkt


def describe_data(r):
    """DATA 로 돌아온 inner 패킷이 ICMP echo reply 인지."""
    if r is None:
        return "no response"
    msg_type, idx, inner = r
    if msg_type != DATA or inner is None:
        return describe(r)
    if len(inner) >= 28 and inner[9] == 1 and inner[20] == 0:
        return "echo reply"
    return "DATA (not an echo reply)"


def check_data(name, got, want):
    global failed
    text = describe_data(got)
    ok = text == want
    print("%-4s %-52s %s%s" % ("ok" if ok else "FAIL", name, text, "" if ok else "   (want %s)" % want))
    failed += not ok


def data_tests():
    """인증된 세션으로만 데이터가 통하는지. 서버의 tun 에 10.0.0.1 을 붙여 커널이 ping 에 답하게 한다."""
    c = Client()
    send = lambda pkt: (c.send(pkt), c.recv())[1]
    server_ip = socket.inet_aton("10.0.0.1")
    ping = lambda seq, src=TUN_IP: echo_request(src, server_ip, seq)

    idx = session(c)
    check_data("ping through an authenticated session (reply verifies)",
               send(data(idx, 0, ping(1))), "echo reply")

    # 터널 안의 내용이 와이어에 그대로 보이지 않는지. 보낸 것도, 돌아온 것도.
    marker = b"ztgate auth_check"
    sent = data(idx, 1, ping(2))
    r = send(sent)
    expect("the payload is not readable on the wire",
           "hidden" if marker not in sent and marker not in c.raw and marker in (r[2] or b"") else "visible", "hidden")

    check_data("the same packet again (replay)", send(sent), "no response")
    flip = lambda p: p[:40] + bytes([p[40] ^ 0x01]) + p[41:]
    check_data("one bit of the sealed packet changed", send(data(idx, 2, ping(3), tamper=flip)), "no response")
    check_data("sealed with a key the server never agreed to",
               send(data(idx, 2, ping(3), key=bytes(32))), "no response")
    check_data("session survives those, same counter now valid", send(data(idx, 2, ping(3))), "echo reply")

    # UDP 는 순서를 바꿔 전달할 수 있다. 늦게 온 패킷도 처음 보는 counter 면 받는다.
    late = data(idx, 10, ping(4))
    check_data("counter 11 arrives first", send(data(idx, 11, ping(5))), "echo reply")
    check_data("counter 10 arrives late", send(late), "echo reply")
    check_data("counter 10 again", send(late), "no response")
    old = data(idx, 20, ping(6))
    check_data("counter 120 (the window moves on)", send(data(idx, 120, ping(7))), "echo reply")
    check_data("counter 20, now older than the window", send(old), "no response")

    check_data("same ping under a session idx nobody was given",
               send(seal(DATA, idx, ping(8), as_idx=idx ^ 0x100)), "no response")
    check_data("inner source is another device's tunnel ip",
               send(data(idx, None, ping(9, TUN2_IP))), "no response")

    # 세션 중에 포스처 때문에 거절되면 데이터 길도 같이 닫힌다.
    sidx = session(c, strict_dev=True)
    check_data("strict device, ping while the posture is fine",
               send(data(sidx, None, ping(10, TUN2_IP))), "echo reply")
    check("strict device, keepalive reports firewall off",
          send(keepalive(sidx, post=posture(firewall=STATE_OFF))), "DENY(4)")
    check_data("strict device, ping after being denied",
               send(data(sidx, None, ping(11, TUN2_IP))), "no response")


def setup_tun(log):
    """서버가 만든 tun 에 터널 주소를 붙인다. test/server.sh 의 setup_if 와 같은 일이다."""
    log.seek(0)
    for line in log.read().decode().splitlines():
        if line.startswith("tun device: "):
            dev = line.split()[2]
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", dev], check=True)
            subprocess.run(["ip", "link", "set", dev, "mtu", "1400", "up"], check=True)
            return dev
    sys.exit("tun device name not found in the server log")


LINE1 = "%s %s 10.0.0.3" % (DEV_ID.hex(), DEV_KEY.hex())
LINE2 = "%s %s 10.0.0.4 firewall=on antivirus=on min-build=22000  # strict" % (DEV2_ID.hex(), DEV2_KEY.hex())


def write_devices(path, *lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def tunnel_only_tests(srv):
    """규칙 파일 없이 뜬 서버는 터널 대역 안까지만 통과시킨다. 판정은 서버 로그에서 읽는다."""
    c = Client()
    idx = session(c)

    def verdict(dst):
        before = len(srv.text())
        c.send(data(idx, None, echo_request(TUN_IP, socket.inet_aton(dst), 700)))
        time.sleep(0.3)
        c.drain()
        new = srv.text()[before:]
        return "denied" if "[deny]" in new else "passed" if "[udp->tun]" in new else "no trace"

    expect("no acl file: the server's tunnel address", verdict("10.0.0.1"), "passed")
    expect("no acl file: another address in the tunnel subnet", verdict("10.0.0.200"), "passed")
    expect("no acl file: just outside the tunnel subnet", verdict("10.0.1.1"), "denied")
    expect("no acl file: the server's other networks", verdict("192.168.0.1"), "denied")
    expect("no acl file: the internet", verdict("8.8.8.8"), "denied")
    ok = "outside the tunnel subnet (no acl file)" in srv.text()
    expect("no acl file: the denial says why", "logged" if ok else "silent", "logged")


def reload_tests(srv, path):
    """서버를 끄지 않고 기기 목록을 바꾼다 (kill -HUP)."""
    c = Client()
    ka = lambda pkt: (c.send(pkt), c.recv())[1]

    def reload(*lines):
        write_devices(path, *lines)
        srv.send_signal(signal.SIGHUP)
        time.sleep(1.5)

    idx = session(c)
    check("before reload", ka(keepalive(idx)), "KEEPALIVE")
    reload(LINE1 + " min-build=99999", LINE2)
    check("policy tightened: next keepalive of the open session", ka(keepalive(idx)), "DENY(4)")
    check("policy tightened: new handshake", c.handshake(), "DENY(4)")

    reload(LINE1, LINE2)
    idx = session(c)
    check("policy relaxed: device is accepted again", ka(keepalive(idx)), "KEEPALIVE")

    # 기기가 목록에서 사라지면 서버에는 그 기기의 키가 없다. 그래도 세션 키는 남아 있어
    # 거절을 세션 키로 감싸 보낼 수 있다.
    reload(LINE2)
    check("device removed: next keepalive of the open session", ka(keepalive(idx)), "DENY(1)")
    check("device removed: new handshake", c.request(), "DENY(1)")

    reload(LINE1, LINE2)
    idx = session(c)
    reload(LINE1 + " firewal=on", LINE2)
    check("broken file: previous list stays in effect", ka(keepalive(idx)), "KEEPALIVE")


def loader_tests():
    """오타가 난 조건을 조용히 넘기지 않는지."""
    global failed
    fd, path = tempfile.mkstemp(prefix="devices.", suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("%s %s 10.0.0.3 firewal=on\n" % (DEV_ID.hex(), DEV_KEY.hex()))
    p = subprocess.run([SERVER, str(PORT), path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    os.unlink(path)
    ok = p.returncode != 0 and b"unknown requirement 'firewal=on'" in p.stdout
    print("%-4s %-52s %s" % ("ok" if ok else "FAIL", "misspelled requirement in the device file",
                             "refused to start" if ok else "exit=%d" % p.returncode))
    failed += not ok


class Server:
    """vpn_server 한 개. 로그는 임시 파일로 받아 두고, 테스트가 그 안에서 서버의 판정을 읽는다."""

    def __init__(self, *args, opts=()):
        self.log = tempfile.TemporaryFile()
        self.status_path = tempfile.mktemp(prefix="vpn_status.", suffix=".sock")
        self.audit_path = tempfile.mktemp(prefix="vpn_audit.", suffix=".log")
        self.enroll_path = tempfile.mktemp(prefix="vpn_enroll.", suffix=".conf")
        self.proc = subprocess.Popen(["stdbuf", "-oL", SERVER, "-s", self.status_path, "-a", self.audit_path,
                                      "-e", self.enroll_path] + list(opts) + [
                                      str(PORT)] + list(args),
                                     stdout=self.log, stderr=subprocess.STDOUT)
        time.sleep(0.7)
        if self.proc.poll() is not None:
            sys.exit("server failed to start:\n" + self.text())
        setup_tun(self.log)

    def text(self):
        self.log.seek(0)
        return self.log.read().decode()

    def reload(self):
        self.proc.send_signal(signal.SIGHUP)
        time.sleep(1.5)

    def status(self):
        """상태 소켓에 접속해 서버가 쓰는 JSON 을 끝까지 읽는다."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(self.status_path)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode())

    def events(self):
        """감사 로그의 사건들. 한 줄이 JSON 하나여야 한다 — 아니면 여기서 예외가 난다."""
        with open(self.audit_path) as f:
            return [json.loads(line) for line in f]

    def stop(self):
        self.proc.terminate()
        self.proc.wait()
        self.socket_left = os.path.exists(self.status_path)
        if os.path.exists(self.enroll_path):
            os.unlink(self.enroll_path)
        if os.path.exists(self.audit_path):
            os.unlink(self.audit_path)


def udp_packet(src, dst, dport, ident):
    """IPv4 + UDP 한 개. 서버의 ACL 판정만 볼 것이라 받는 쪽은 없어도 된다."""
    udp = struct.pack("!HHHH", 40000, dport, 8 + 4, 0) + b"acl?"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0, src, dst)
    return ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:] + udp


def acl_tests(srv, acl_path):
    """ACL 을 서버를 끄지 않고 바꾼다 (kill -HUP). 판정은 서버 로그에서 읽는다 —
    통과한 패킷은 [udp->tun], 막힌 패킷은 [deny] 로 찍힌다."""
    c = Client()
    server_ip = socket.inet_aton("10.0.0.1")
    seq = [100]

    def verdict(inner, idx):
        seq[0] += 1
        before = len(srv.text())
        c.send(data(idx, None, inner))
        time.sleep(0.3)
        c.drain()       # 통과한 패킷에는 서버의 커널이 답한다. 다음 검사가 그걸 읽지 않게 비운다.
        new = srv.text()[before:]
        return "denied" if "[deny]" in new else "passed" if "[udp->tun]" in new else "no trace"

    def expect(name, got, want):
        global failed
        ok = got == want
        print("%-4s %-52s %s%s" % ("ok" if ok else "FAIL", name, got, "" if ok else "   (want %s)" % want))
        failed += not ok

    def rules(*lines):
        with open(acl_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        srv.reload()

    ping = lambda: echo_request(TUN_IP, server_ip, seq[0])
    udp = lambda port: udp_packet(TUN_IP, server_ip, port, seq[0])

    idx = session(c)
    expect("acl: icmp allowed by the starting rules", verdict(ping(), idx), "passed")
    expect("acl: udp/53 not in the starting rules", verdict(udp(53), idx), "denied")

    rules("10.0.0.0/24 10.0.0.1 udp 53 allow")
    expect("acl reloaded: udp/53 now allowed", verdict(udp(53), idx), "passed")
    expect("acl reloaded: icmp no longer allowed", verdict(ping(), idx), "denied")
    check("acl reloaded: the session itself stays open",
          (c.send(keepalive(idx)), c.recv())[1], "KEEPALIVE")

    rules("10.0.0.0/24 10.0.0.1 udp 53 deny", "10.0.0.0/24 10.0.0.1 icmp any allow", "any any any any allwo")
    expect("broken acl file: previous rules stay (udp/53)", verdict(udp(53), idx), "passed")
    expect("broken acl file: previous rules stay (icmp)", verdict(ping(), idx), "denied")
    ok = "acl: reload failed, keeping the previous rules" in srv.text()
    expect("broken acl file: the server says so", "logged" if ok else "silent", "logged")

    # 리소스마다 요구하는 포스처를 다르게 건다. 첫 번째 기기에는 기기 조건이 없어 어떤
    # 포스처로도 터널에는 들어온다. 들어온 뒤 어디까지 가는지는 규칙이 정한다.
    rules("10.0.0.0/24 10.0.0.1 udp 53 allow firewall=on min-build=22000",
          "10.0.0.0/24 10.0.0.1 icmp any allow",
          "any any any any allow")
    ka = lambda n, **post: (c.send(keepalive(idx, post=posture(**post))), c.recv())[1]

    idx = session(c)
    expect("rule requires firewall: reported on", verdict(udp(53), idx), "passed")
    check("keepalive reports firewall off (no device policy)", ka(0, firewall=STATE_OFF), "KEEPALIVE")
    expect("rule requires firewall: now off", verdict(udp(53), idx), "denied")
    expect("a rule without requirements still passes (icmp)", verdict(ping(), idx), "passed")
    expect("the broad allow below does not rescue udp/53", verdict(udp(53), idx), "denied")
    expect("the broad allow still covers udp/54", verdict(udp(54), idx), "passed")
    ok = "posture below the rule (build=26200 firewall=1 antivirus=2)" in srv.text()
    expect("the denial names the posture", "logged" if ok else "silent", "logged")

    check("keepalive reports firewall on again", ka(1), "KEEPALIVE")
    expect("rule requires firewall: on again", verdict(udp(53), idx), "passed")
    check("keepalive reports firewall unknown", ka(2, firewall=STATE_UNKNOWN), "KEEPALIVE")
    expect("rule requires firewall: unknown", verdict(udp(53), idx), "denied")
    check("keepalive reports build 19045", ka(3, build=19045), "KEEPALIVE")
    expect("rule requires min-build=22000: 19045", verdict(udp(53), idx), "denied")

    # 핸드셰이크에서 보고한 값도 같은 자리에 쓰인다 (첫 keepalive 를 기다리지 않는다).
    r = c.handshake(post=posture(firewall=STATE_OFF))
    expect("posture from the handshake, firewall off", verdict(udp(53), r[1]), "denied")


def config_tests(srv, acl_path, dev_path):
    """서버가 터널 설정을 정책에서 뽑아 내려 주는지. ACL 을 켠 서버로 돌린다."""
    c = Client()

    def rules(*lines):
        with open(acl_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        srv.reload()

    def refreshed(idx):
        """keepalive 를 보내고 응답에 실려 온 설정을 읽는다."""
        c.send(keepalive(idx))
        r = c.recv()
        return config(r[2]) if r and r[0] == KEEPALIVE else describe(r)

    base = ("10.0.0.0/24 10.0.0.1 icmp any allow",      # 터널 대역 안: 주소를 받으면 이미 그리로 간다
            "10.0.0.3 10.20.0.0/16 tcp 443 allow",      # 첫 번째 기기만
            "10.0.0.3 10.20.0.0/16 tcp 22 allow",       # 같은 대역을 한 번 더: 경로는 하나다
            "10.0.0.4 10.30.0.0/16 any any allow",      # 두 번째 기기만
            "any 192.168.5.0/24 any any deny",          # 막는 곳을 터널로 끌어올 이유가 없다
            "any any udp 53 allow")                     # 목적지가 any: 전체를 터널로 돌리지 않는다
    rules(*base)

    idx = session(c)
    expect("routes are the allowed destinations of this device",
           c.config, "10.0.0.3/24 mtu 1400 routes 10.20.0.0/16")
    session(c, strict_dev=True)
    expect("another device, another set of routes",
           c.config, "10.0.0.4/24 mtu 1400 routes 10.30.0.0/16")

    # 열려 있는 세션은 keepalive 응답으로 지금의 설정을 계속 받는다. 다시 붙을 필요가 없다.
    expect("the keepalive answer repeats the configuration",
           refreshed(idx), "10.0.0.3/24 mtu 1400 routes 10.20.0.0/16")
    rules(*(base + ("10.0.0.0/24 10.40.0.0/16 any any allow",)))
    expect("acl changed: the open session learns the new route",
           refreshed(idx), "10.0.0.3/24 mtu 1400 routes 10.20.0.0/16,10.40.0.0/16")
    rules(base[0])
    expect("acl changed: the routes are withdrawn",
           refreshed(idx), "10.0.0.3/24 mtu 1400 routes -")

    # 관리자가 기기의 터널 주소를 바꿨다. 열린 세션은 새 주소를 통보받고, 다시
    # 핸드셰이크하면 새 주소로 세션이 열린다. 예전 주소의 세션은 남지 않는다.
    write_devices(dev_path, LINE1.replace("10.0.0.3", "10.0.0.7"), LINE2)
    srv.reload()
    expect("device readdressed: the open session is told",
           refreshed(idx), "10.0.0.7/24 mtu 1400 routes -")
    session(c)
    expect("device readdressed: a new handshake gets the new address",
           c.config, "10.0.0.7/24 mtu 1400 routes -")
    mine = sorted(s["tunnel_ip"] for s in srv.status()["sessions"] if s["device_id"] == DEV_ID.hex())
    expect("device readdressed: its old session is gone", mine, ["10.0.0.7"])

    write_devices(dev_path, LINE1, LINE2)
    srv.reload()


def status_tests(srv):
    """상태 소켓이 서버의 피어 테이블과 판정 횟수를 그대로 보여 주는지. ACL 을 켠 서버로 돌린다."""
    c = Client()
    server_ip = socket.inet_aton("10.0.0.1")

    def find(st, ip):
        return next((s for s in st["sessions"] if s["tunnel_ip"] == ip), None)

    def counted(st, before, *names):
        return tuple(st["counters"][n] - before["counters"][n] for n in names)

    mode = os.stat(srv.status_path).st_mode & 0o777
    expect("status: socket file mode", "%03o" % mode, "600")

    # 앞의 검사들이 남긴 세션을 지우고 시작한다 (규칙은 icmp 만 허용).
    with open(srv.acl_path, "w") as f:
        f.write("10.0.0.0/24 10.0.0.1 icmp any allow\n")
    srv.reload()
    before = srv.status()

    idx = session(c)
    st = srv.status()
    s = find(st, "10.0.0.3")
    expect("status: the new session is listed", s is not None and s["device_id"], DEV_ID.hex())
    expect("status: session idx", s and s["session_idx"], "%08x" % idx)
    expect("status: posture from the handshake", s and s["posture"],
           {"os_build": 26200, "firewall": "on", "antivirus": "on"})
    expect("status: handshake_ok counted", counted(st, before, "handshake_ok"), (1,))

    c.send(keepalive(idx, post=posture(firewall=STATE_OFF)))
    c.recv()
    s = find(srv.status(), "10.0.0.3")
    expect("status: posture follows the keepalive", s and s["posture"]["firewall"], "off")

    c.send(data(idx, None, echo_request(TUN_IP, server_ip, 900)))
    c.recv()
    c.send(data(idx, None, udp_packet(TUN_IP, server_ip, 53, 901)))
    time.sleep(0.3)
    st = srv.status()
    s = find(st, "10.0.0.3")
    expect("status: one packet in, one out, one denied",
           s and (s["rx_packets"], s["tx_packets"], s["acl_denied"]), (1, 1, 1))
    expect("status: acl_denied counted", counted(st, before, "acl_denied"), (1,))

    # 키가 틀린 핸드셰이크, 세션 키로 열리지 않는 패킷, 다시 보낸 패킷, 순서가 뒤바뀐 포스처 보고
    c.handshake(key=bytes(32))
    c.send(keepalive(idx, key=bytes(32)))
    c.recv()
    good = keepalive(idx)
    c.send(good)
    c.recv()
    c.send(good)
    c.recv()
    c.send(keepalive(idx, 3))       # 서버가 아직 받아들인 적 없는 counter 지만 마지막 보고보다 앞이다
    c.recv()
    st = srv.status()
    expect("status: bad auth / bad tag / replayed / out of order counted",
           counted(st, before, "deny_bad_auth", "bad_tag", "replayed", "keepalive_dropped"), (1, 1, 1, 1))
    expect("status: none of those touched the session",
           find(st, "10.0.0.3")["session_idx"], "%08x" % idx)

    sidx = session(c, strict_dev=True)
    expect("status: two sessions", len(srv.status()["sessions"]), 2)
    c.send(keepalive(sidx, post=posture(firewall=STATE_OFF)))
    c.recv()
    st = srv.status()
    expect("status: the dropped session is gone", find(st, "10.0.0.4"), None)
    expect("status: the other one stays", find(st, "10.0.0.3") is not None, True)

    # 읽지 않고 끊는 접속, 줄지어 오는 접속에도 서버는 터널을 계속 나른다.
    for _ in range(50):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(srv.status_path)
        s.close()
    check("status: server still answers after 50 abandoned connections",
          (c.send(keepalive(idx)), c.recv())[1], "KEEPALIVE")

    # 접속한 쪽이 보낸 것은 읽지 않는다.
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(srv.status_path)
    try:
        s.sendall(b"drop 10.0.0.3\n")
        while s.recv(65536):
            pass
    except (BrokenPipeError, ConnectionResetError):
        pass            # 서버는 쓰자마자 닫는다. 보내기도 전에 닫혀 있을 수 있다.
    s.close()
    expect("status: input on the socket is ignored", find(srv.status(), "10.0.0.3") is not None, True)


def audit_tests(srv):
    """감사 로그가 사건마다 한 줄을 남기는지. ACL 을 켠 서버로 돌린다 (규칙은 icmp 만 허용)."""
    c = Client()
    server_ip = socket.inet_aton("10.0.0.1")
    start = len(srv.events())

    def since(event, **want):
        """start 뒤에 적힌 사건 중 종류와 주어진 값이 맞는 것들."""
        return [e for e in srv.events()[start:]
                if e["event"] == event and all(e.get(k) == v for k, v in want.items())]

    expect("audit: log file mode", "%03o" % (os.stat(srv.audit_path).st_mode & 0o777), "600")

    idx = session(c)
    opened = since("session_open", session="%08x" % idx)
    expect("audit: session_open", len(opened), 1)
    expect("audit: session_open says who and from where",
           opened and (opened[0]["device"], opened[0]["tunnel_ip"], opened[0]["endpoint"].startswith("127.0.0.1:"),
                       opened[0]["posture"]["firewall"]),
           (DEV_ID.hex(), "10.0.0.3", True, "on"))

    c.handshake(key=bytes(32))
    c.request(dev_id=bytes(range(0xa0, 0xb0)))
    expect("audit: auth_denied for a wrong key", len(since("auth_denied", device=DEV_ID.hex(), reason="bad_auth")), 1)
    expect("audit: auth_denied for an unknown device, with the id it claimed",
           len(since("auth_denied", device=bytes(range(0xa0, 0xb0)).hex(), reason="unknown_device")), 1)

    # 패킷마다 적지 않는다. 같은 목적지와 같은 판정은 한 줄이다.
    for seq in range(3):
        c.send(data(idx, None, echo_request(TUN_IP, server_ip, 950 + seq)))
        c.recv()
    for seq in range(2):
        c.send(data(idx, None, udp_packet(TUN_IP, server_ip, 53, 960 + seq)))
    c.send(data(idx, None, udp_packet(TUN_IP, server_ip, 54, 970)))
    time.sleep(0.3)
    expect("audit: three pings to one destination, one line",
           len(since("access", session="%08x" % idx, dst="10.0.0.1", proto=1, verdict="allow")), 1)
    denied = since("access", session="%08x" % idx, verdict="deny")
    expect("audit: denied destinations, one line each, with the reason",
           sorted((e["dst"], e["proto"], e["dport"], e["why"]) for e in denied),
           [("10.0.0.1", 17, 53, "acl"), ("10.0.0.1", 17, 54, "acl")])

    sidx = session(c, strict_dev=True)
    c.send(data(sidx, None, echo_request(TUN2_IP, server_ip, 980)))
    c.recv()
    c.send(keepalive(sidx, post=posture(firewall=STATE_OFF)))
    c.recv()
    closed = since("session_close", session="%08x" % sidx)
    expect("audit: session_close says why and how much went through",
           closed and (closed[0]["reason"], closed[0]["device"], closed[0]["rx_packets"], closed[0]["tx_packets"]),
           ("posture", DEV2_ID.hex(), 1, 1))

    # 같은 기기가 다시 인증하면 앞의 세션은 "replaced" 로 닫힌다.
    session(c)
    expect("audit: re-authentication closes the previous session",
           len(since("session_close", session="%08x" % idx, reason="replaced")), 1)

    srv.reload()
    expect("audit: reload", [(e["what"], e["ok"]) for e in since("reload")], [("acl", True), ("devices", True)])
    with open(srv.acl_path, "a") as f:
        f.write("any any any any allwo\n")
    srv.reload()
    expect("audit: a reload that failed", len(since("reload", what="acl", ok=False)), 1)
    with open(srv.acl_path, "w") as f:
        f.write("10.0.0.0/24 10.0.0.1 icmp any allow\n")
    srv.reload()

    # 틀린 요청을 쏟아부어도 줄 수가 따라 늘지 않는다. 버린 만큼은 다음 줄에 적힌다.
    before = len(srv.events())
    for i in range(300):
        c.send(header(REQ_HANDSHAKE) + bytes([0xee] * 15 + [i & 0xff]))
    time.sleep(1.2)
    c.drain()
    c.request(dev_id=bytes([0xee] * 16))
    flood = srv.events()[before:]
    expect("audit: 300 bad requests in a burst are not 300 lines",
           "limited" if len(flood) < 80 else "%d lines" % len(flood), "limited")
    expect("audit: the suppressed count is written down",
           "counted" if any(e.get("suppressed", 0) > 0 for e in flood) else "lost", "counted")


def enroll_identity(code):
    """등록 코드에서 뽑는 임시 신원 (ID, 키). secure.h 의 secure_enroll_identity."""
    norm = code.upper().replace("-", "").replace(" ", "").replace("O", "0").replace("I", "1").replace("L", "1")
    return mac(b"ztgate enroll id", norm.encode())[:16], mac(b"ztgate enroll key", norm.encode())


def enroll_tests(srv, dev_path):
    """등록 코드로 기기를 올린다. 관리 도구가 하는 일(대기 목록에 줄을 쓰고 SIGHUP)을 여기서 흉내 낸다."""
    c = Client()
    new_id, new_key = bytes(range(0x70, 0x80)), bytes(range(0x80, 0xa0))

    def pending(*entries):
        """entries: (코드, 터널 주소, 지금부터 몇 초 뒤 만료, 포스처 조건, 이름)"""
        fd = os.open(srv.enroll_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            for code, ip, ttl, reqs, label in entries:
                eid, ekey = enroll_identity(code)
                f.write("%s %s %s %d %s  # %s\n" % (eid.hex(), ekey.hex(), ip, time.time() + ttl, reqs, label))
        srv.reload()

    def open_with(code, **post):
        """코드로 핸드셰이크한다. 열리면 세션 번호, 아니면 서버의 답을 글로."""
        eid, ekey = enroll_identity(code)
        r = c.request(dev_id=eid)
        if not r or r[0] != CHALLENGE:
            return describe(r)
        r = c.auth(r[2], key=ekey, dev_id=eid, post=posture(**post))
        return r[1] if r and r[0] == RES_HANDSHAKE and r[2] is not None else describe(r)

    def enroll(idx, dev_id, dev_key):
        c.send(seal(ENROLL, idx, dev_id + dev_key))
        return c.recv()

    code = "7K2QF-9XWM4-ABCDE-FGHJK-MNPQR"

    # 관리 도구(node)와 서버 / 클라이언트(C)와 이 스크립트가 같은 코드에서 같은 신원을 뽑아야 한다.
    expect("enroll: the identity derived from a code",
           enroll_identity("0123456789ABCDEFGHJKMNPQR")[0].hex(), "1fff58721da8863917ba05e6d47ce662")

    expect("enroll: a code nobody issued", open_with(code), "DENY(1)")

    pending((code, "10.0.0.9", 600, "firewall=on", "laptop-kim"))
    idx = open_with(code, firewall=STATE_OFF)
    expect("enroll: an issued code opens a session (posture is not judged yet)",
           "session" if isinstance(idx, int) else idx, "session")
    expect("enroll: the session shows the address the device will get",
           c.config, "10.0.0.9/24 mtu 1400 routes -")
    expect("enroll: that session is not listed as a device session",
           [s["tunnel_ip"] for s in srv.status()["sessions"] if s["tunnel_ip"] == "10.0.0.9"], [])

    # 등록용 세션으로는 등록 말고 아무것도 하지 못한다.
    check_data("enroll: the session cannot carry tunnel packets",
               (c.send(data(idx, None, echo_request(socket.inet_aton("10.0.0.9"), socket.inet_aton("10.0.0.1"), 990))),
                c.recv())[1], "no response")
    check("enroll: nor keepalives", (c.send(keepalive(idx)), c.recv())[1], "no response")

    other = Client()
    didx = session(other)
    check("enroll: a device session cannot enroll anything",
          (other.send(seal(ENROLL, didx, new_id + new_key)), other.recv())[1], "no response")

    check("enroll: request too short", (c.send(seal(ENROLL, idx, new_id)), c.recv())[1], "no response")
    check("enroll: an id that is already registered", enroll(idx, DEV_ID, new_key), "ENROLL(2)")

    check("enroll: the device hands in its id and key", enroll(idx, new_id, new_key), "ENROLL(0)")
    with open(dev_path) as f:
        added = [line.split("#") for line in f if line.startswith(new_id.hex())]
    expect("enroll: the device list has the new line, as the admin set it up",
           added and (added[0][0].split()[1:], added[0][1].strip()),
           ([new_key.hex(), "10.0.0.9", "firewall=on"], "laptop-kim"))
    expect("enroll: the device list keeps its mode", "%03o" % (os.stat(dev_path).st_mode & 0o777), "600")
    with open(dev_path) as f:
        expect("enroll: the devices that were there are still there",
               sum(line.startswith((DEV_ID.hex(), DEV2_ID.hex())) for line in f), 2)

    # 답이 사라져 같은 요청이 다시 가는 경우와, 같은 세션으로 다른 기기를 올리려는 경우
    check("enroll: the same request again gets the same answer", enroll(idx, new_id, new_key), "ENROLL(0)")
    check("enroll: a second device on the same code", enroll(idx, bytes(16), new_key), "ENROLL(1)")
    with open(dev_path) as f:
        expect("enroll: still one line for that device", sum(line.startswith(new_id.hex()) for line in f), 1)

    expect("enroll: the code cannot be used again", open_with(code), "DENY(1)")
    with open(srv.enroll_path) as f:
        expect("enroll: the used code is gone from the pending list",
               enroll_identity(code)[0].hex() in f.read(), False)

    # 등록된 기기는 자기 키로 붙는다. 주소와 포스처 조건은 코드를 만들 때 정한 것이다.
    r = c.request(dev_id=new_id)
    check("enroll: the new device connects with its own key",
          c.auth(r[2], key=new_key, dev_id=new_id), "RES_HANDSHAKE")
    expect("enroll: and gets the address tied to the code", c.config, "10.0.0.9/24 mtu 1400 routes -")
    r = c.request(dev_id=new_id)
    check("enroll: the posture requirement came along",
          c.auth(r[2], key=new_key, dev_id=new_id, post=posture(firewall=STATE_OFF)), "DENY(4)")

    events = [e for e in srv.events() if e["event"] == "enrolled"]
    expect("enroll: audit says which device, where, under what name",
           events and (events[-1]["device"], events[-1]["tunnel_ip"], events[-1]["label"]),
           (new_id.hex(), "10.0.0.9", "laptop-kim"))

    # 만료된 코드, 그리고 그 사이에 다른 기기가 쓰게 된 주소에 묶인 코드
    pending(("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "10.0.0.10", -5, "", "late"),
            ("FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK", "10.0.0.3", 600, "", "clash"))
    expect("enroll: an expired code", open_with("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"), "DENY(1)")
    didx = session(other)
    expect("enroll: a code whose address now belongs to a device",
           open_with("FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK"), "DENY(1)")
    check("enroll: that device's session is untouched",
          (other.send(keepalive(didx)), other.recv())[1], "KEEPALIVE")

    # 대기 목록의 권한이 열려 있으면 읽지 않는다 (등록용 세션을 열 수 있는 키가 들어 있다).
    pending(("MMMMM-NNNNN-PPPPP-QQQQQ-RRRRR", "10.0.0.11", 600, "", "open-file"))
    os.chmod(srv.enroll_path, 0o644)
    srv.reload()
    expect("enroll: a pending list readable by others is refused, the previous one stays",
           ("enroll: reload failed" in srv.text(), isinstance(open_with("MMMMM-NNNNN-PPPPP-QQQQQ-RRRRR"), int)),
           (True, True))

    os.unlink(srv.enroll_path)
    write_devices(dev_path, LINE1, LINE2)
    srv.reload()


def acl_loader_tests(dev_path):
    """ACL 파일의 실수를 조용히 넘기지 않는지. 서버는 tun 을 만들기 전에 끝난다."""
    global failed
    cases = [
        ("acl: requirement on a deny rule", "any any any any deny firewall=on", "only for allow rules"),
        ("acl: misspelled requirement", "any any any any allow firewal=on", "unknown requirement 'firewal=on'"),
        ("acl: line with a missing field", "10.0.0.0/24 10.0.0.1 tcp deny\nany any any any allow", "expected <src>"),
    ]
    for name, text, want in cases:
        fd, path = tempfile.mkstemp(prefix="acl.", suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write(text + "\n")
        p = subprocess.run([SERVER, str(PORT), dev_path, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        os.unlink(path)
        ok = p.returncode != 0 and want.encode() in p.stdout
        print("%-4s %-52s %s" % ("ok" if ok else "FAIL", name, "refused to start" if ok else "exit=%d" % p.returncode))
        failed += not ok


# ---- 커넥터 ----------------------------------------------------------------------

CON_ID = bytes(range(0x90, 0xa0))
CON_KEY = bytes(range(0xa0, 0xc0))
CON_LINE = "%s %s 10.0.0.9 connector=198.51.100.0/24  # connector" % (CON_ID.hex(), CON_KEY.hex())
RESOURCE = socket.inet_aton("198.51.100.10")


def disconnect_tests(srv):
    """DISCONNECT 로 세션이 바로 닫히는가. 세션 키로 열리지 않는 것으로는 닫히지 않는가."""
    c = Client()
    start = len(srv.events())
    idx = session(c)

    c.send(seal(DISCONNECT, idx, bytes([DISCONNECT_CLIENT_EXIT]), key=bytes(32)))
    time.sleep(0.2)
    c.drain()
    c.send(keepalive(idx))
    r = c.recv()
    expect("disconnect: a forged one does not close the session", r and r[0], KEEPALIVE)

    c.send(seal(DISCONNECT, idx, bytes([DISCONNECT_CLIENT_EXIT])))
    time.sleep(0.2)
    c.drain()
    c.send(keepalive(idx))
    expect("disconnect: the session is gone right away", describe(c.recv()), "no response")
    closed = [e["reason"] for e in srv.events()[start:]
              if e["event"] == "session_close" and e.get("session") == "%08x" % idx]
    expect("disconnect: audited as closed", closed, ["closed"])


def shutdown_tests(path):
    """서버가 끝날 때 열린 세션에 DISCONNECT 를 보내는가. 클라이언트는 그것을 보고 30초를
    기다리지 않고 바로 다시 붙는다."""
    srv = Server(path)
    c = Client()
    idx = session(c)
    c.drain()
    srv.stop()
    r = c.recv()
    expect("shutdown: the server tells the session it is leaving",
           r and (r[0], r[1] == idx, r[2]), (DISCONNECT, True, bytes([DISCONNECT_SERVER_SHUTDOWN])))
    return srv


def rekey_tests(path):
    """세션 키의 수명(-L)이 다하면 서버가 DISCONNECT(REKEY) 로 세션을 끝내고, 다시 핸드셰이크한
    세션은 새 번호와 새 키로 열리는가. 이전 세션의 키로 감싼 패킷은 더 이상 받지 않는가."""
    DISCONNECT_REKEY = 3
    srv = Server(path, opts=["-L", "2"])
    c = Client()
    idx = session(c)
    old = SESSIONS[idx][:]

    r = None
    for _ in range(5):
        r = c.recv()
        if r is not None and r[0] == DISCONNECT:
            break
    expect("rekey: the server ends the session when its key is old",
           r and (r[0], r[1] == idx, r[2]), (DISCONNECT, True, bytes([DISCONNECT_REKEY])))

    new = session(c)
    expect("rekey: the next handshake opens a new session", new != idx, True)
    expect("rekey: ...with new keys", SESSIONS[new][0] != old[0] and SESSIONS[new][1] != old[1], True)

    c.drain()
    c.send(keepalive(idx))
    expect("rekey: the old session no longer answers", describe(c.recv()), "no response")
    c.send(keepalive(new))
    r = c.recv()
    expect("rekey: the new session answers", r and r[0], KEEPALIVE)

    reasons = [e["reason"] for e in srv.events() if e["event"] == "session_close" and e.get("session") == "%08x" % idx]
    expect("rekey: audited as rekey", reasons, ["rekey"])
    srv.stop()
    return srv


SCALE_DEVICES = 1000


def scale_device(i):
    """규모 시험의 i 번째 기기: (id, key, 터널 주소). 10.0.1.1 부터 250개씩 /16 안에 놓는다."""
    dev_id = b"scale" + struct.pack("!I", i) + bytes(7)
    dev_key = hashlib.sha256(b"scale key %d" % i).digest()
    return dev_id, dev_key, "10.0.%d.%d" % (1 + i // 250, 1 + i % 250)


def scale_tests(srv):
    """기기 SCALE_DEVICES 대가 한꺼번에 붙어도 밀려나는 세션 없이 모두 남는가.

    세션 표, 기기 색인, 상태 소켓이 처음 정한 상한(세션 8, 기기 16, 상태 32KB)보다 훨씬
    큰 수에서 맞게 도는지 본다. 상태 JSON 은 받는 쪽 소켓 버퍼보다 커서 서버가 여러 번에
    나눠 써야 한다."""
    c = Client()
    idxs = []
    for i in range(SCALE_DEVICES):
        dev_id, dev_key, _ = scale_device(i)
        r = c.request(dev_id)
        if r is None or r[0] != CHALLENGE:
            break
        r = c.auth(r[2], key=dev_key, dev_id=dev_id)
        if r is None or r[0] != RES_HANDSHAKE or r[2] is None:
            break
        idxs.append(r[1])

    expect("scale: every device gets a session", len(idxs), SCALE_DEVICES)
    expect("scale: session numbers are all different", len(set(idxs)), len(idxs))
    expect("scale: slots beyond the old 8-bit limit are used", max(i & 0xFFFF for i in idxs) >= 256, True)
    expect("scale: no session was evicted", "evicting" in srv.text(), False)

    # 가장 먼저 연 세션과 가장 나중에 연 세션이 모두 살아 있다.
    for name, idx in (("first", idxs[0]), ("last", idxs[-1])):
        c.drain()
        c.send(keepalive(idx))
        r = c.recv()
        expect("scale: the %s session still answers" % name, r and r[0], KEEPALIVE)

    st = srv.status()
    expect("scale: the status lists every session", len(st["sessions"]), SCALE_DEVICES)
    expect("scale: the status counts every device", st["devices"], SCALE_DEVICES)
    last_ip = scale_device(SCALE_DEVICES - 1)[2]
    found = [s for s in st["sessions"] if s["tunnel_ip"] == last_ip]
    expect("scale: the last device is found by its tunnel ip", len(found), 1)

    # 다시 읽어도 색인이 같은 기기를 찾는다. 다음 keepalive 가 목록에 대 본다.
    srv.reload()
    c.drain()
    c.send(keepalive(idxs[SCALE_DEVICES // 2]))
    r = c.recv()
    expect("scale: after reload a session in the middle still answers", r and r[0], KEEPALIVE)


def connector_tests(srv, acl_path, dev_path):
    """서버가 커넥터의 대역으로 가는 패킷을 그 커넥터의 세션으로 보내고, 커넥터가 보낸 답을
    클라이언트에게 돌려주는지. 커넥터가 맡은 대역 밖을 출발지로 대거나 클라이언트가 아닌
    곳으로 보내는 패킷은 버려야 한다."""
    write_devices(dev_path, LINE1, LINE2, CON_LINE)
    with open(acl_path, "w") as f:
        f.write("10.0.0.0/24 198.51.100.0/24 icmp any allow\nany any any any deny\n")
    srv.reload()

    cl, con = Client(), Client()
    idx = session(cl)
    expect("connector: clients get the connector's network as a route", cl.config,
           "10.0.0.3/24 mtu 1400 routes 198.51.100.0/24")
    r = con.request(dev_id=CON_ID)
    r = con.auth(r[2], key=CON_KEY, dev_id=CON_ID)
    expect("connector: handshake", describe(r), "RES_HANDSHAKE")
    cidx = r[1]
    expect("connector: the connector itself gets no routes", con.config, "10.0.0.9/24 mtu 1400 routes -")

    ping = echo_request(TUN_IP, RESOURCE, 900)
    cl.send(data(idx, None, ping))
    r = con.recv()
    expect("connector: client -> its network arrives in the connector's session",
           r and (r[0], r[1], r[2] == ping), (DATA, cidx, True))

    reply = echo_request(RESOURCE, TUN_IP, 901)
    con.send(data(cidx, None, reply))
    r = cl.recv()
    expect("connector: the network's reply reaches the client", r and (r[0], r[2] == reply), (DATA, True))

    before = len(srv.text())
    con.send(data(cidx, None, echo_request(socket.inet_aton("10.101.0.5"), TUN_IP, 902)))
    expect("connector: a source outside its network is dropped", describe(cl.recv()), "no response")
    expect("connector: ...and the server says why",
           "source outside its networks" in srv.text()[before:], True)

    before = len(srv.text())
    con.send(data(cidx, None, echo_request(RESOURCE, socket.inet_aton("10.0.0.1"), 903)))
    time.sleep(0.3)
    expect("connector: it cannot send to the server's own address",
           "no client session there" in srv.text()[before:], True)

    write_devices(dev_path, LINE1, LINE2)
    srv.reload()


# ---- 사용자 로그인 ----------------------------------------------------------------

sys.path.insert(0, os.path.join(ROOT, "tools", "idp"))
import mint     # noqa: E402  시험용 IdP: 서명 키, JWKS, 토큰

LOGIN_OK, LOGIN_NO_IDP, LOGIN_MALFORMED, LOGIN_UNTRUSTED, LOGIN_WRONG_TOKEN, LOGIN_EXPIRED, \
    LOGIN_BAD_USER = range(7)


def login(c, idx, token):
    """LOGIN 을 보내고 (status, expires, 이름) 을 돌려준다. 답이 없으면 None."""
    c.send(seal(LOGIN, idx, token.encode() if isinstance(token, str) else token))
    r = c.recv()
    if r is None or r[0] != LOGIN or r[2] is None or len(r[2]) < 9:
        return None
    return r[2][0], struct.unpack("!Q", r[2][1:9])[0], r[2][9:].decode()


def login_no_idp_tests():
    """-u 없이 뜬 서버는 로그인을 받지 않는다고 답한다."""
    c = Client()
    idx = session(c)
    r = login(c, idx, "a.b.c")
    expect("login: server without -u says so", r and r[0], LOGIN_NO_IDP)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def login_tests(srv, acl_path, idp_dir):
    """사용자 토큰으로 로그인하고, user= / group= 규칙이 그 사용자에게만 열리는지."""
    c = Client()
    server_ip = socket.inet_aton("10.0.0.1")
    seq = [500]

    def verdict(dport, idx):
        seq[0] += 1
        before = len(srv.text())
        c.send(data(idx, None, udp_packet(TUN_IP, server_ip, dport, seq[0])))
        time.sleep(0.3)
        c.drain()
        new = srv.text()[before:]
        return "denied" if "[deny]" in new else "passed" if "[udp->tun]" in new else "no trace"

    with open(acl_path, "w") as f:
        f.write("10.0.0.0/24 10.0.0.1 udp 53 allow user=alice\n"
                "10.0.0.0/24 10.0.0.1 udp 54 allow group=ops group=sre\n"
                "10.0.0.0/24 10.0.0.1 udp 55 allow\n"
                "any any any any deny\n")
    srv.reload()

    tok = lambda user, **kw: mint.token(idp_dir, user, **kw)
    status = lambda r: r[0] if r else "no response"

    idx = session(c)
    expect("login: user rule, nobody logged in", verdict(53, idx), "denied")
    ok = "rule is for other users (logged in: nobody)" in srv.text()
    expect("login: the denial says nobody is logged in", "logged" if ok else "silent", "logged")
    expect("login: rule without users still passes", verdict(55, idx), "passed")

    t = tok("alice", groups=["dev"], ttl=600)
    want_exp = int(time.time()) + 600
    r = login(c, idx, t)
    expect("login: alice (RS256)", status(r), LOGIN_OK)
    expect("login: the answer names the user", r and r[2], "alice")
    expect("login: the answer carries the token's exp", r and abs(r[1] - want_exp) <= 2, True)
    expect("login: alice reaches the user=alice rule", verdict(53, idx), "passed")
    expect("login: alice is not in group ops", verdict(54, idx), "denied")
    expect("login: same token again (lost answer)", status(login(c, idx, t)), LOGIN_OK)
    logins = [e for e in srv.events() if e["event"] == "login" and e.get("result") == "ok"]
    expect("login: a resent token is audited once", len(logins), 1)

    sess = [s for s in srv.status()["sessions"] if s["session_idx"] == "%08x" % idx]
    expect("login: status socket shows the user",
           sess and sess[0]["user"] and (sess[0]["user"]["name"], sess[0]["user"]["groups"]), ("alice", ["dev"]))

    r = login(c, idx, tok("bob", groups=["ops"], alg="ES256"))
    expect("login: another user on the same device (ES256)", status(r), LOGIN_OK)
    expect("login: bob does not get alice's rule", verdict(53, idx), "denied")
    expect("login: bob reaches group=ops", verdict(54, idx), "passed")

    # 받지 않는 토큰들. 실패해도 이미 로그인한 bob 은 그대로여야 한다.
    now = int(time.time())
    good = tok("mallory", groups=["ops"])
    head, body, sig = good.split(".")
    jwks = json.load(open(os.path.join(idp_dir, "jwks.json")))
    rsa_n = base64.urlsafe_b64decode(jwks["keys"][0]["n"] + "==")
    hs_head = b64(json.dumps({"alg": "HS256", "kid": "rs-1"}).encode())
    hs_sig = b64(hmac.new(rsa_n, (hs_head + "." + body).encode(), hashlib.sha256).digest())
    payload = json.loads(base64.urlsafe_b64decode(body + "=="))
    payload["preferred_username"] = "admin"
    evil_body = b64(json.dumps(payload, separators=(",", ":")).encode())
    cases = [
        ("alg none, empty signature", b64(b'{"alg":"none","kid":"rs-1"}') + "." + body + ".", LOGIN_MALFORMED),
        ("alg none, with a signature", b64(b'{"alg":"none","kid":"rs-1"}') + "." + body + "." + sig, LOGIN_UNTRUSTED),
        ("HS256 keyed with the RSA public key", hs_head + "." + body + "." + hs_sig, LOGIN_UNTRUSTED),
        ("unknown kid", tok("mallory", kid="nope"), LOGIN_UNTRUSTED),
        ("ES256 claimed for the RSA key's kid", tok("mallory", alg="ES256", kid="rs-1"), LOGIN_UNTRUSTED),
        ("kid of a key that is not for signing", tok("mallory", kid="enc-1"), LOGIN_UNTRUSTED),
        ("payload changed after signing", head + "." + evil_body + "." + sig, LOGIN_UNTRUSTED),
        ("signature from another key", head + "." + body + "." + tok("x", alg="RS256").split(".")[2],
         LOGIN_UNTRUSTED),
        ("crit header", b64(b'{"alg":"RS256","kid":"rs-1","crit":["x"]}') + "." + body + "." + sig, LOGIN_UNTRUSTED),
        ("issued by another issuer", tok("mallory", iss="https://evil.test"), LOGIN_WRONG_TOKEN),
        ("issued for another service", tok("mallory", aud="mail"), LOGIN_WRONG_TOKEN),
        ("expired", tok("mallory", exp=now - 120), LOGIN_EXPIRED),
        ("not valid yet (nbf)", tok("mallory", nbf=now + 600), LOGIN_EXPIRED),
        ("no exp", tok("mallory", claims={"exp": None}), LOGIN_MALFORMED),
        ("user name with a quote", tok('mal"lory'), LOGIN_BAD_USER),
        ("no user claim", tok("mallory", claims={"preferred_username": None}), LOGIN_BAD_USER),
        ("not a JWT", "hello", LOGIN_MALFORMED),
        ("four parts", good + ".x", LOGIN_MALFORMED),
        ("base64 with padding", good + "=", LOGIN_MALFORMED),
        # 서명은 맞는데 같은 키가 두 번 나온다. 구현마다 앞 / 뒤 중 다른 것을 쓰므로 받지 않는다.
        ("duplicate claim (signed)", mint.raw_token(idp_dir, json.dumps(payload)[:-1] +
                                                     ',"preferred_username":"admin"}'), LOGIN_MALFORMED),
    ]
    for name, token, want in cases:
        expect("login rejects: " + name, status(login(c, idx, token)), want)
    expect("login: bob is still logged in after the rejects", verdict(54, idx), "passed")

    # 토큰은 UDP 한 통에 들어가야 하고 서버는 LOGIN_TOKEN_MAX 를 넘는 것을 읽지 않는다.
    expect("login rejects: longer than LOGIN_TOKEN_MAX", status(login(c, idx, "a" * 1960)), LOGIN_MALFORMED)

    # aud 는 배열일 수 있다. 그룹 이름에 쓸 수 없는 글자가 있으면 그 그룹만 빠진다.
    r = login(c, idx, tok("carol", aud=["account", "ztgate"], groups=["ops", 'bad"group']))
    expect("login: aud as a list containing ztgate", status(r), LOGIN_OK)
    sess = [s for s in srv.status()["sessions"] if s["session_idx"] == "%08x" % idx]
    expect("login: an unusable group name is dropped", sess and sess[0]["user"]["groups"], ["ops"])

    # 세션 중에 토큰이 끝난다. 그 순간부터 사용자 규칙은 맞지 않고, 세션은 그대로다.
    r = login(c, idx, tok("dave", groups=["sre"], ttl=3))
    expect("login: dave with a 3-second token", status(r), LOGIN_OK)
    expect("login: dave reaches group=sre", verdict(54, idx), "passed")
    time.sleep(3.5)
    expect("login: after exp the user rule is closed", verdict(54, idx), "denied")
    expect("login: ...but the rest of the session works", verdict(55, idx), "passed")
    check("login: keepalive after exp", (c.send(keepalive(idx)), c.recv())[1], "KEEPALIVE")
    ev = srv.events()
    out = [e for e in ev if e["event"] == "logout"]
    expect("login: the expiry is audited as logout", out and (out[-1]["user"], out[-1]["reason"]), ("dave", "expired"))
    deny = [e for e in ev if e["event"] == "access" and e.get("why") == "user"]
    expect("login: a user-rule denial is audited with why=user", len(deny) > 0, True)
    named = [e for e in ev if e["event"] == "access" and e.get("user") == "bob"]
    expect("login: access events name the user", len(named) > 0, True)
    bad = [e for e in ev if e["event"] == "login" and e["result"] == "untrusted"]
    expect("login: rejected tokens are audited", len(bad) > 0, True)

    # 키를 바꿔 끼우다 깨진 JWKS 를 읽으면 이전 키로 계속 받는다.
    jwks_path = os.path.join(idp_dir, "jwks.json")
    saved = open(jwks_path).read()
    with open(jwks_path, "w") as f:
        f.write('{"keys": [')
    srv.reload()
    expect("login: broken jwks on reload is reported", "idp: reload failed" in srv.text(), True)
    expect("login: ...and the previous keys still work", status(login(c, idx, tok("erin"))), LOGIN_OK)
    with open(jwks_path, "w") as f:
        f.write(saved)

    # ACL 파일의 사용자 조건도 틀리면 받지 않는다.
    for name, text, want in [
        ("acl: user condition on a deny rule", "any any any any deny user=alice", "only for allow rules"),
        ("acl: user name with a quote", 'any any any any allow user=al"ice', "bad user condition"),
        ("acl: five users on one rule", "any any any any allow " + " ".join("user=u%d" % i for i in range(5)),
         "bad user condition"),
    ]:
        with open(acl_path, "w") as f:
            f.write(text + "\n")
        before = len(srv.text())
        srv.reload()
        new = srv.text()[before:]
        expect(name, "refused" if want in new and "acl: reload failed" in new else "accepted", "refused")


def main():
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 test/auth_check.py")

    fd, path = tempfile.mkstemp(prefix="devices.", suffix=".conf")
    with os.fdopen(fd, "w") as f:      # mkstemp 는 0600 으로 만든다
        f.write(LINE1 + "\n" + LINE2 + "\n")
    fd, acl_path = tempfile.mkstemp(prefix="acl.", suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("10.0.0.0/24 10.0.0.1 icmp any allow\n")

    loader_tests()
    acl_loader_tests(path)

    logs = []
    try:
        # ACL 없이: 인증된 세션의 패킷은 모두 통과한다.
        srv = Server(path)
        try:
            handshake_tests()
            disruption_tests()
            posture_tests()
            keepalive_tests()
            data_tests()
            tunnel_only_tests(srv)
            login_no_idp_tests()
            reload_tests(srv.proc, path)
        finally:
            srv.stop()
            logs.append(srv.text())

        # ACL 을 켜고 다시 띄운다.
        write_devices(path, LINE1, LINE2)
        srv = Server(path, acl_path)
        srv.acl_path = acl_path
        try:
            acl_tests(srv, acl_path)
            config_tests(srv, acl_path, path)
            status_tests(srv)
            audit_tests(srv)
            disconnect_tests(srv)
            enroll_tests(srv, path)
            connector_tests(srv, acl_path, path)
        finally:
            srv.stop()
            logs.append(srv.text())
        # 사용자 로그인을 받는 서버 (-u). 시험용 IdP 의 키로 토큰을 만든다.
        idp_dir = tempfile.mkdtemp(prefix="idp.")
        mint.make_keys(idp_dir)
        write_devices(path, LINE1, LINE2)
        srv_idp = Server(path, acl_path, opts=["-u", os.path.join(idp_dir, "idp.conf")])
        try:
            login_tests(srv_idp, acl_path, idp_dir)
        finally:
            srv_idp.stop()
            logs.append(srv_idp.text())
            subprocess.run(["rm", "-rf", idp_dir])

        write_devices(path, LINE1, LINE2)
        logs.append(shutdown_tests(path).text())
        logs.append(rekey_tests(path).text())

        # 기기 여러 대. 터널 대역을 /16 으로 넓혀 1000 대의 주소가 들어가게 한다.
        write_devices(path, *("%s %s %s" % (d.hex(), k.hex(), ip)
                              for d, k, ip in map(scale_device, range(SCALE_DEVICES))))
        srv_scale = Server(path, opts=["-n", "16"])
        try:
            scale_tests(srv_scale)
        finally:
            srv_scale.stop()
            logs.append(srv_scale.text())

        global failed
        print("%-4s %-52s %s" % ("FAIL" if srv.socket_left else "ok", "status: socket file removed on exit",
                                 "left behind" if srv.socket_left else "removed"))
        failed += srv.socket_left
    finally:
        os.unlink(path)
        os.unlink(acl_path)

    if "-v" in sys.argv:
        print("\n--- server log\n" + "\n--- server log (acl)\n".join(logs))
    print("\n%s" % ("all passed" if not failed else "%d FAILED" % failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
