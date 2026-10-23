#!/usr/bin/env bash
# 실제 IdP(Keycloak)가 발급한 토큰을 서버가 받는지 확인한다.
#
#   KC=http://localhost:8080 test/keycloak_check.sh
#
# Keycloak 이 떠 있어야 한다 (관리자 admin / admin). CI 의 idp 잡이 컨테이너로 띄운다:
#
#   docker run -d -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#       -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.0.7 start-dev
#
# 다른 시험(auth_check.py, linux_e2e.sh)의 토큰은 tools/idp/mint.py 가 만든다. 서명과 검증의
# 논리는 그것으로 확인되지만, "실제 IdP 의 토큰이 이 모양인가"는 확인되지 않는다 — aud 가
# 배열로 오는지, JWKS 에 서명용이 아닌 키가 섞여 있는지, 그룹 클레임이 어떤 이름으로 오는지.
# 여기서는 README 의 "사용자 로그인"에 적은 Keycloak 설정을 관리 API 로 그대로 만들고, 그
# 설정이 발급한 토큰을 vpn_server verify-token 에 넣어 본다.
#
#   1. 렐름, 공개 클라이언트(ztgate, 기기 인가 켬, audience / 그룹 매퍼), 그룹 ops, 사용자 alice
#   2. 디스커버리에서 issuer 와 jwks_uri 를 읽어 idp.conf 와 jwks.json 을 만든다
#   3. alice 의 토큰 -> ok user=alice groups=ops
#   4. 같은 IdP 가 다른 클라이언트(other)에 준 토큰 -> wrong_token (aud)
#   5. 서명 뒤에 바꾼 토큰 -> untrusted
#   6. 기기 인가 엔드포인트가 기기 코드를 준다 (client/ztgate_login 이 쓰는 첫 단계)
#   7. Windows GUI 의 흐름: 인가 코드 + PKCE, 루프백 redirect. 브라우저가 하는 일(로그인 화면에
#      입력하고 앱의 127.0.0.1:<포트> 로 돌아가기)을 스크립트가 대신한다. 포트 두 개로 해서
#      IdP 가 루프백의 포트를 가리지 않는지 본다.
#   8. 받은 refresh token 으로 갱신되고, 폐기(RFC 7009)한 뒤에는 갱신되지 않는다.
#
# 3~5 의 토큰은 비밀번호 방식(direct access grant)으로 받는다. 기기 인가는 사람이 브라우저에서
# 승인해야 끝나므로 자동 시험에서는 첫 단계까지만 본다. 나머지 흐름은 linux_e2e.sh 가
# 시험용 OIDC 서버로 확인한다.

set -u

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$ROOT_DIR/server/bin/vpn_server"
KC=${KC:-http://localhost:8080}
REALM=ztgate
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
failed=0

[ -x "$SERVER" ] || { echo "build first: make server" >&2; exit 1; }

check() {	# check <이름> <받은 값> <바라는 값>
	if [ "$2" = "$3" ]; then
		printf 'ok   %-52s %s\n' "$1" "$2"
	else
		printf 'FAIL %-52s %s   (want %s)\n' "$1" "$2" "$3"
		failed=$((failed + 1))
	fi
}

json() {	# json <파이썬 식>   표준 입력의 JSON 을 j 로 읽어 식의 값을 찍는다
	python3 -c "import json, sys; j = json.load(sys.stdin); print($1)"
}

for i in $(seq 90); do
	curl -sf "$KC/realms/master" > /dev/null && break
	sleep 2
done
curl -sf "$KC/realms/master" > /dev/null || { echo "Keycloak is not up at $KC" >&2; exit 1; }

ADMIN=$(curl -sf -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
	"$KC/realms/master/protocol/openid-connect/token" | json 'j["access_token"]')
api() {	# api <method> <path> [json]
	curl -sf -X "$1" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
		"$KC/admin/realms$2" ${3:+-d "$3"}
}

# ---- 1. Keycloak 설정 (README "사용자 로그인" 의 순서 그대로) --------------------------
api POST "" "{\"realm\":\"$REALM\",\"enabled\":true}" || { echo "cannot create realm" >&2; exit 1; }

# 공개 클라이언트: 비밀이 없다 (사용자의 장비에 비밀을 둘 수 없다). 기기 인가를 켠다.
# Windows GUI 용으로 표준 흐름(인가 코드)을 켜고, 돌아올 주소는 루프백만 둔다.
# PKCE 를 클라이언트에서 필수로 걸지는 않는다 — Keycloak 은 그 설정을 기기 인가에도 적용해
# PKCE 를 보내지 않는 client/ztgate_login 이 막힌다. Windows GUI 는 PKCE 를 늘 보낸다.
# audience 매퍼가 토큰의 aud 에 ztgate 를 넣고, 그룹 매퍼가 groups 클레임에 그룹 이름을 넣는다.
api POST "/$REALM/clients" '{
	"clientId": "ztgate", "publicClient": true, "standardFlowEnabled": true,
	"redirectUris": ["http://127.0.0.1/*"],
	"directAccessGrantsEnabled": true,
	"attributes": {"oauth2.device.authorization.grant.enabled": "true"},
	"protocolMappers": [
		{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		 "config": {"included.client.audience": "ztgate", "access.token.claim": "true", "id.token.claim": "false"}},
		{"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
		 "config": {"claim.name": "groups", "full.path": "false", "access.token.claim": "true",
		            "id.token.claim": "false", "userinfo.token.claim": "false"}}
	]}' || { echo "cannot create client ztgate" >&2; exit 1; }

# 같은 IdP 의 다른 앱. 이 앱에 준 토큰으로 VPN 에 들어오면 안 된다.
api POST "/$REALM/clients" '{"clientId": "other", "publicClient": true, "standardFlowEnabled": false,
	"directAccessGrantsEnabled": true}' || { echo "cannot create client other" >&2; exit 1; }

api POST "/$REALM/groups" '{"name": "ops"}' || { echo "cannot create group" >&2; exit 1; }
api POST "/$REALM/users" '{"username": "alice", "enabled": true, "email": "alice@example.test",
	"emailVerified": true, "firstName": "Alice", "lastName": "Test", "groups": ["/ops"],
	"credentials": [{"type": "password", "value": "alice-pw", "temporary": false}]}' \
	|| { echo "cannot create user" >&2; exit 1; }

# ---- 2. 서버 쪽 설정 ----------------------------------------------------------------------
curl -sf "$KC/realms/$REALM/.well-known/openid-configuration" > "$WORK/discovery.json"
ISSUER=$(json 'j["issuer"]' < "$WORK/discovery.json")
curl -sf "$(json 'j["jwks_uri"]' < "$WORK/discovery.json")" > "$WORK/jwks.json"
cat > "$WORK/idp.conf" <<EOF
issuer        $ISSUER
audience      ztgate
jwks          jwks.json
user-claim    preferred_username
groups-claim  groups
EOF
echo "     issuer $ISSUER, $(json 'len(j["keys"])' < "$WORK/jwks.json") keys in the JWKS" \
	"($(json '",".join(k.get("use", "?") + ":" + k.get("alg", "?") for k in j["keys"])' < "$WORK/jwks.json"))"

token() {	# token <client-id>
	curl -sf -d client_id="$1" -d username=alice -d password=alice-pw -d grant_type=password \
		-d scope=openid "$KC/realms/$REALM/protocol/openid-connect/token" | json 'j["access_token"]'
}
verify() { "$SERVER" verify-token "$WORK/idp.conf" | sed 's/ expires_in=.*//'; }

# ---- 3 ~ 5. 토큰 -------------------------------------------------------------------------
TOK=$(token ztgate)
echo "     claims: $(echo "$TOK" | cut -d. -f2 | python3 -c 'import base64, json, sys
s = sys.stdin.read().strip(); j = json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
print({k: j.get(k) for k in ("iss", "aud", "preferred_username", "groups", "azp")})')"
check "keycloak: alice's token for ztgate" "$(echo "$TOK" | verify)" "ok user=alice groups=ops"
check "keycloak: a token the same IdP gave another app" "$(token other | verify)" "rejected: wrong_token"
TAMPERED=$(echo "$TOK" | python3 -c 'import base64, json, sys
h, p, s = sys.stdin.read().strip().split(".")
j = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
j["preferred_username"] = "admin"
print(h + "." + base64.urlsafe_b64encode(json.dumps(j).encode()).rstrip(b"=").decode() + "." + s)')
check "keycloak: alice's token with the user changed" "$(echo "$TAMPERED" | verify)" "rejected: untrusted"

# JWKS 갱신 도구가 같은 키를 받아 오는가. 파일을 비워 두고 받게 한 뒤 그 파일로 alice 의 토큰을 다시 본다.
echo '{"keys": []}' > "$WORK/jwks.json"
python3 "$ROOT_DIR/tools/idp/ztgate_jwks.py" "$WORK/idp.conf" --reload none > /dev/null
check "keycloak: tools/idp/ztgate_jwks.py fetches the signing keys" "$(echo "$TOK" | verify)" "ok user=alice groups=ops"

# ---- 6. 기기 인가의 첫 단계 -------------------------------------------------------------
DEVICE=$(json 'j.get("device_authorization_endpoint", "")' < "$WORK/discovery.json")
check "keycloak: discovery offers device authorization" "$([ -n "$DEVICE" ] && echo yes || echo no)" yes
GOT=$(curl -sf -d client_id=ztgate -d scope=openid "$DEVICE" | json '"device_code" in j and "user_code" in j')
check "keycloak: device authorization hands out a code" "$GOT" True

# ---- 7 ~ 8. Windows GUI 의 흐름: 인가 코드 + PKCE, 루프백 redirect, 갱신, 폐기 --------------
cat > "$WORK/pkce.py" <<'PY'
"""브라우저가 하는 일을 대신한다: 로그인 화면을 받아 입력하고, 앱으로 돌아가는 주소를 받는다.
인자: discovery.json, 그 뒤로 할 일. 결과는 한 줄씩 'key value'."""
import base64, hashlib, html.parser, http.cookiejar, json, secrets, sys, urllib.error, urllib.parse, urllib.request

meta = json.load(open(sys.argv[1]))


class Form(html.parser.HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("id") == "kc-form-login":
            self.action = a["action"]


class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(op, url, form=None):
    try:
        r = op.open(urllib.request.Request(url, urllib.parse.urlencode(form).encode() if form else None))
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def login(port):
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), Stop)
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = "http://127.0.0.1:%d/callback" % port
    q = {"response_type": "code", "client_id": "ztgate", "redirect_uri": redirect, "scope": "openid",
         "state": secrets.token_urlsafe(8), "code_challenge": challenge, "code_challenge_method": "S256"}
    _, body, _ = call(op, meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q))
    f = Form()
    f.feed(body)
    if not f.action:
        return None
    # 브라우저는 127.0.0.1 을 안전한 출처로 보고 Secure 쿠키도 보낸다. urllib 은 그렇지 않다.
    for c in jar:
        c.secure = False
    _, _, h = call(op, f.action, {"username": "alice", "password": "alice-pw", "credentialId": ""})
    back = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query))
    if not h.get("Location", "").startswith(redirect) or back.get("state") != q["state"]:
        return None
    _, body, _ = call(op, meta["token_endpoint"], {"grant_type": "authorization_code", "code": back["code"],
                                                   "redirect_uri": redirect, "client_id": "ztgate",
                                                   "code_verifier": verifier})
    return json.loads(body)


def refresh(rt):
    st, _, _ = call(urllib.request.build_opener(), meta["token_endpoint"],
                    {"grant_type": "refresh_token", "refresh_token": rt, "client_id": "ztgate"})
    return st


a = login(49823)
b = login(61234)
print("port_a", "ok" if a and "access_token" in a else "fail")
print("port_b", "ok" if b and "access_token" in b else "fail")
if a:
    open(sys.argv[2], "w").write(a["access_token"])
    print("refresh", refresh(a["refresh_token"]))
    st, _, _ = call(urllib.request.build_opener(), meta["revocation_endpoint"],
                    {"token": a["refresh_token"], "token_type_hint": "refresh_token", "client_id": "ztgate"})
    print("revoke", st)
    print("refresh_after_revoke", refresh(a["refresh_token"]))
PY
python3 "$WORK/pkce.py" "$WORK/discovery.json" "$WORK/pkce.jwt" > "$WORK/pkce.out" 2>&1
pk() { awk -v k="$1" '$1 == k { print $2 }' "$WORK/pkce.out"; }
check "keycloak: code + PKCE, loopback port 49823" "$(pk port_a)" ok
check "keycloak: code + PKCE, loopback port 61234" "$(pk port_b)" ok
check "keycloak: that token on the server" "$( [ -s "$WORK/pkce.jwt" ] && verify < "$WORK/pkce.jwt")" "ok user=alice groups=ops"
check "keycloak: refresh token works" "$(pk refresh)" 200
check "keycloak: revocation (RFC 7009)" "$(pk revoke)" 200
check "keycloak: refresh after revocation" "$(pk refresh_after_revoke)" 400
[ "$failed" -eq 0 ] || cat "$WORK/pkce.out"

echo
if [ "$failed" -eq 0 ]; then
	echo "all passed"
else
	echo "$failed failed"
fi
exit "$failed"
