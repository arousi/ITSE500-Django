#!/bin/sh
# End-to-end test harness for the django-bolt port, run INSIDE the image.
# Covers: auth_api (health/register/login/refresh/pin/otp/oauth-authorize/oauth-result),
# user_mang (/me GET+POST+PATCH), crypto_api (umk GET/POST), and the Django ASGI
# mount (admin). Uses SQLite (no DB_HOST). Python for HTTP (slim has no curl).
#
# Usage (on the VPS, after `docker build -f Dockerfile.vps -t itse500-d6-bolt .`):
#   docker run --rm --user root -e DJANGO_DEBUG=True \
#     -v "$PWD/scripts/bolt_poc_test.sh:/t.sh:ro" --entrypoint sh itse500-d6-bolt /t.sh
set -e

echo "=== migrate (SQLite) ==="
python manage.py migrate --noinput 2>&1 | tail -2

echo "=== start runbolt on 127.0.0.1:8001 ==="
python manage.py runbolt --host 127.0.0.1 --port 8001 > /tmp/bolt.log 2>&1 &
BOLT_PID=$!
sleep 8
echo "--- runbolt startup log ---"
tail -12 /tmp/bolt.log

echo "=== E2E suite ==="
set +e
python - <<'PYEOF'
import json, urllib.request, urllib.error

BASE = "http://127.0.0.1:8001"
PASS, FAIL = [], []

def call(method, path, body=None, token=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, method=method, data=data, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=15)
        raw = r.read().decode()
        try:
            return r.status, json.loads(raw)
        except Exception:
            return r.status, raw[:200]
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:200]
    except Exception as e:
        return "ERR", repr(e)

def check(name, got_status, want_status, detail=""):
    ok = got_status == want_status
    (PASS if ok else FAIL).append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {got_status} (want {want_status}) {detail}")

# --- auth_api simple ---
s, b = call("GET", "/api/v1/auth_api/health/")
check("health", s, 200, str(b)[:80])

s, b = call("POST", "/api/v1/auth_api/register/", {"username": "boltuser", "email": "bolt@example.com", "user_password": "hash123456"})
check("register", s, 201, f"keys={sorted(b)[:6] if isinstance(b, dict) else b}")
access = b.get("access_token") if isinstance(b, dict) else None

s, b = call("POST", "/api/v1/auth_api/register/", {"username": "boltuser", "email": "bolt@example.com", "user_password": "hash123456"})
check("register-existing", s, 200, str(b)[:80])

s, b = call("POST", "/api/v1/auth_api/login/", {"email": "bolt@example.com", "password": "hash123456"})
check("login", s, 200, f"conv={len(b.get('conversations', [])) if isinstance(b, dict) else '?'}")
access = b.get("access_token") or access
refresh = b.get("refresh_token") if isinstance(b, dict) else None

s, b = call("POST", "/api/v1/auth_api/login/", {"email": "bolt@example.com", "password": "WRONGHASH"})
check("login-bad-password", s, 401)

s, b = call("POST", "/api/v1/auth_api/token/refresh/", {"refresh": refresh})
check("token-refresh", s, 200, f"access={'access' in b if isinstance(b, dict) else b}")

s, b = call("POST", "/api/v1/auth_api/token/refresh/", {"refresh": "garbage"})
check("token-refresh-bad", s, 401)

s, b = call("POST", "/api/v1/auth_api/verify-email-pin/", {"email": "bolt@example.com", "pin": "99999"}, token=access)
check("verify-pin-invalid", s, 400, str(b)[:60])

s, b = call("POST", "/api/v1/auth_api/otp-login/", {})
check("otp-gone", s, 410)

s, b = call("POST", "/api/v1/auth_api/logout/", {}, token=access)
check("logout", s, 200)

s, b = call("POST", "/api/v1/auth_api/logout/", {})
check("logout-unauth", s, 401)

# --- OAuth (no provider round-trip; authorize + state machinery only) ---
s, b = call("GET", "/api/v1/auth_api/google/authorize/")
state = b.get("state") if isinstance(b, dict) else None
check("google-authorize", s, 200, f"state={bool(state)} url={'authorize_url' in b if isinstance(b, dict) else '?'}")

s, b = call("GET", f"/api/v1/auth_api/oauth/result/{state}/")
check("oauth-result-not-ready", s, 202)

s, b = call("GET", "/api/v1/auth_api/google/callback/?state=BOGUS&code=x")
check("callback-bad-state", s, 400)

# 200 with env configured, 400 ("redirect_uri not configured") without — both fine here
s, b = call("GET", "/api/v1/auth_api/github/authorize/")
check("github-authorize", s, s if s in (200, 400) else 200, str(b)[:60])

# --- user_mang /me ---
s, b = call("GET", "/api/v1/user_mang/me/", token=access)
check("me-get", s, 200, f"profile={'profile' in b if isinstance(b, dict) else '?'} chat={'chat' in b if isinstance(b, dict) else '?'}")

s, b = call("GET", "/api/v1/user_mang/me/")
check("me-get-unauth", s, 401)

s, b = call("GET", "/api/v1/user_mang/me/?temp_id=visitor-test-123")
check("me-visitor", s, 200, f"tokens={'tokens' in b if isinstance(b, dict) else '?'}")

conv_id = "11111111-2222-3333-4444-555555555555"
msg_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
s, b = call("POST", "/api/v1/user_mang/me/", {
    "chat": True,
    "conversations": [{"conversation_id": conv_id, "title": "Bolt test conv"}],
    "messages": [{"message_id": msg_id, "conversation_id": conv_id, "vote": True}],
}, token=access)
summary = b.get("summary", {}) if isinstance(b, dict) else {}
check("me-post-upsert", s, 200, f"conv_created={summary.get('conversations_created')} msg_created={summary.get('messages_created')}")

s, b = call("GET", "/api/v1/user_mang/me/?chat=true", token=access)
convs = (b.get("chat") or {}).get("conversations", []) if isinstance(b, dict) else []
check("me-get-after-upsert", s, 200, f"convs={len(convs)}")

s, b = call("PATCH", "/api/v1/user_mang/me/", {"phone_number": "+218911111111"}, token=access)
check("me-patch", s, 200, str((b.get('profile') or {}).get('phone_number') if isinstance(b, dict) else b))

# --- crypto_api (cross-app token check) ---
s, b = call("GET", "/api/v1/crypto_api/umk", token=access)
check("umk-get-empty", s, 200, f"exists={b.get('exists') if isinstance(b, dict) else '?'}")

s, b = call("POST", "/api/v1/crypto_api/umk", {}, token=access)
check("umk-post", s, 201)

s, b = call("GET", "/api/v1/crypto_api/umk", token=access)
check("umk-get-exists", s, 200, f"exists={b.get('exists') if isinstance(b, dict) else '?'}")

# --- Django ASGI mount ---
s, b = call("GET", "/admin/login/")
check("admin-mounted", s, 200)

s, b = call("GET", "/healthz")
check("healthz", s, 200)

print(f"\n=== RESULT: {len(PASS)} passed, {len(FAIL)} failed ===")
if FAIL:
    print("FAILED:", ", ".join(FAIL))
    raise SystemExit(1)
PYEOF
RC=$?
set -e

kill "$BOLT_PID" 2>/dev/null || true
echo "=== done (rc=$RC) ==="
exit $RC
