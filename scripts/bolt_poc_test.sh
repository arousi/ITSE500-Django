#!/bin/sh
# Validated end-to-end test harness for a django-bolt endpoint, run INSIDE the D6+bolt image.
# See DJANGO6_BOLT_PORT_HANDOFF.md §6. Uses SQLite (no DB_HOST) + a freshly-minted simplejwt
# token WITH a `sub` claim (django-bolt reads `sub` as the user id). Python for HTTP (slim has no curl).
#
# Usage (on the VPS, after `docker build -f Dockerfile.vps -t itse500-d6-bolt .`):
#   docker run --rm --user root -e DJANGO_DEBUG=True \
#     -v "$PWD/scripts/bolt_poc_test.sh:/t.sh:ro" --entrypoint sh itse500-d6-bolt /t.sh
set -e

echo "=== migrate (SQLite) ==="
python manage.py migrate --noinput 2>&1 | tail -3

echo "=== create test user + mint a simplejwt access token (with sub) ==="
python manage.py shell <<'PYEOF'
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
U = get_user_model()
u, created = U.objects.get_or_create(username="bolttest")
access = RefreshToken.for_user(u).access_token
access["sub"] = str(u.pk)   # django-bolt's Rust JWT verifier reads `sub` as the user id
open("/tmp/tok", "w").write(str(access))
print("user pk:", u.pk, "| created:", created, "| claims:", dict(access.payload))
PYEOF
TOK=$(cat /tmp/tok)
echo "token length: ${#TOK}"

echo "=== start runbolt on 127.0.0.1:8001 ==="
python manage.py runbolt --host 127.0.0.1 --port 8001 > /tmp/bolt.log 2>&1 &
BOLT_PID=$!
sleep 8
echo "--- runbolt startup log ---"
tail -15 /tmp/bolt.log

echo "=== E2E: GET (exists:false) -> POST (201) -> GET (exists:true) ==="
python - "$TOK" <<'PYEOF'
import sys, urllib.request, urllib.error
tok = sys.argv[1]
URL = "http://127.0.0.1:8001/api/v1/crypto_api/umk"
def call(method, body=None):
    data = body.encode() if body else None
    req = urllib.request.Request(URL, method=method, data=data,
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, r.read().decode()[:300]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:
        return "ERR", repr(e)
print("GET  #1 :", *call("GET"))
print("POST    :", *call("POST", "{}"))
print("GET  #2 :", *call("GET"))
PYEOF

kill "$BOLT_PID" 2>/dev/null || true
echo "=== done ==="
