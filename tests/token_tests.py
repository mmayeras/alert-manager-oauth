"""Token endpoint and receiver tests (README 3.2).

Runs INSIDE a pod in openshift-monitoring (same network path as Alertmanager),
on the distroless Hummingbird python image: standard library only. The README
command pipes it to `python3 -`, prefixed with two lines defining S_ALLOWED and
S_NOT_ALLOWED, so client secrets never appear in the pod spec.

Expects the receiver in AUTH_MODE=strict. Exit code 1 if any check fails.
"""

import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = globals().get(
    "TOKEN_URL",
    "https://keycloak.am-oauth2-lab.svc:8443/realms/monitoring/protocol/openid-connect/token",
)
RECEIVER_BASE = globals().get("RECEIVER_BASE", "https://webhook-receiver.am-oauth2-lab.svc:8443")
CA = globals().get("CA", "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt")
S_ALLOWED = globals()["S_ALLOWED"]
S_NOT_ALLOWED = globals()["S_NOT_ALLOWED"]

CTX = ssl.create_default_context(cafile=CA)
results = {"ok": 0, "ko": 0}


def http(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def check(name, expected, got):
    ok = expected == got
    results["ok" if ok else "ko"] += 1
    print(f"{'OK' if ok else 'KO'}  {name} (expected HTTP {expected}, got HTTP {got})")


def token(client_id, secret, scope="alerting", basic=False):
    form = {"grant_type": "client_credentials"}
    if scope:
        form["scope"] = scope
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if basic:
        cred = f"{urllib.parse.quote(client_id)}:{urllib.parse.quote(secret)}"
        headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
    else:
        form.update(client_id=client_id, client_secret=secret)
    status, body = http(TOKEN_URL, urllib.parse.urlencode(form).encode(), headers)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {}


def claims(jwt):
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


PAYLOAD = json.dumps({
    "version": "4", "status": "firing", "receiver": "token-tests",
    "alerts": [{"status": "firing", "labels": {"alertname": "TokenTestsSynthetic"}}],
}).encode()


def post_alert(path, bearer=None):
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return http(RECEIVER_BASE + path, PAYLOAD, headers)[0]


print(f"== Token endpoint: {TOKEN_URL}")
status, tok = token("ocp-allowed", S_ALLOWED)
check("ocp-allowed token, credentials in body (client_secret_post)", 200, status)
if status == 200:
    shown = {k: v for k, v in tok.items() if k not in ("access_token", "refresh_token")}
    print(f"    response: {json.dumps(shown)}")
    c = claims(tok["access_token"])
    keep = ("iss", "aud", "azp", "client_id", "scope", "iat", "exp", "jti")
    print(f"    claims:   {json.dumps({k: c.get(k) for k in keep})}")
check("ocp-allowed token, credentials in Basic Auth (client_secret_basic)", 200,
      token("ocp-allowed", S_ALLOWED, basic=True)[0])
check("ocp-allowed token, wrong secret", 401, token("ocp-allowed", "wrong-secret")[0])
_, tok_noscope = token("ocp-allowed", S_ALLOWED, scope=None)
_, tok_not_allowed = token("ocp-not-allowed", S_NOT_ALLOWED)

print(f"== Receiver: {RECEIVER_BASE}")
check("/alerts with valid token", 200, post_alert("/alerts", tok.get("access_token")))
check("/alerts without token", 401, post_alert("/alerts"))
check("/alerts with forged token", 401,
      post_alert("/alerts", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"))
check("/alerts token without alerting scope (no audience)", 401,
      post_alert("/alerts", tok_noscope.get("access_token")))
check("/alerts token from a client not allowed (ocp-not-allowed)", 403,
      post_alert("/alerts", tok_not_allowed.get("access_token")))
check("/alerts-legacy without token (legacy flow)", 200, post_alert("/alerts-legacy"))

print(f"== Result: {results['ok']} OK, {results['ko']} KO")
sys.exit(1 if results["ko"] else 0)
