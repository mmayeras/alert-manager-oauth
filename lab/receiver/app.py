"""Test webhook receiver for Alertmanager OAuth2.

Really validates the bearer token sent by Alertmanager: RS256 signature against
the Keycloak JWKS, issuer, audience, expiry, required scope and an allow-list of
client IDs. Logs one JSON line per request with the client_id and a summary of
the payload. The token itself is never logged.

Standard library HTTP server + PyJWT only, so it runs on a distroless image.

Endpoints:
  POST /alerts         authenticated flow (bearer required in strict mode)
  POST /alerts-legacy  legacy flow, no authentication
  GET  /stats          counters and last events
  GET  /healthz        probe
"""

import json
import os
import ssl
import sys
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt

ISSUER = os.environ["OIDC_ISSUER"]
JWKS_URL = os.environ.get("OIDC_JWKS_URL", f"{ISSUER}/protocol/openid-connect/certs")
AUDIENCE = os.environ.get("OIDC_AUDIENCE", "alert-collector")
REQUIRED_SCOPE = os.environ.get("REQUIRED_SCOPE", "alerting")
ALLOWED_CLIENTS = {
    c.strip() for c in os.environ.get("ALLOWED_CLIENTS", "ocp-allowed").split(",") if c.strip()
}
# strict: reject anything without a valid token.
# tolerant: accept everything, log the validation result (migration mode).
AUTH_MODE = os.environ.get("AUTH_MODE", "strict")
CA_FILE = os.environ.get("OIDC_CA_FILE")
LEEWAY = int(os.environ.get("JWT_LEEWAY_SECONDS", "30"))
PORT = int(os.environ.get("PORT", "8443"))
TLS_CERT = os.environ.get("TLS_CERT", "/certs/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY", "/certs/tls.key")

_ssl_ctx = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else None
_jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True, lifespan=300, ssl_context=_ssl_ctx)

_lock = threading.Lock()
STATS = Counter()
EVENTS = deque(maxlen=100)


def log(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False), file=sys.stdout, flush=True)


def verify_bearer(header):
    """Return (http_status, details). 200 means the token is accepted."""
    if not header or not header.lower().startswith("bearer "):
        return 401, {"error": "missing_token"}
    token = header[7:].strip()
    try:
        key = _jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway=LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        return 401, {"error": "invalid_token", "detail": f"{type(exc).__name__}: {exc}"}

    # Keycloak puts the OAuth2 client ID in "azp" (and in "client_id" when the
    # service_account client scope is attached).
    client_id = claims.get("azp") or claims.get("client_id")
    info = {
        "client_id": client_id,
        "jti": claims.get("jti"),
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
        "scope": claims.get("scope", ""),
    }
    if REQUIRED_SCOPE and REQUIRED_SCOPE not in claims.get("scope", "").split():
        return 403, {"error": "insufficient_scope", **info}
    if client_id not in ALLOWED_CLIENTS:
        return 403, {"error": "client_not_allowed", **info}
    return 200, info


def summarize(payload) -> dict:
    if not isinstance(payload, dict):
        return {"payload": "not-json"}
    alerts = payload.get("alerts") or []
    return {
        "am_receiver": payload.get("receiver"),
        "am_status": payload.get("status"),
        "alerts": len(alerts),
        "alertnames": sorted({a.get("labels", {}).get("alertname", "?") for a in alerts}),
        "external_url": payload.get("externalURL"),
    }


def record(endpoint, outcome, client_id, summary, extra) -> None:
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "endpoint": endpoint,
        "outcome": outcome,
        "client_id": client_id,
        **summary,
        **extra,
    }
    with _lock:
        STATS[f"{endpoint}|{outcome}|{client_id}"] += 1
        EVENTS.append(event)
    log(event)


class Handler(BaseHTTPRequestHandler):
    server_version = "webhook-receiver-lab"

    def log_message(self, fmt, *args):
        pass  # one JSON line per request is enough

    def _send(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _payload(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok"})
        if self.path == "/stats":
            with _lock:
                body = {
                    "mode": AUTH_MODE,
                    "issuer": ISSUER,
                    "audience": AUDIENCE,
                    "required_scope": REQUIRED_SCOPE,
                    "allowed_clients": sorted(ALLOWED_CLIENTS),
                    "counters": dict(STATS),
                    "events": list(EVENTS),
                }
            return self._send(200, body)
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/alerts-legacy":
            record("/alerts-legacy", "accepted", None, summarize(self._payload()), {})
            return self._send(200, {"status": "ok"})
        if self.path != "/alerts":
            return self._send(404, {"error": "not_found"})

        status, info = verify_bearer(self.headers.get("Authorization"))
        summary = summarize(self._payload())
        accepted = status == 200 or AUTH_MODE == "tolerant"
        outcome = "accepted" if status == 200 else ("tolerated" if accepted else "rejected")
        record("/alerts", outcome, info.get("client_id"), summary,
               {"auth_status": status, "auth": info, "mode": AUTH_MODE})
        if accepted:
            return self._send(200, {"status": "ok"})
        challenge = f'Bearer error="{info["error"]}"'
        if status == 403:
            challenge += f', scope="{REQUIRED_SCOPE}"'
        return self._send(status, info, {"WWW-Authenticate": challenge})


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    log({"msg": "listening", "port": PORT, "mode": AUTH_MODE, "issuer": ISSUER,
         "audience": AUDIENCE, "allowed_clients": sorted(ALLOWED_CLIENTS)})
    server.serve_forever()


if __name__ == "__main__":
    main()
