"""
Push notification sender.

Runs immediately after pipeline/fetch.py in the same CI job and reads the
transient summary that step just wrote (corpus/last-run-new.json) to decide
whether anything happened worth a lock-screen alert.

Deliberately fail-open: a problem here (missing secrets, an expired
subscription, a push service outage) must never fail the build. The site
still has to deploy. Every early-return below is a "nothing to do" or
"nothing we can do about it", never an exception that reaches main().

Secrets (set once, by hand, in GitHub Settings -> Secrets and variables ->
Actions -- never committed):
  VAPID_PRIVATE_KEY   base64url, unpadded, raw 32-byte EC private scalar
                       (SECP256R1). See README / setup notes for how this
                       was generated.
  PUSH_SUBSCRIPTION   the JSON a browser's pushManager.subscribe() call
                       returns, exactly as the "Enable notifications"
                       button on the site displays it for copy/paste:
                       {"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}}

VAPID_PUBLIC_KEY is not read here -- it is not secret (it is embedded in the
site's own JS as the applicationServerKey) and this script derives it from
the private key, so the two can never drift apart.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))

import http_ece as ece  # noqa: E402  (vendored -- see pipeline/http_ece/__init__.py)

import httpx  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    decode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parent.parent
LAST_RUN_NEW = ROOT / "corpus" / "last-run-new.json"

SITE_URL = "https://vigneshn08.github.io/nevintel/"
VAPID_SUB = "mailto:nemmikantivignesh17@gmail.com"
VAPID_JWT_TTL = 12 * 3600       # how long the JWT itself is valid for
PUSH_TTL_SECONDS = 12 * 3600    # how long the push service may hold the message


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_new_articles() -> list[dict] | None:
    if not LAST_RUN_NEW.exists():
        print("  [notify] no corpus/last-run-new.json -- fetch.py did not run first, skipping.")
        return None
    try:
        data = json.loads(LAST_RUN_NEW.read_text())
    except json.JSONDecodeError as exc:
        print(f"  [notify] corpus/last-run-new.json is not valid JSON ({exc}), skipping.")
        return None
    if data.get("first_run"):
        print("  [notify] first run against an empty corpus -- that is a backfill, not news. Skipping.")
        return None
    articles = data.get("articles") or []
    if not articles:
        print("  [notify] nothing new this run, nothing to send.")
        return None
    return articles


def build_payload(articles: list[dict]) -> bytes:
    n = len(articles)
    top = articles[0]["title"]
    if n == 1:
        body = top
    else:
        body = f"{top} — and {n - 1} more"
    payload = {
        "title": "NEVINTEL",
        "body": body,
        "url": SITE_URL,
        "count": n,
    }
    return json.dumps(payload).encode("utf-8")


def vapid_jwt(aud: str, private_key) -> str:
    header = {"typ": "JWT", "alg": "ES256"}
    payload = {
        "aud": aud,
        "exp": int(time.time()) + VAPID_JWT_TTL,
        "sub": VAPID_SUB,
    }
    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(payload, separators=(",", ":")).encode())
    )
    der_sig = private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input + "." + b64u(raw_sig)


def send(subscription: dict, vapid_private, vapid_public_b64u: str, body: bytes) -> None:
    endpoint = subscription["endpoint"]
    keys = subscription["keys"]
    receiver_pub = b64u_decode(keys["p256dh"])
    auth_secret = b64u_decode(keys["auth"])

    sender_ephemeral = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(16)
    encrypted = ece.encrypt(
        body,
        salt=salt,
        dh=receiver_pub,
        private_key=sender_ephemeral,
        auth_secret=auth_secret,
        version="aes128gcm",
    )

    aud = urlsplit(endpoint)
    aud = f"{aud.scheme}://{aud.netloc}"
    jwt = vapid_jwt(aud, vapid_private)

    resp = httpx.post(
        endpoint,
        content=encrypted,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "aes128gcm",
            "TTL": str(PUSH_TTL_SECONDS),
            "Authorization": f"vapid t={jwt}, k={vapid_public_b64u}",
        },
        timeout=20,
    )

    if resp.status_code in (200, 201, 202):
        print(f"  [notify] sent ({resp.status_code}).")
    elif resp.status_code in (404, 410):
        print(f"  [notify] subscription is gone ({resp.status_code}) -- it expired or was "
              "revoked on the device. Re-subscribe from the site to fix this; not a build error.")
    else:
        print(f"  [notify] push service returned {resp.status_code}: {resp.text[:300]}")


def main() -> int:
    articles = load_new_articles()
    if articles is None:
        return 0

    raw_priv = os.environ.get("VAPID_PRIVATE_KEY", "").strip()
    raw_sub = os.environ.get("PUSH_SUBSCRIPTION", "").strip()
    if not raw_priv or not raw_sub:
        print("  [notify] VAPID_PRIVATE_KEY / PUSH_SUBSCRIPTION not configured yet -- skipping "
              "(this is expected until those secrets are set in the repo).")
        return 0

    try:
        priv_int = int.from_bytes(b64u_decode(raw_priv), "big")
        vapid_private = ec.derive_private_key(priv_int, ec.SECP256R1())
        vapid_public_b64u = b64u(
            vapid_private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        )
    except Exception as exc:  # noqa: BLE001 -- any malformed secret is "can't send", not a build failure
        print(f"  [notify] VAPID_PRIVATE_KEY is not usable ({exc}), skipping.")
        return 0

    try:
        subscription = json.loads(raw_sub)
        subscription["endpoint"]
        subscription["keys"]["p256dh"]
        subscription["keys"]["auth"]
    except Exception as exc:  # noqa: BLE001
        print(f"  [notify] PUSH_SUBSCRIPTION is not usable ({exc}), skipping.")
        return 0

    body = build_payload(articles)

    try:
        send(subscription, vapid_private, vapid_public_b64u, body)
    except Exception as exc:  # noqa: BLE001 -- never fail the site build over a push delivery hiccup
        print(f"  [notify] failed to send: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
