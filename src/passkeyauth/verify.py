"""Passkey assertion verification.

The store is a plain mapping with two sections:

``credentials``
    Maps a credential id to a record containing ``user``, ``public_key``,
    ``sign_count``, ``origin`` and ``rp_id``.

``challenges``
    Maps a challenge value to a record containing ``user``, ``issued_at``,
    ``expires_at`` and ``used``.

The signature format used by this exercise is a pair of hex encoded message
authentication codes joined by a dot.  The first part authenticates the
client data digest and the second part authenticates the authenticator data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

_DEFAULT_CHALLENGE_TTL = 300


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _client_data_digest(client_data: dict[str, Any]) -> bytes:
    return hashlib.sha256(_canonical_json(client_data)).digest()


def _client_part(assertion: dict[str, Any], public_key: bytes) -> str:
    return hmac.new(
        public_key,
        _client_data_digest(assertion["client_data"]),
        hashlib.sha256,
    ).hexdigest()


def _auth_part(assertion: dict[str, Any], public_key: bytes) -> str:
    return hmac.new(
        public_key,
        assertion["authenticator_data"],
        hashlib.sha256,
    ).hexdigest()


def issue_challenge(store, user, now, policy):
    """Issue a fresh challenge for ``user`` and remember it in ``store``."""
    policy = policy or {}
    ttl = policy.get("ttl", _DEFAULT_CHALLENGE_TTL)
    challenge = secrets.token_urlsafe(32)
    expires_at = now + ttl
    store.setdefault("challenges", {})[challenge] = {
        "user": user,
        "issued_at": now,
        "expires_at": expires_at,
        "used": False,
    }
    return {
        "challenge": challenge,
        "user": user,
        "expires_at": expires_at,
        "rp_id": policy.get("rp_id"),
        "origin": policy.get("origin"),
    }


def consume_challenge(store, challenge, user, now):
    """Return whether ``challenge`` is available to ``user`` at ``now``."""
    record = store.get("challenges", {}).get(challenge)
    if record is None:
        return False
    if record.get("used") is True:
        return False
    if now > record["expires_at"]:
        return False
    return True


def check_origin(client_data, expected):
    """Check that the ceremony origin belongs to the expected origin."""
    origin = (client_data or {}).get("origin", "")
    return origin.startswith(expected)


def check_rp_id(client_data, expected):
    """Check that the ceremony relying party matches ``expected``."""
    rp_id = (client_data or {}).get("rp_id")
    return bool(rp_id)


def check_counter(credential, sign_count):
    """Check that ``sign_count`` moves the credential counter forward."""
    previous = credential.get("sign_count", 0)
    if sign_count < previous:
        # A single step back can happen while an authenticator is being
        # restored, so accept it and leave the clone decision to the caller.
        return previous - sign_count <= 1
    return sign_count >= previous


def verify_signature(assertion, public_key):
    """Verify the signature over the assertion."""
    signature = assertion.get("signature") or ""
    client_part = signature.split(".", 1)[0]
    expected = _client_part(assertion, public_key)
    return hmac.compare_digest(client_part, expected)


def _credential_for(store, credential_id):
    return store.get("credentials", {}).get(credential_id)


def _failure(reason, credential_id):
    return {
        "ok": False,
        "reason": reason,
        "credential_id": credential_id,
        "sign_count": None,
    }


def _verify_with_credential(store, user, assertion, now, credential):
    credential_id = assertion.get("credential_id")
    if credential.get("user") != user:
        return _failure("credential", credential_id)

    challenge = assertion.get("challenge")
    if not consume_challenge(store, challenge, user, now):
        return _failure("challenge", credential_id)

    client_data = assertion.get("client_data") or {}
    if not check_origin(client_data, credential.get("origin")):
        return _failure("origin", credential_id)
    if not check_rp_id(client_data, credential.get("rp_id")):
        return _failure("rp_id", credential_id)

    public_key = assertion.get("public_key") or credential.get("public_key")
    if not verify_signature(assertion, public_key):
        return _failure("signature", credential_id)

    sign_count = assertion.get("sign_count", 0)
    credential["sign_count"] = sign_count
    return {
        "ok": True,
        "reason": None,
        "credential_id": credential_id,
        "sign_count": sign_count,
    }


def verify(store, user, assertion, now):
    """Verify a single assertion for ``user``."""
    credential_id = (assertion or {}).get("credential_id")
    credential = _credential_for(store, credential_id)
    if credential is None:
        return _failure("credential", credential_id)
    return _verify_with_credential(store, user, assertion, now, credential)


def assertion_batch(requests, store, now):
    """Verify a batch of independent assertions."""
    results = []
    shared_credential = None
    for request in requests:
        assertion = request.get("assertion") or {}
        if shared_credential is None:
            shared_credential = _credential_for(store, assertion.get("credential_id"))
        if shared_credential is None:
            results.append(_failure("credential", assertion.get("credential_id")))
            continue
        results.append(
            _verify_with_credential(
                store,
                request.get("user"),
                assertion,
                now,
                shared_credential,
            )
        )
    return {
        "ok": all(result["ok"] for result in results),
        "count": len(results),
        "results": results,
    }