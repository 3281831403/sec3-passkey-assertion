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
    """Redeem ``challenge`` for ``user`` at ``now``.

    A challenge is single use: the first successful redemption marks it as
    used and every later redemption of the same value fails.  It is also
    bound to the user it was issued for; a wrong-user attempt never marks
    the challenge as used, so the legitimate user can still redeem it.
    """
    if not isinstance(challenge, str) or not challenge:
        return False

    record = store.get("challenges", {}).get(challenge)
    if not isinstance(record, dict):
        return False

    # Owner check first and without side effects: a failed cross-user
    # redemption must not burn the challenge.
    if record.get("user") != user:
        return False
    if record.get("used") is True:
        return False
    if now > record["expires_at"]:
        return False

    record["used"] = True
    return True


def check_origin(client_data, expected):
    """Check that the ceremony origin exactly matches ``expected``."""
    if not isinstance(expected, str) or not expected:
        return False
    origin = (client_data or {}).get("origin") if isinstance(client_data, dict) else None
    return isinstance(origin, str) and origin == expected


def check_rp_id(client_data, expected):
    """Check that the ceremony relying party id exactly matches ``expected``."""
    if not isinstance(expected, str) or not expected:
        return False
    rp_id = (client_data or {}).get("rp_id") if isinstance(client_data, dict) else None
    return isinstance(rp_id, str) and rp_id == expected


def check_counter(credential, sign_count):
    """Check that ``sign_count`` strictly advances the credential counter.

    The signature counter must be monotonically increasing.  An equal value
    is a replay and a lower value is a rollback; both indicate a cloned
    authenticator and are rejected.
    """
    if not isinstance(credential, dict):
        return False
    previous = credential.get("sign_count", 0)
    if isinstance(previous, bool) or not isinstance(previous, int):
        return False
    if isinstance(sign_count, bool) or not isinstance(sign_count, int):
        return False
    return sign_count > previous


def verify_signature(assertion, public_key):
    """Verify both MAC halves of the assertion signature.

    The first half must authenticate the client-data digest and the second
    half must authenticate the raw authenticator data.  Tampering with
    either protected structure invalidates the signature.
    """
    if not isinstance(assertion, dict):
        return False
    if not isinstance(public_key, (bytes, bytearray)) or not public_key:
        return False

    signature = assertion.get("signature")
    if not isinstance(signature, str):
        return False
    parts = signature.split(".")
    if len(parts) != 2:
        return False
    client_signature, auth_signature = parts

    try:
        expected_client = _client_part(assertion, public_key)
        expected_auth = _auth_part(assertion, public_key)
    except (KeyError, TypeError, ValueError):
        return False

    client_ok = hmac.compare_digest(client_signature, expected_client)
    auth_ok = hmac.compare_digest(auth_signature, expected_auth)
    return client_ok and auth_ok


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
    if not isinstance(assertion, dict):
        return _failure("assertion", None)

    credential_id = assertion.get("credential_id")
    if credential.get("user") != user:
        return _failure("credential", credential_id)

    client_data = assertion.get("client_data")
    if not isinstance(client_data, dict):
        return _failure("client_data", credential_id)

    challenge = assertion.get("challenge")
    # The challenge carried by the signed client data must be the same
    # challenge presented at the top level and redeemed below.
    if client_data.get("challenge") != challenge:
        return _failure("challenge", credential_id)

    if not check_origin(client_data, credential.get("origin")):
        return _failure("origin", credential_id)
    if not check_rp_id(client_data, credential.get("rp_id")):
        return _failure("rp_id", credential_id)

    # Trust only the public key recorded at registration.  A key attached
    # to the assertion itself could be supplied by an attacker.
    public_key = credential.get("public_key")
    if not verify_signature(assertion, public_key):
        return _failure("signature", credential_id)

    sign_count = assertion.get("sign_count", 0)
    if not check_counter(credential, sign_count):
        # Equal (replay) or lower (rollback) counter: cloned authenticator.
        # Do not advance the stored counter on failure.
        return _failure("clone", credential_id)

    # Redeem the one-time challenge only after every other check has
    # succeeded, so a rejected assertion cannot burn a legitimate challenge.
    if not consume_challenge(store, challenge, user, now):
        return _failure("challenge", credential_id)

    credential["sign_count"] = sign_count
    return {
        "ok": True,
        "reason": None,
        "credential_id": credential_id,
        "sign_count": sign_count,
    }


def verify(store, user, assertion, now):
    """Verify a single assertion for ``user``."""
    if not isinstance(assertion, dict):
        return _failure("assertion", None)
    credential_id = assertion.get("credential_id")
    credential = _credential_for(store, credential_id)
    if credential is None:
        return _failure("credential", credential_id)
    return _verify_with_credential(store, user, assertion, now, credential)


def assertion_batch(requests, store, now):
    """Verify a batch of assertions independently.

    Each request resolves its own credential and advances its own counter,
    so the outcome of one assertion can never influence another.
    """
    results = []
    for request in requests or []:
        if not isinstance(request, dict):
            results.append(_failure("request", None))
            continue

        assertion = request.get("assertion")
        if not isinstance(assertion, dict):
            results.append(_failure("assertion", None))
            continue

        credential_id = assertion.get("credential_id")
        credential = _credential_for(store, credential_id)
        if credential is None:
            results.append(_failure("credential", credential_id))
            continue

        results.append(
            _verify_with_credential(
                store,
                request.get("user"),
                assertion,
                now,
                credential,
            )
        )
    return {
        "ok": all(result["ok"] for result in results),
        "count": len(results),
        "results": results,
    }
