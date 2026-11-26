"""Public tests for the passkey assertion exercise."""

import hashlib
import hmac
import json

from passkeyauth import (
    assertion_batch,
    check_origin,
    consume_challenge,
    issue_challenge,
    verify,
    verify_signature,
)

RP_ID = "login.example.com"
ORIGIN = "https://login.example.com"
ALICE_KEY = b"alice-registration-key"
BOB_KEY = b"bob-registration-key"


def _canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign(assertion, key):
    client_digest = hashlib.sha256(_canonical_json(assertion["client_data"])).digest()
    client_part = hmac.new(key, client_digest, hashlib.sha256).hexdigest()
    auth_part = hmac.new(key, assertion["authenticator_data"], hashlib.sha256).hexdigest()
    assertion["signature"] = client_part + "." + auth_part
    return assertion


def _store():
    return {
        "credentials": {
            "cred-alice": {
                "user": "alice",
                "public_key": ALICE_KEY,
                "sign_count": 5,
                "origin": ORIGIN,
                "rp_id": RP_ID,
            },
            "cred-bob": {
                "user": "bob",
                "public_key": BOB_KEY,
                "sign_count": 5,
                "origin": ORIGIN,
                "rp_id": RP_ID,
            },
        },
        "challenges": {},
    }


def _issue(store, user, now=1000):
    return issue_challenge(
        store,
        user,
        now,
        {"ttl": 300, "rp_id": RP_ID, "origin": ORIGIN},
    )["challenge"]


def _assertion(store, user, challenge, sign_count, key, credential_id, **overrides):
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": ORIGIN,
        "rp_id": RP_ID,
    }
    client_data.update(overrides)
    assertion = {
        "challenge": challenge,
        "client_data": client_data,
        "authenticator_data": b"authenticator-data-" + credential_id.encode(),
        "credential_id": credential_id,
        "sign_count": sign_count,
    }
    return _sign(assertion, key)


def test_issue_challenge_can_only_be_consumed_once():
    store = _store()
    challenge = _issue(store, "alice")
    assert challenge
    assert consume_challenge(store, challenge, "alice", 1001) is True
    assert consume_challenge(store, challenge, "alice", 1002) is False


def test_counter_increment_succeeds_and_replay_is_rejected():
    store = _store()
    first = _assertion(store, "alice", _issue(store, "alice"), 6, ALICE_KEY, "cred-alice")
    assert verify(store, "alice", first, 1001)["ok"] is True

    replay = _assertion(store, "alice", _issue(store, "alice"), 6, ALICE_KEY, "cred-alice")
    assert verify(store, "alice", replay, 1002)["ok"] is False


def test_origin_requires_an_exact_match():
    assert check_origin({"origin": ORIGIN}, ORIGIN) is True
    assert check_origin({"origin": ORIGIN + ".attacker.test"}, ORIGIN) is False


def test_signature_covers_authenticator_data():
    store = _store()
    assertion = _assertion(store, "alice", _issue(store, "alice"), 6, ALICE_KEY, "cred-alice")
    assert verify_signature(assertion, ALICE_KEY) is True

    assertion["authenticator_data"] += b"-tampered"
    assert verify_signature(assertion, ALICE_KEY) is False


def test_batch_assertions_are_independent():
    store = _store()
    alice = _assertion(store, "alice", _issue(store, "alice"), 6, ALICE_KEY, "cred-alice")
    bob = _assertion(store, "bob", _issue(store, "bob"), 6, BOB_KEY, "cred-bob")

    result = assertion_batch(
        [
            {"user": "alice", "assertion": alice},
            {"user": "bob", "assertion": bob},
        ],
        store,
        1001,
    )

    assert result["results"][0]["ok"] is True
    assert result["results"][0]["credential_id"] == "cred-alice"
    assert result["results"][1]["ok"] is True
    assert result["results"][1]["credential_id"] == "cred-bob"