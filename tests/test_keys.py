import base64
import time

from keys import KeyStore, generate_key


def test_generated_keys_have_unique_kids():
    assert generate_key(time.time() + 60).kid != generate_key(time.time() + 60).kid


def test_is_expired():
    assert generate_key(time.time() - 10).is_expired()
    assert not generate_key(time.time() + 100).is_expired()


def test_is_expired_with_explicit_now():
    key = generate_key(1000)
    assert key.is_expired(now=2000)
    assert not key.is_expired(now=500)


def test_store_has_one_valid_and_one_expired_key():
    store = KeyStore()
    assert not store.valid_key.is_expired()
    assert store.expired_key.is_expired()


def test_jwks_only_contains_unexpired_keys():
    store = KeyStore()
    kids = [k["kid"] for k in store.jwks()["keys"]]
    assert kids == [store.valid_key.kid]


def test_jwk_fields():
    jwk = KeyStore().valid_key.to_jwk()
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    # e for 65537 is "AQAB" in base64url
    assert jwk["e"] == "AQAB"
    # n must be valid base64url with no padding
    assert "=" not in jwk["n"]
    base64.urlsafe_b64decode(jwk["n"] + "==")


def test_private_pem_format():
    pem = KeyStore().valid_key.private_pem()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
