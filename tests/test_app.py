import time

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from app import create_app
from keys import KeyStore


@pytest.fixture
def store():
    return KeyStore()


@pytest.fixture
def client(store):
    return create_app(store).test_client()


def public_key_for(client, kid):
    """Look up a kid in the JWKS and turn it into a key PyJWT can verify with."""
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    jwk = next(k for k in keys if k["kid"] == kid)
    return RSAAlgorithm.from_jwk(jwk)


def test_jwks_returns_valid_key(client, store):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    kids = [k["kid"] for k in resp.get_json()["keys"]]
    assert store.valid_key.kid in kids


def test_jwks_does_not_return_expired_key(client, store):
    kids = [k["kid"] for k in client.get("/.well-known/jwks.json").get_json()["keys"]]
    assert store.expired_key.kid not in kids


def test_auth_returns_verifiable_jwt(client, store):
    token = client.post("/auth").get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == store.valid_key.kid
    assert header["alg"] == "RS256"

    claims = jwt.decode(
        token, public_key_for(client, header["kid"]), algorithms=["RS256"]
    )
    assert claims["exp"] > time.time()


def test_auth_expired_uses_expired_key(client, store):
    resp = client.post("/auth?expired")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)

    header = jwt.get_unverified_header(token)
    assert header["kid"] == store.expired_key.kid

    # Expired key isn't in the JWKS, so verify with it directly
    # and turn off the exp check to read the claims.
    claims = jwt.decode(
        token,
        store.expired_key.private_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims["exp"] < time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            store.expired_key.private_key.public_key(),
            algorithms=["RS256"],
        )


def test_wrong_methods_are_rejected(client):
    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.get("/auth").status_code == 405
    assert client.put("/auth").status_code == 405
    assert client.delete("/.well-known/jwks.json").status_code == 405


def test_unknown_route_is_404(client):
    assert client.get("/nope").status_code == 404


def test_default_store_is_created():
    resp = create_app().test_client().get("/.well-known/jwks.json")
    assert len(resp.get_json()["keys"]) == 1
