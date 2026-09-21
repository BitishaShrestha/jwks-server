"""Flask app for the JWKS server.

Endpoints:
    GET  /.well-known/jwks.json  -> public keys that haven't expired
    POST /auth                   -> a signed JWT (add ?expired for an expired one)
"""

import time

import jwt
from flask import Flask, jsonify, request

from keys import KeyStore

TOKEN_LIFETIME = 5 * 60  # normal tokens last 5 minutes


def create_app(key_store=None):
    """Build the Flask app. A key store can be passed in for testing."""
    app = Flask(__name__)
    store = key_store or KeyStore()

    @app.route("/.well-known/jwks.json", methods=["GET"])
    def jwks():
        return jsonify(store.jwks())

    @app.route("/auth", methods=["POST"])
    def auth():
        # The mere presence of ?expired (even with no value) counts.
        if "expired" in request.args:
            key = store.expired_key
            exp = key.expires_at  # already in the past
        else:
            key = store.valid_key
            exp = int(time.time()) + TOKEN_LIFETIME

        payload = {
            "sub": "fakeuser",
            "iat": int(time.time()),
            "exp": exp,
        }
        # kid goes in the header so clients know which key to verify with.
        token = jwt.encode(
            payload,
            key.private_pem(),
            algorithm="RS256",
            headers={"kid": key.kid},
        )
        # Send the raw JWT as the body.
        return token, 200, {"Content-Type": "text/plain; charset=utf-8"}

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
