"""RSA key generation and storage for the JWKS server."""

import base64
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# How long the valid key lasts, and how long ago the expired key "expired".
VALID_KEY_LIFETIME = 60 * 60  # 1 hour
EXPIRED_KEY_AGE = 60 * 60  # expired 1 hour ago


@dataclass
class KeyRecord:
    """One RSA key pair along with its kid and expiry time (unix seconds)."""

    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: int

    def is_expired(self, now=None):
        """Return True if this key's expiry time has passed."""
        if now is None:
            now = time.time()
        return self.expires_at <= now

    def private_pem(self):
        """Private key as PEM bytes, which is what PyJWT wants for signing."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def to_jwk(self):
        """Public half of the key as a JWK dictionary."""
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_int(numbers.n),
            "e": _b64url_int(numbers.e),
        }


def _b64url_int(value):
    """Base64url encode an integer with no padding, as JWK requires."""
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_key(expires_at):
    """Make a new 2048 bit RSA key with a random kid."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return KeyRecord(
        kid=str(uuid.uuid4()),
        private_key=private_key,
        expires_at=int(expires_at),
    )


class KeyStore:
    """Holds one valid key and one expired key for the life of the server."""

    def __init__(self):
        now = time.time()
        self.valid_key = generate_key(now + VALID_KEY_LIFETIME)
        self.expired_key = generate_key(now - EXPIRED_KEY_AGE)

    def all_keys(self):
        return [self.valid_key, self.expired_key]

    def unexpired_keys(self):
        """Only the keys that are still good, these are the ones in the JWKS."""
        return [k for k in self.all_keys() if not k.is_expired()]

    def jwks(self):
        """Build the JWKS document (only unexpired keys)."""
        return {"keys": [k.to_jwk() for k in self.unexpired_keys()]}
