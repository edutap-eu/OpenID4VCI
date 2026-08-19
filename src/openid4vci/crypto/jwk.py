"""JSON Web Key handling (RFC 7517).

Our own issuer keys, the keys a Wallet presents in a proof, and the key set we
publish for signed issuer metadata.
"""

from joserfc.jwk import ECKey
from joserfc.jwk import import_key
from joserfc.jwk import KeySet
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
from typing import Any


#: Key types that carry a public and a private half.
ASYMMETRIC_KEY_TYPES = ("EC", "RSA", "OKP")


def is_asymmetric(key_data: dict[str, Any]) -> bool:
    """Return whether the JWK describes an asymmetric key.

    A key proof signed with a symmetric key proves possession to nobody: both
    sides of a MAC hold the same secret, so the signature says only that
    someone who knows the secret produced it.
    """
    return key_data.get("kty") in ASYMMETRIC_KEY_TYPES


def public_key_from_jwk(key_data: dict[str, Any]) -> ECKey | RSAKey | OKPKey:
    """Import a public key from its JWK representation.

    :raises ValueError: if the JWK is not an asymmetric public key.
    """
    if not is_asymmetric(key_data):
        raise ValueError(f"Expected an asymmetric key, got kty={key_data.get('kty')!r}")
    key = import_key(key_data)
    if isinstance(key, KeySet):
        raise ValueError("Expected a single key, got a key set")
    return key  # type: ignore[return-value]
