"""Signing issued credentials."""

from joserfc import jws
from joserfc.jwk import ECKey
from openid4vci.crypto.signer import LocalJwsSigner

import pytest


@pytest.fixture
def issuer_key():
    return ECKey.generate_key("P-256", auto_kid=True)


async def test_a_signed_credential_verifies_against_the_public_key(issuer_key):
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    token = await signer.sign(payload='{"vct":"StudentCredential"}')

    verified = jws.deserialize_compact(token, issuer_key)
    assert verified.payload == b'{"vct":"StudentCredential"}'


async def test_the_algorithm_reaches_the_header(issuer_key):
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    token = await signer.sign(payload="{}")

    assert jws.deserialize_compact(token, issuer_key).protected["alg"] == "ES256"


async def test_the_key_identifier_is_published_so_a_verifier_can_find_the_key(
    issuer_key,
):
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    token = await signer.sign(payload="{}")

    assert jws.deserialize_compact(token, issuer_key).protected["kid"] == issuer_key.kid


async def test_the_caller_can_add_header_parameters(issuer_key):
    """SD-JWT VC needs its own typ, mdoc needs x5c; the signer stays neutral."""
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    token = await signer.sign(payload="{}", header={"typ": "dc+sd-jwt"})

    assert jws.deserialize_compact(token, issuer_key).protected["typ"] == "dc+sd-jwt"


async def test_the_caller_cannot_override_the_algorithm(issuer_key):
    """The signing key and the algorithm belong together."""
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    with pytest.raises(ValueError, match="alg"):
        await signer.sign(payload="{}", header={"alg": "ES384"})


def test_the_public_key_is_offered_without_its_private_half(issuer_key):
    signer = LocalJwsSigner(issuer_key, algorithm="ES256")

    published = signer.public_jwk()

    assert published["kty"] == "EC"
    assert "d" not in published


def test_a_symmetric_key_cannot_sign_credentials():
    """The signature already excludes this; the runtime check is for the rest.

    Keys are routinely loaded from configuration, where no type checker is
    watching, so the guard has to hold at runtime too. The call below violates
    the annotation on purpose.
    """
    from joserfc.jwk import OctKey

    with pytest.raises(ValueError):
        LocalJwsSigner(OctKey.import_key("a" * 32), algorithm="HS256")  # ty: ignore[invalid-argument-type]
