"""JOSE header sizes on key proofs and key attestations.

A strict JOSE library caps the header it will parse, and rightly so: the
header is read before anything is verified, on input from a stranger. The cap
this protocol needs is nonetheless much larger than the usual one, because it
puts a whole signed JWT inside a header -- and an attestation whose signer
identifies itself by a certificate chain carries that chain as well.

These tests exist because the first fix guessed a number instead of measuring
one, and the guess was too small for a three-certificate chain.
"""

from joserfc import jwt
from joserfc.jwk import ECKey
from openid4vci.crypto.attestation import validate_key_attestation
from openid4vci.crypto.proofs import validate_jwt_proof
from openid4vci.crypto.registry import DEFAULT_JOSE_REGISTRY
from openid4vci.crypto.registry import DEFAULT_MAX_HEADER_LENGTH
from openid4vci.crypto.registry import jose_registry
from openid4vci.crypto.registry import OPENID4VCI_HEADERS
from openid4vci.crypto.registry import PROOF_HEADER_MEASUREMENTS
from openid4vci.exceptions import CredentialRequestError

import base64
import pytest


ISSUER = "https://issuer.example.edu"
NONCE = "LarRGSbmUPYtRYO6BQ4yn8"
NOW = 1_766_000_000


def certificate_chain(count):
    """Stand-ins the size of a real DER certificate, base64 encoded."""
    return [base64.b64encode(b"\x30" * 1100).decode("ascii") for _ in range(count)]


@pytest.fixture
def provider_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def device_key():
    return ECKey.generate_key("P-256")


def attestation_for(provider_key, device_key, *, certificates=0, keys=1):
    header = {"typ": "key-attestation+jwt", "alg": "ES256"}
    if certificates:
        header["x5c"] = certificate_chain(certificates)
    else:
        header["kid"] = "provider-1"
    claims = {
        "iat": NOW - 60,
        "exp": NOW + 3600,
        "attested_keys": [device_key.as_dict(private=False)]
        + [ECKey.generate_key("P-256").as_dict(private=False) for _ in range(keys - 1)],
        "key_storage": ["iso_18045_moderate"],
        "nonce": NONCE,
    }
    # The registry is needed to *build* one of these, not only to read it:
    # the size limit applies at encoding too. Anything producing key proofs or
    # attestations needs the same registry, which is why it is public.
    return jwt.encode(header, claims, provider_key, registry=DEFAULT_JOSE_REGISTRY)


def proof_with(attestation, device_key, registry):
    return jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": device_key.as_dict(private=False),
            "key_attestation": attestation,
        },
        {"aud": ISSUER, "iat": NOW - 30, "nonce": NONCE},
        device_key,
        registry=registry,
    )


def test_the_default_is_larger_than_every_measured_case():
    """The number is derived from the table, not chosen for looking round."""
    assert DEFAULT_MAX_HEADER_LENGTH > max(PROOF_HEADER_MEASUREMENTS.values())


def test_an_attestation_with_a_certificate_chain_is_accepted(provider_key, device_key):
    """The case the first fix missed: roughly six kilobytes of header."""
    attestation = attestation_for(provider_key, device_key, certificates=3)
    assert len(attestation.split(".")[0]) > 4000

    result = validate_key_attestation(
        attestation, resolve_key=lambda header: provider_key, c_nonce=NONCE, now=NOW
    )

    assert result.attested_keys[0] == device_key.as_dict(private=False)


def test_a_proof_carrying_such_an_attestation_is_accepted(provider_key, device_key):
    """And the proof around it, which is larger still."""
    registry = jose_registry()
    attestation = attestation_for(provider_key, device_key, certificates=3, keys=10)
    proof = proof_with(attestation, device_key, registry)
    assert len(proof.split(".")[0]) > 8192, "the old limit would have refused this"

    result = validate_jwt_proof(
        proof,
        credential_issuer=ISSUER,
        c_nonce=NONCE,
        attestation_resolve_key=lambda header: provider_key,
        now=NOW,
    )

    assert result.attestation is not None


def test_an_oversized_proof_says_so_rather_than_blaming_the_signature(
    provider_key, device_key
):
    """The first version reported this as a signature failure.

    That sends whoever debugs it to the keys and the certificates, which are
    fine, instead of to a parser limit, which is not.
    """
    generous = jose_registry(max_header_length=64_000)
    attestation = attestation_for(provider_key, device_key, certificates=3, keys=10)
    proof = proof_with(attestation, device_key, generous)

    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            proof,
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            attestation_resolve_key=lambda header: provider_key,
            now=NOW,
            registry=jose_registry(max_header_length=1024),
        )

    message = str(caught.value)
    assert "larger than this issuer accepts" in message
    assert "signature does not verify" not in message


def test_an_oversized_attestation_says_so_too(provider_key, device_key):
    attestation = attestation_for(provider_key, device_key, certificates=3)

    with pytest.raises(CredentialRequestError) as caught:
        validate_key_attestation(
            attestation,
            resolve_key=lambda header: provider_key,
            c_nonce=NONCE,
            now=NOW,
            registry=jose_registry(max_header_length=1024),
        )

    assert "larger than this issuer accepts" in str(caught.value)


def test_a_deployment_can_tighten_the_limit(provider_key, device_key):
    """An issuer expecting no attestations has no reason to parse kilobytes."""
    registry = jose_registry(max_header_length=512)

    assert registry.max_header_length == 512
    assert set(registry.header_registry) >= set(OPENID4VCI_HEADERS)

    plain = jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": device_key.as_dict(private=False),
        },
        {"aud": ISSUER, "iat": NOW - 30, "nonce": NONCE},
        device_key,
    )

    result = validate_jwt_proof(
        plain,
        credential_issuer=ISSUER,
        c_nonce=NONCE,
        now=NOW,
        registry=registry,
    )
    assert result.bound_key == device_key.as_dict(private=False)
