"""Key attestations, OpenID4VCI 1.0 Appendix D."""

from joserfc import jwt
from joserfc.jwk import ECKey
from openid4vci.crypto.attestation import AttackPotentialResistance
from openid4vci.crypto.attestation import KEY_ATTESTATION_TYP
from openid4vci.crypto.attestation import validate_key_attestation
from openid4vci.crypto.proofs import PROOF_REGISTRY
from openid4vci.crypto.proofs import PROOF_TYPE_ATTESTATION
from openid4vci.crypto.proofs import validate_attestation_proof
from openid4vci.crypto.proofs import validate_jwt_proof
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode

import pytest


ISSUER = "https://issuer.example.edu"
NONCE = "LarRGSbmUPYtRYO6BQ4yn8"
NOW = 1_766_000_000


@pytest.fixture
def provider_key():
    """The Wallet Provider's signing key."""
    return ECKey.generate_key("P-256")


@pytest.fixture
def device_key():
    """A key in the Wallet's key storage component."""
    return ECKey.generate_key("P-256")


def make_attestation(provider_key, device_key, *, claims=None, header=None):
    full_header = {"typ": KEY_ATTESTATION_TYP, "alg": "ES256", "kid": "provider-1"}
    full_header.update(header or {})
    full_claims = {
        "iat": NOW - 60,
        "exp": NOW + 3600,
        "attested_keys": [device_key.as_dict(private=False)],
        "key_storage": ["iso_18045_moderate"],
        "user_authentication": ["iso_18045_moderate"],
        "nonce": NONCE,
    }
    full_claims.update(claims or {})
    full_claims = {k: v for k, v in full_claims.items() if v is not None}
    return jwt.encode(full_header, full_claims, provider_key)


def resolver(provider_key):
    return lambda header: provider_key


def test_the_attack_potential_values_are_the_four_the_specification_defines():
    assert {value.value for value in AttackPotentialResistance} == {
        "iso_18045_high",
        "iso_18045_moderate",
        "iso_18045_enhanced-basic",
        "iso_18045_basic",
    }


def test_a_valid_attestation_yields_the_attested_keys(provider_key, device_key):
    attestation = validate_key_attestation(
        make_attestation(provider_key, device_key),
        resolve_key=resolver(provider_key),
        c_nonce=NONCE,
        now=NOW,
    )

    assert attestation.attested_keys == [device_key.as_dict(private=False)]
    assert attestation.key_storage == ["iso_18045_moderate"]


def test_the_type_header_must_be_the_prescribed_one(provider_key, device_key):
    with pytest.raises(CredentialRequestError):
        validate_key_attestation(
            make_attestation(provider_key, device_key, header={"typ": "JWT"}),
            resolve_key=resolver(provider_key),
            now=NOW,
        )


def test_an_attestation_must_attest_something(provider_key, device_key):
    with pytest.raises(CredentialRequestError, match="attested_keys"):
        validate_key_attestation(
            make_attestation(provider_key, device_key, claims={"attested_keys": []}),
            resolve_key=resolver(provider_key),
            now=NOW,
        )


def test_an_expired_attestation_is_refused(provider_key, device_key):
    with pytest.raises(CredentialRequestError, match="expired"):
        validate_key_attestation(
            make_attestation(provider_key, device_key, claims={"exp": NOW - 1}),
            resolve_key=resolver(provider_key),
            now=NOW,
        )


def test_a_stale_nonce_is_refused(provider_key, device_key):
    """Appendix F.1: the nonce claim must be the c_nonce we provided."""
    with pytest.raises(CredentialRequestError) as caught:
        validate_key_attestation(
            make_attestation(provider_key, device_key, claims={"nonce": "stale"}),
            resolve_key=resolver(provider_key),
            c_nonce=NONCE,
            now=NOW,
        )

    assert caught.value.code is CredentialErrorCode.INVALID_NONCE


def test_the_issuer_can_demand_a_level_of_key_storage(provider_key, device_key):
    with pytest.raises(CredentialRequestError, match="key_storage"):
        validate_key_attestation(
            make_attestation(
                provider_key, device_key, claims={"key_storage": ["iso_18045_basic"]}
            ),
            resolve_key=resolver(provider_key),
            c_nonce=NONCE,
            required_key_storage=["iso_18045_high", "iso_18045_moderate"],
            now=NOW,
        )


def test_a_demanded_level_that_is_met_passes(provider_key, device_key):
    attestation = validate_key_attestation(
        make_attestation(provider_key, device_key),
        resolve_key=resolver(provider_key),
        c_nonce=NONCE,
        required_key_storage=["iso_18045_high", "iso_18045_moderate"],
        required_user_authentication=["iso_18045_moderate"],
        now=NOW,
    )

    assert attestation.user_authentication == ["iso_18045_moderate"]


def test_a_key_proof_may_carry_its_attestation_in_the_header(provider_key, device_key):
    """Appendix F.1: the proof MUST be signed by a key inside the attestation."""
    attestation = make_attestation(provider_key, device_key)
    proof = jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": device_key.as_dict(private=False),
            "key_attestation": attestation,
        },
        {"aud": ISSUER, "iat": NOW - 30, "nonce": NONCE},
        device_key,
        registry=PROOF_REGISTRY,
    )

    result = validate_jwt_proof(
        proof,
        credential_issuer=ISSUER,
        c_nonce=NONCE,
        attestation_resolve_key=resolver(provider_key),
        now=NOW,
    )

    assert result.attestation is not None
    assert result.attestation.key_storage == ["iso_18045_moderate"]


def test_a_proof_signed_by_an_unattested_key_is_refused(provider_key, device_key):
    """The attestation says which keys are protected; another key is not covered."""
    other_key = ECKey.generate_key("P-256")
    attestation = make_attestation(provider_key, device_key)
    proof = jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": other_key.as_dict(private=False),
            "key_attestation": attestation,
        },
        {"aud": ISSUER, "iat": NOW - 30, "nonce": NONCE},
        other_key,
        registry=PROOF_REGISTRY,
    )

    with pytest.raises(CredentialRequestError, match="does not attest"):
        validate_jwt_proof(
            proof,
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            attestation_resolve_key=resolver(provider_key),
            now=NOW,
        )


def test_an_attestation_used_with_a_key_proof_must_expire(provider_key, device_key):
    """Appendix D: exp MUST be present if the attestation is used with the jwt proof."""
    attestation = make_attestation(provider_key, device_key, claims={"exp": None})
    proof = jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": device_key.as_dict(private=False),
            "key_attestation": attestation,
        },
        {"aud": ISSUER, "iat": NOW - 30, "nonce": NONCE},
        device_key,
        registry=PROOF_REGISTRY,
    )

    with pytest.raises(CredentialRequestError, match="exp"):
        validate_jwt_proof(
            proof,
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            attestation_resolve_key=resolver(provider_key),
            now=NOW,
        )


def test_the_attestation_proof_type_carries_exactly_one_jwt(provider_key, device_key):
    """Appendix F: an array containing exactly one JWT."""
    assert PROOF_TYPE_ATTESTATION == "attestation"
    attestation = make_attestation(provider_key, device_key)

    result = validate_attestation_proof(
        [attestation],
        resolve_key=resolver(provider_key),
        c_nonce=NONCE,
        now=NOW,
    )

    assert result.attested_keys == [device_key.as_dict(private=False)]

    with pytest.raises(CredentialRequestError, match="exactly one"):
        validate_attestation_proof(
            [attestation, attestation],
            resolve_key=resolver(provider_key),
            c_nonce=NONCE,
            now=NOW,
        )
