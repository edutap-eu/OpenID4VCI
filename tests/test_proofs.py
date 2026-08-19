"""Key proof validation, OpenID4VCI 1.0 Appendix F.1 (`jwt` proof type)."""

from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from openid4vci.crypto.proofs import PROOF_TYPE_JWT
from openid4vci.crypto.proofs import validate_jwt_proof
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode

import pytest


ISSUER = "https://issuer.example.edu"
NONCE = "LarRGSbmUPYtRYO6BQ4yn8"


@pytest.fixture
def holder_key():
    return ECKey.generate_key("P-256")


def make_proof(key, *, header=None, claims=None, signing_key=None):
    """Build a key proof JWT, defaulting to a valid one."""
    full_header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": key.as_dict(private=False),
    }
    full_header.update(header or {})
    full_claims = {"aud": ISSUER, "iat": 1735689600, "nonce": NONCE}
    full_claims.update(claims or {})
    full_claims = {k: v for k, v in full_claims.items() if v is not None}
    return jwt.encode(full_header, full_claims, signing_key or key)


def test_the_proof_type_identifier():
    assert PROOF_TYPE_JWT == "jwt"


def test_a_valid_proof_returns_the_key_the_credential_binds_to(holder_key):
    result = validate_jwt_proof(
        make_proof(holder_key),
        credential_issuer=ISSUER,
        c_nonce=NONCE,
    )

    assert result.bound_key == holder_key.as_dict(private=False)
    assert result.claims["aud"] == ISSUER


def test_the_typ_header_must_be_the_one_the_specification_prescribes(holder_key):
    """Appendix F.1: explicit typing, as recommended by RFC 8725 Section 3.11."""
    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            make_proof(holder_key, header={"typ": "JWT"}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )

    assert caught.value.code is CredentialErrorCode.INVALID_PROOF


def test_an_unsigned_proof_is_refused(holder_key):
    """alg MUST NOT be none. An unsigned proof proves nothing."""
    unsigned = ".".join(
        [
            "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6Im5vbmUifQ",
            "eyJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmVkdSIsImlhdCI6MX0",
            "",
        ]
    )

    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(unsigned, credential_issuer=ISSUER, c_nonce=NONCE)


def test_a_symmetric_algorithm_is_refused():
    """alg MUST NOT identify a MAC: a shared secret proves possession to nobody.

    The resolver is supplied deliberately. Without it the proof would be
    refused for lacking a resolvable key, and the test would pass without ever
    reaching the rule it claims to check -- which is how the missing MAC check
    stayed invisible in the first place.
    """
    secret = OctKey.import_key("a" * 32)
    proof = jwt.encode(
        {"typ": "openid4vci-proof+jwt", "alg": "HS256", "kid": "shared"},
        {"aud": ISSUER, "iat": 1735689600, "nonce": NONCE},
        secret,
    )

    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            proof,
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            resolve_key=lambda header: secret,
        )

    assert "MAC algorithm" in str(caught.value)


def test_a_symmetric_key_in_the_jwk_header_is_refused():
    secret = OctKey.import_key("a" * 32)
    proof = jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "HS256",
            "jwk": secret.as_dict(private=False),
        },
        {"aud": ISSUER, "iat": 1735689600, "nonce": NONCE},
        secret,
    )

    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(proof, credential_issuer=ISSUER, c_nonce=NONCE)


def test_the_audience_must_be_this_issuer(holder_key):
    """A proof made for another issuer must not be replayable here."""
    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            make_proof(holder_key, claims={"aud": "https://other.example.edu"}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )

    assert caught.value.code is CredentialErrorCode.INVALID_PROOF


def test_the_audience_is_required(holder_key):
    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(
            make_proof(holder_key, claims={"aud": None}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )


def test_the_issued_at_is_required(holder_key):
    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(
            make_proof(holder_key, claims={"iat": None}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )


def test_a_missing_nonce_is_an_invalid_proof(holder_key):
    """Section 8.4: invalid_proof covers a key proof without a c_nonce."""
    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            make_proof(holder_key, claims={"nonce": None}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )

    assert caught.value.code is CredentialErrorCode.INVALID_PROOF


def test_a_wrong_nonce_is_an_invalid_nonce(holder_key):
    """Section 8.4: a wrong c_nonce is its own error, so the Wallet can retry.

    The distinction matters: invalid_nonce tells the Wallet to fetch a fresh
    nonce and try again, while invalid_proof does not.
    """
    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            make_proof(holder_key, claims={"nonce": "stale-nonce"}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )

    assert caught.value.code is CredentialErrorCode.INVALID_NONCE


def test_no_nonce_is_expected_when_the_issuer_has_no_nonce_endpoint(holder_key):
    result = validate_jwt_proof(
        make_proof(holder_key, claims={"nonce": None}),
        credential_issuer=ISSUER,
        c_nonce=None,
    )

    assert result.bound_key == holder_key.as_dict(private=False)


def test_the_key_headers_are_mutually_exclusive(holder_key):
    """Appendix F.1: jwk MUST NOT be present if kid or x5c is."""
    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(
            make_proof(holder_key, header={"kid": "did:example:123#key-1"}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
        )

    assert "mutually exclusive" in str(caught.value)


def test_some_key_must_be_identified():
    key = ECKey.generate_key("P-256")
    proof = jwt.encode(
        {"typ": "openid4vci-proof+jwt", "alg": "ES256"},
        {"aud": ISSUER, "iat": 1735689600, "nonce": NONCE},
        key,
    )

    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(proof, credential_issuer=ISSUER, c_nonce=NONCE)


def test_a_signature_by_another_key_is_refused(holder_key):
    """The header may claim any key; the signature decides."""
    attacker_key = ECKey.generate_key("P-256")
    proof = make_proof(holder_key, signing_key=attacker_key)

    with pytest.raises(CredentialRequestError) as caught:
        validate_jwt_proof(proof, credential_issuer=ISSUER, c_nonce=NONCE)

    assert caught.value.code is CredentialErrorCode.INVALID_PROOF


def test_the_algorithm_must_be_one_we_advertised(holder_key):
    """Appendix F.1: alg MUST match proof_signing_alg_values_supported."""
    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(
            make_proof(holder_key),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            supported_algorithms=["ES384"],
        )


def test_the_issuer_claim_must_be_the_client_that_asks(holder_key):
    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(
            make_proof(holder_key, claims={"iss": "https://other.wallet.example"}),
            credential_issuer=ISSUER,
            c_nonce=NONCE,
            client_id="https://wallet.example.edu",
        )


def test_a_kid_proof_needs_a_resolver(holder_key):
    """We cannot resolve a DID URL or a certificate chain ourselves."""
    proof = jwt.encode(
        {"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "did:example:123#key-1"},
        {"aud": ISSUER, "iat": 1735689600, "nonce": NONCE},
        holder_key,
    )

    with pytest.raises(CredentialRequestError):
        validate_jwt_proof(proof, credential_issuer=ISSUER, c_nonce=NONCE)

    result = validate_jwt_proof(
        proof,
        credential_issuer=ISSUER,
        c_nonce=NONCE,
        resolve_key=lambda header: holder_key,
    )
    assert result.claims["aud"] == ISSUER
