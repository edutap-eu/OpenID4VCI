"""The dc+sd-jwt credential format adapter.

Selective disclosure follows RFC 9901; the credential profile on top follows
draft-ietf-oauth-sd-jwt-vc-18. The embedding into a Credential Response follows
OpenID4VCI 1.0 Appendix A.3.
"""

from joserfc import jws
from joserfc.jwk import ECKey
from openid4vci.adapters.sd_jwt_vc import FORMAT_SD_JWT_VC
from openid4vci.adapters.sd_jwt_vc import SD_JWT_VC_TYP
from openid4vci.adapters.sd_jwt_vc import SdJwtVcAdapter
from openid4vci.crypto.signer import LocalJwsSigner

import base64
import hashlib
import json
import pytest


VCT = "https://credentials.example.edu/student"

CLAIMS = {
    "family_name": "Musterfrau",
    "given_name": "Erika",
    "matriculation_number": "12345678",
}


@pytest.fixture
def issuer_key():
    return ECKey.generate_key("P-256", auto_kid=True)


@pytest.fixture
def holder_key():
    return ECKey.generate_key("P-256").as_dict(private=False)


@pytest.fixture
def adapter(issuer_key):
    return SdJwtVcAdapter(
        vct=VCT,
        signer=LocalJwsSigner(issuer_key),
        issuer="https://issuer.example.edu",
    )


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def split(credential: str):
    """Return the issuer-signed JWT and the disclosures."""
    parts = credential.split("~")
    return parts[0], parts[1:-1], parts[-1]


def payload_of(issuer_jwt: str, key) -> dict:
    return json.loads(jws.deserialize_compact(issuer_jwt, key).payload)


def test_the_format_identifier_and_the_type_header():
    assert FORMAT_SD_JWT_VC == "dc+sd-jwt"
    assert SD_JWT_VC_TYP == "dc+sd-jwt"


async def test_the_serialization_ends_with_a_tilde(adapter, holder_key):
    """RFC 9901 Section 4: without a key binding JWT the last element is empty.

    The trailing tilde is how a verifier tells an SD-JWT from an SD-JWT+KB, so
    dropping it changes what the credential claims to be.
    """
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    assert credential.endswith("~")
    _, disclosures, key_binding = split(credential)
    assert len(disclosures) == 3
    assert key_binding == ""


async def test_the_type_header_is_set(adapter, holder_key, issuer_key):
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    issuer_jwt, _, _ = split(credential)
    header = jws.deserialize_compact(issuer_jwt, issuer_key).protected
    assert header["typ"] == SD_JWT_VC_TYP


async def test_each_disclosure_is_a_salted_triple(adapter, holder_key):
    """RFC 9901 Section 4.2.1: salt, claim name, claim value, in that order."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    _, disclosures, _ = split(credential)
    decoded = [json.loads(b64url_decode(d)) for d in disclosures]

    assert all(len(item) == 3 for item in decoded)
    assert {item[1] for item in decoded} == set(CLAIMS)
    assert {item[2] for item in decoded} == set(CLAIMS.values())


async def test_salts_are_unique_and_carry_enough_entropy(adapter, holder_key):
    """RFC 9901 Section 9.3: 128 bits, and unique per disclosed claim."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    _, disclosures, _ = split(credential)
    salts = [json.loads(b64url_decode(d))[0] for d in disclosures]

    assert len(set(salts)) == len(salts)
    assert all(len(b64url_decode(salt)) >= 16 for salt in salts)


async def test_the_digests_are_taken_over_the_encoded_disclosure(
    adapter, holder_key, issuer_key
):
    """RFC 9901 Section 4.2.3: over the base64url string, not over its bytes.

    This is the single easiest thing to get wrong in the whole format, and it
    fails silently: the credential looks right and no verifier accepts it.
    """
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    issuer_jwt, disclosures, _ = split(credential)
    payload = payload_of(issuer_jwt, issuer_key)

    expected = {
        base64.urlsafe_b64encode(hashlib.sha256(d.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
        for d in disclosures
    }
    assert set(payload["_sd"]) == expected


async def test_the_digest_order_does_not_follow_the_claim_order(
    adapter, holder_key, issuer_key
):
    """RFC 9901 Section 4.2.4.1: the original order must be hidden.

    Sorting is one of the ways the specification suggests, and it has the
    advantage of being checkable.
    """
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    payload = payload_of(split(credential)[0], issuer_key)
    assert payload["_sd"] == sorted(payload["_sd"])


async def test_the_hash_algorithm_is_named(adapter, holder_key, issuer_key):
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    assert payload_of(split(credential)[0], issuer_key)["_sd_alg"] == "sha-256"


async def test_disclosable_claims_do_not_appear_in_the_payload(
    adapter, holder_key, issuer_key
):
    """If a value were still in the payload, disclosure would decide nothing."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    payload = payload_of(split(credential)[0], issuer_key)
    for name in CLAIMS:
        assert name not in payload
    assert "Musterfrau" not in json.dumps(payload)


async def test_the_credential_type_is_always_visible(adapter, holder_key, issuer_key):
    """draft-18 Section 3.2.2: vct is REQUIRED, and a verifier reads it first."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    payload = payload_of(split(credential)[0], issuer_key)
    assert payload["vct"] == VCT
    assert payload["iss"] == "https://issuer.example.edu"


async def test_the_holder_key_is_carried_as_a_confirmation_claim(
    adapter, holder_key, issuer_key
):
    """draft-18 Section 3.2.2: cnf is REQUIRED when key binding is supported."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    payload = payload_of(split(credential)[0], issuer_key)
    assert payload["cnf"]["jwk"] == holder_key


async def test_claims_can_be_kept_permanently_visible(issuer_key, holder_key):
    adapter = SdJwtVcAdapter(
        vct=VCT,
        signer=LocalJwsSigner(issuer_key),
        always_visible=["given_name"],
    )

    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    payload = payload_of(split(credential)[0], issuer_key)
    assert payload["given_name"] == "Erika"
    assert len(split(credential)[1]) == 2


async def test_the_signature_verifies(adapter, holder_key, issuer_key):
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    assert jws.deserialize_compact(split(credential)[0], issuer_key)


async def test_a_claim_name_the_format_reserves_is_refused(adapter, holder_key):
    """RFC 9901 Section 4.2.1: a disclosure must not be named _sd or ..."""
    with pytest.raises(ValueError, match="_sd"):
        await adapter.issue({"_sd": "anything"}, holder_key=holder_key)


def test_the_metadata_fragment_declares_the_credential_type(adapter):
    fragment = adapter.metadata_fragment()

    assert fragment["format"] == FORMAT_SD_JWT_VC
    assert fragment["vct"] == VCT


# --- Test vectors from RFC 9901 --------------------------------------------
#
# These two strings are printed in Section 4.2.3 of the RFC. They were produced
# by the reference implementation the specification uses to generate its
# examples (openwallet-foundation-labs/sd-jwt-python), so matching them means
# matching that implementation -- without taking a dependency whose last
# release predates the RFC by well over a year.

RFC_DISCLOSURE = (
    "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
)
RFC_DIGEST = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"


def test_our_digest_matches_the_rfc_example():
    """The one rule that fails silently, pinned to the normative example."""
    from openid4vci.adapters.sd_jwt_vc import disclosure_digest

    assert disclosure_digest(RFC_DISCLOSURE) == RFC_DIGEST


def test_our_disclosure_encoding_matches_the_rfc_example(monkeypatch):
    """Same salt in, same disclosure out -- byte for byte.

    This checks the part the digest test cannot: how the JSON array is
    serialized before encoding. Separators and non-ASCII handling both change
    the bytes, and therefore the digest, without changing the meaning.
    """
    from openid4vci.adapters import sd_jwt_vc

    salt, name, value = json.loads(b64url_decode(RFC_DISCLOSURE))
    monkeypatch.setattr(
        sd_jwt_vc.secrets, "token_bytes", lambda _n: b64url_decode(salt)
    )

    assert sd_jwt_vc.make_disclosure(name, value) == RFC_DISCLOSURE
    assert value == "Möbius", "the example carries a non-ASCII value on purpose"
