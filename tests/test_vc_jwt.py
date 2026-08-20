"""The jwt_vc_json credential format adapter.

Structures follow the W3C Verifiable Credentials Data Model; the embedding
into a Credential Response follows OpenID4VCI 1.0 Appendix A.1.1.
"""

from joserfc import jws
from joserfc.jwk import ECKey
from openid4vci.adapters.vc_jwt import CONTEXT_VC_V1
from openid4vci.adapters.vc_jwt import did_jwk
from openid4vci.adapters.vc_jwt import FORMAT_JWT_VC_JSON
from openid4vci.adapters.vc_jwt import JwtVcAdapter
from openid4vci.crypto.signer import LocalJwsSigner

import base64
import json
import pytest


ISSUER = "https://issuer.example.edu"
CLAIMS = {
    "given_name": "Erika",
    "achievement": {
        "type": "Achievement",
        "name": "Introduction to Cryptography",
        "creditsAvailable": 5,
    },
}


@pytest.fixture
def issuer_key():
    return ECKey.generate_key("P-256", auto_kid=True)


@pytest.fixture
def holder_key():
    return ECKey.generate_key("P-256").as_dict(private=False)


@pytest.fixture
def adapter(issuer_key):
    return JwtVcAdapter(
        types=["MicroCredential"],
        signer=LocalJwsSigner(issuer_key),
        issuer=ISSUER,
    )


def payload_of(credential: str, key) -> dict:
    return json.loads(jws.deserialize_compact(credential, key).payload)


def test_the_format_identifier():
    assert FORMAT_JWT_VC_JSON == "jwt_vc_json"


async def test_the_credential_is_a_bare_jwt(adapter, holder_key):
    """Appendix A.1.1: already base64url, and MUST NOT be re-encoded."""
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    assert credential.count(".") == 2
    assert "~" not in credential


async def test_the_registered_claims_mirror_the_credential(
    adapter, holder_key, issuer_key
):
    """The JWT encoding duplicates parts of the credential into JWT claims.

    A verifier may read either, so the two must agree; disagreeing copies are
    how a credential ends up saying two different things.
    """
    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["iss"] == payload["vc"]["issuer"] == ISSUER
    assert payload["jti"] == payload["vc"]["id"]
    assert payload["sub"] == payload["vc"]["credentialSubject"]["id"]


async def test_the_issuance_date_matches_the_not_before_claim(
    adapter, holder_key, issuer_key
):
    from datetime import datetime
    from datetime import timezone

    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    issued = datetime.fromisoformat(
        payload["vc"]["issuanceDate"].replace("Z", "+00:00")
    )
    assert issued == datetime.fromtimestamp(payload["nbf"], tz=timezone.utc)


async def test_the_base_type_and_context_are_always_present(
    adapter, holder_key, issuer_key
):
    """A credential that does not say it is one cannot be processed as one."""
    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["vc"]["type"] == ["VerifiableCredential", "MicroCredential"]
    assert payload["vc"]["@context"][0] == CONTEXT_VC_V1


async def test_the_base_type_is_not_repeated(issuer_key, holder_key):
    adapter = JwtVcAdapter(
        types=["VerifiableCredential", "MicroCredential"],
        signer=LocalJwsSigner(issuer_key),
        issuer=ISSUER,
    )

    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["vc"]["type"] == ["VerifiableCredential", "MicroCredential"]


async def test_the_claims_become_the_credential_subject(
    adapter, holder_key, issuer_key
):
    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    subject = payload["vc"]["credentialSubject"]
    assert subject["given_name"] == "Erika"
    assert subject["achievement"]["name"] == "Introduction to Cryptography"


async def test_the_subject_is_the_holder_key(adapter, holder_key, issuer_key):
    """Binding without a DID method of our own: the key is the identifier."""
    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["sub"] == did_jwk(holder_key)
    assert payload["sub"].startswith("did:jwk:")

    encoded = payload["sub"].removeprefix("did:jwk:")
    encoded += "=" * (-len(encoded) % 4)
    assert json.loads(base64.urlsafe_b64decode(encoded)) == holder_key


async def test_a_caller_can_name_the_subject_instead(adapter, holder_key, issuer_key):
    credential = await adapter.issue(
        CLAIMS, holder_key=holder_key, subject_id="did:example:erika"
    )

    payload = payload_of(credential, issuer_key)
    assert payload["sub"] == "did:example:erika"


async def test_an_expiry_is_written_to_both_places(issuer_key, holder_key):
    from datetime import timedelta

    adapter = JwtVcAdapter(
        types=["MicroCredential"],
        signer=LocalJwsSigner(issuer_key),
        issuer=ISSUER,
        validity=timedelta(days=30),
    )

    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["exp"] > payload["nbf"]
    assert payload["vc"]["expirationDate"].endswith("Z")


async def test_without_a_validity_there_is_no_expiry(adapter, holder_key, issuer_key):
    """A micro-credential that records an achievement does not go stale."""
    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert "exp" not in payload
    assert "expirationDate" not in payload["vc"]


async def test_an_additional_context_can_be_carried(issuer_key, holder_key):
    """Open Badges 3.0 and its kin are VCDM credentials with their own context."""
    open_badges = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
    adapter = JwtVcAdapter(
        types=["OpenBadgeCredential"],
        signer=LocalJwsSigner(issuer_key),
        issuer=ISSUER,
        contexts=[open_badges],
    )

    payload = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert payload["vc"]["@context"] == [CONTEXT_VC_V1, open_badges]
    assert payload["vc"]["type"] == ["VerifiableCredential", "OpenBadgeCredential"]


async def test_identifiers_differ_between_credentials(adapter, holder_key, issuer_key):
    """Two credentials must not share an identifier, or revoking one hits both."""
    first = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)
    second = payload_of(await adapter.issue(CLAIMS, holder_key=holder_key), issuer_key)

    assert first["jti"] != second["jti"]


async def test_the_signature_verifies(adapter, holder_key, issuer_key):
    credential = await adapter.issue(CLAIMS, holder_key=holder_key)

    assert jws.deserialize_compact(credential, issuer_key)


def test_the_metadata_fragment_declares_the_types(adapter):
    """Appendix A.1.1: credential_definition with a type array is REQUIRED."""
    fragment = adapter.metadata_fragment()

    assert fragment["format"] == FORMAT_JWT_VC_JSON
    assert fragment["credential_definition"]["type"] == [
        "VerifiableCredential",
        "MicroCredential",
    ]
