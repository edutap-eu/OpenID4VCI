"""The mso_mdoc credential format adapter.

Structures follow ISO/IEC 18013-5:2021 sections 8.3.2.1.2.2 and 9.1.2; the
embedding into a Credential Response follows OpenID4VCI 1.0 Appendix A.2.
"""

import pytest


# The adapter imports cbor2 and pycose at module level, so the guard has to run
# before it is imported -- hence the placement, and the noqa below.
cbor2 = pytest.importorskip("cbor2", reason="needs the mdoc extra")
pytest.importorskip("pycose", reason="needs the mdoc extra")

from datetime import datetime  # noqa: E402
from datetime import timezone  # noqa: E402
from joserfc.jwk import ECKey  # noqa: E402
from openid4vci.adapters.mdoc import FORMAT_MSO_MDOC  # noqa: E402
from openid4vci.adapters.mdoc import LocalCoseSigner  # noqa: E402
from openid4vci.adapters.mdoc import MdocAdapter  # noqa: E402

import base64  # noqa: E402
import hashlib  # noqa: E402


DOCTYPE = "org.iso.18013.5.1.mDL"
NAMESPACE = "org.iso.18013.5.1"

CLAIMS = {
    NAMESPACE: {
        "family_name": "Musterfrau",
        "given_name": "Erika",
        "birth_date": "1990-01-02",
    }
}


@pytest.fixture
def signer():
    return LocalCoseSigner.generate(certificate_chain=[b"a-fake-der-certificate"])


@pytest.fixture
def holder_key():
    return ECKey.generate_key("P-256").as_dict(private=False)


@pytest.fixture
def adapter(signer):
    return MdocAdapter(doctype=DOCTYPE, signer=signer)


def decode_credential(credential: str) -> dict:
    padding = "=" * (-len(credential) % 4)
    return cbor2.loads(base64.urlsafe_b64decode(credential + padding))


async def issue(adapter, holder_key, claims=None):
    credential = await adapter.issue(claims or CLAIMS, holder_key=holder_key)
    return decode_credential(credential)


def mso_of(issuer_signed: dict) -> dict:
    """Unwrap the Mobile Security Object from the IssuerAuth structure."""
    payload = issuer_signed["issuerAuth"][2]
    return cbor2.loads(cbor2.loads(payload).value)


def test_the_format_identifier():
    assert FORMAT_MSO_MDOC == "mso_mdoc"


async def test_the_credential_is_base64url_of_cbor(adapter, holder_key):
    issuer_signed = await issue(adapter, holder_key)

    assert set(issuer_signed) == {"nameSpaces", "issuerAuth"}


async def test_every_data_element_is_an_embedded_cbor_item(adapter, holder_key):
    """Section 8.3.2.1.2.2: the items are embedded CBOR, tag 24."""
    issuer_signed = await issue(adapter, holder_key)

    items = issuer_signed["nameSpaces"][NAMESPACE]
    assert len(items) == 3
    for item in items:
        assert isinstance(item, cbor2.CBORTag)
        assert item.tag == 24


async def test_each_item_carries_an_unpredictable_salt(adapter, holder_key):
    """Section 9.1.2.5: at least 16 bytes, and different for each item.

    Without it the digest of a short, guessable value would reveal that value.
    """
    issuer_signed = await issue(adapter, holder_key)

    salts = []
    for item in issuer_signed["nameSpaces"][NAMESPACE]:
        decoded = cbor2.loads(item.value)
        assert len(decoded["random"]) >= 16
        salts.append(decoded["random"])

    assert len(set(salts)) == len(salts)


async def test_digest_identifiers_are_unique_and_in_range(adapter, holder_key):
    """Section 9.1.2.4: unique within a namespace, smaller than 2^31."""
    issuer_signed = await issue(adapter, holder_key)

    ids = [
        cbor2.loads(i.value)["digestID"] for i in issuer_signed["nameSpaces"][NAMESPACE]
    ]
    assert len(set(ids)) == len(ids)
    assert all(0 <= i < 2**31 for i in ids)


async def test_the_digests_in_the_security_object_match_the_items(adapter, holder_key):
    """This is the whole point of issuer data authentication."""
    issuer_signed = await issue(adapter, holder_key)
    mso = mso_of(issuer_signed)

    assert mso["digestAlgorithm"] == "SHA-256"
    digests = mso["valueDigests"][NAMESPACE]

    for item in issuer_signed["nameSpaces"][NAMESPACE]:
        digest_id = cbor2.loads(item.value)["digestID"]
        assert digests[digest_id] == hashlib.sha256(cbor2.dumps(item)).digest()


async def test_the_security_object_names_the_document_type(adapter, holder_key):
    mso = mso_of(await issue(adapter, holder_key))

    assert mso["version"] == "1.0"
    assert mso["docType"] == DOCTYPE


async def test_the_holder_key_is_carried_as_a_cose_key(adapter, holder_key):
    """Section 9.1.2.4: deviceKeyInfo carries the mdoc authentication key."""
    mso = mso_of(await issue(adapter, holder_key))

    device_key = mso["deviceKeyInfo"]["deviceKey"]
    assert device_key[1] == 2  # kty: EC2
    assert device_key[-2] == base64.urlsafe_b64decode(holder_key["x"] + "==")


async def test_validity_runs_from_signing(adapter, holder_key):
    mso = mso_of(await issue(adapter, holder_key))

    validity = mso["validityInfo"]
    # cbor2 turns the standard date/time tag back into a datetime, so the
    # encoding is checked through what it decodes to.
    assert validity["signed"].tzinfo is timezone.utc
    assert validity["signed"].microsecond == 0, "fractions of seconds are excluded"
    assert validity["validFrom"] >= validity["signed"]
    assert validity["validUntil"] > validity["validFrom"]


async def test_the_timestamps_are_written_as_utc_without_fractions(adapter, holder_key):
    """Section 9.1.2.4: no fractional seconds, UTC offset of zero."""
    from openid4vci.adapters.mdoc import _timestamp

    written = _timestamp(datetime(2026, 8, 19, 14, 30, 5, 123456, tzinfo=timezone.utc))

    assert written.tag == 0
    assert written.value == "2026-08-19T14:30:05Z"


async def test_the_issuer_signature_verifies(adapter, holder_key, signer):
    """The signature is what makes the whole structure worth anything."""
    issuer_signed = await issue(adapter, holder_key)

    assert signer.verify(issuer_signed["issuerAuth"])


async def test_a_tampered_credential_does_not_verify(adapter, holder_key, signer):
    issuer_signed = await issue(adapter, holder_key)
    issuer_auth = list(issuer_signed["issuerAuth"])
    mso = cbor2.loads(cbor2.loads(issuer_auth[2]).value)
    mso["docType"] = "org.example.forged"
    issuer_auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))

    assert not signer.verify(issuer_auth)


async def test_the_certificate_chain_travels_with_the_signature(adapter, holder_key):
    """Section 9.1.2.4: x5chain, unprotected, at least one certificate."""
    issuer_signed = await issue(adapter, holder_key)

    unprotected = issuer_signed["issuerAuth"][1]
    assert unprotected[33] == [b"a-fake-der-certificate"]


async def test_only_the_algorithm_is_protected(adapter, holder_key):
    """Section 9.1.2.4: other elements should not be in the protected header."""
    issuer_signed = await issue(adapter, holder_key)

    protected = cbor2.loads(issuer_signed["issuerAuth"][0])
    assert list(protected) == [1]


def test_the_metadata_fragment_declares_the_doctype(adapter):
    """Appendix A.2: doctype is REQUIRED in the credential configuration."""
    fragment = adapter.metadata_fragment()

    assert fragment["format"] == FORMAT_MSO_MDOC
    assert fragment["doctype"] == DOCTYPE


async def test_claims_outside_a_namespace_are_refused(adapter, holder_key):
    with pytest.raises(ValueError):
        await adapter.issue({"family_name": "Musterfrau"}, holder_key=holder_key)
