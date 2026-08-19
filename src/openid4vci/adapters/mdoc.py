"""ISO mdoc profile, format identifier ``mso_mdoc`` (Appendix A.2).

The credential is a CBOR structure, not a token: data elements are carried
individually, each salted and hashed, and a signed Mobile Security Object
holds the hashes. A verifier can therefore check a subset of the elements the
holder chose to show, without the issuer having signed that subset -- which is
how selective disclosure works here.

Structures follow ISO/IEC 18013-5:2021, sections 8.3.2.1.2.2 and 9.1.2. The
standard is not freely available; section numbers are cited so an implementer
with access can follow along, and no normative text is reproduced.

Requires the ``mdoc`` extra.
"""

from ..crypto.jwk import is_asymmetric
from cbor2 import CBORTag
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any

import base64
import cbor2
import hashlib
import secrets


#: Credential Format Identifier (Appendix A.2).
FORMAT_MSO_MDOC = "mso_mdoc"

#: CBOR tag for an embedded CBOR data item (RFC 8949).
TAG_EMBEDDED_CBOR = 24

#: CBOR tag for a standard date/time string (RFC 8949).
TAG_DATE_TIME = 0

#: COSE header label for a certificate chain.
COSE_HEADER_X5CHAIN = 33

#: COSE header label for the signature algorithm.
COSE_HEADER_ALG = 1

#: Version of the Mobile Security Object structure this implements.
MSO_VERSION = "1.0"

#: Digest algorithms the standard permits, and their hashlib names.
DIGEST_ALGORITHMS = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}

#: Minimum length of the salt on a data element (section 9.1.2.5).
MINIMUM_SALT_BYTES = 16

#: Digest identifiers must stay below this (section 9.1.2.4).
MAX_DIGEST_ID = 2**31


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _timestamp(moment: datetime) -> CBORTag:
    """Encode a moment the way the standard requires.

    Whole seconds and a UTC offset of zero: fractions and local offsets are
    excluded, and the timestamps are a linkability clue, so precision here is
    something to give away rather than to keep.
    """
    text = moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    return CBORTag(TAG_DATE_TIME, text.replace("+00:00", "Z"))


def cose_key_from_jwk(jwk: dict[str, Any]) -> dict[int, Any]:
    """Convert a public EC JWK into an untagged COSE_Key (RFC 8152).

    Only the EC2 key types are handled, which is what the standard's signature
    algorithms use.

    :raises ValueError: for a key type this profile cannot carry.
    """
    if not is_asymmetric(jwk):
        raise ValueError(f"Expected an asymmetric key, got kty={jwk.get('kty')!r}")
    if jwk.get("kty") != "EC":
        raise ValueError(
            f"The mdoc profile carries EC keys as COSE_Key, got kty={jwk.get('kty')!r}"
        )
    curves = {"P-256": 1, "P-384": 2, "P-521": 3}
    curve = curves.get(jwk.get("crv", ""))
    if curve is None:
        raise ValueError(f"Unsupported curve for a COSE_Key: {jwk.get('crv')!r}")
    return {
        1: 2,  # kty: EC2
        -1: curve,
        -2: _b64url_decode(jwk["x"]),
        -3: _b64url_decode(jwk["y"]),
    }


class LocalCoseSigner:
    """Signs the Mobile Security Object with a key held in this process.

    Anything with stronger key handling replaces this: what an adapter needs
    is the algorithm, the certificate chain and a signature over the COSE
    signing structure.
    """

    def __init__(self, key: Any, certificate_chain: list[bytes]) -> None:
        """
        :param key: a pycose EC2 key holding the private half.
        :param certificate_chain: DER certificates, issuer certificate first.
            The standard requires at least one; it travels unprotected, so a
            verifier can find the key without already having it.
        """
        if not certificate_chain:
            raise ValueError(
                "A certificate chain must contain at least one certificate"
            )
        self._key = key
        self.certificate_chain = certificate_chain

    @classmethod
    def generate(cls, certificate_chain: list[bytes]) -> "LocalCoseSigner":
        """Create a signer with a fresh P-256 key, for tests and development."""
        from pycose.keys import EC2Key

        return cls(EC2Key.generate_key(crv="P_256"), certificate_chain)

    @property
    def algorithm(self) -> Any:
        """The COSE algorithm this signer uses."""
        from pycose.algorithms import Es256

        return Es256

    def sign(self, payload: bytes) -> list[Any]:
        """Return an untagged COSE_Sign1 over ``payload``.

        Untagged is what the standard prescribes for ``IssuerAuth``, and the
        external additional authenticated data is empty.
        """
        from pycose.headers import Algorithm
        from pycose.messages import Sign1Message

        message = Sign1Message(
            phdr={Algorithm: self.algorithm},
            uhdr={COSE_HEADER_X5CHAIN: self.certificate_chain},
            payload=payload,
        )
        message.key = self._key
        return cbor2.loads(message.encode(tag=False))

    def verify(self, issuer_auth: list[Any]) -> bool:
        """Verify an untagged COSE_Sign1 produced by this signer.

        Present for tests and for an issuer checking its own output; a verifier
        in the field obtains the key from the certificate chain instead.
        """
        from pycose.messages import Sign1Message

        # from_cose_obj rather than decode: decode expects the tagged form, and
        # the standard prescribes the untagged one. allow_unknown_attributes
        # because the certificate chain header is not one pycose knows.
        message = Sign1Message.from_cose_obj(
            list(issuer_auth), allow_unknown_attributes=True
        )
        message.key = self._key
        return message.verify_signature()


class MdocAdapter:
    """Issues credentials in the ISO mdoc format."""

    def __init__(
        self,
        doctype: str,
        signer: LocalCoseSigner,
        digest_algorithm: str = "SHA-256",
        validity: timedelta = timedelta(days=365),
    ) -> None:
        """
        :param doctype: the document type, e.g. ``org.iso.18013.5.1.mDL``.
        :param signer: signs the Mobile Security Object.
        :param digest_algorithm: one of SHA-256, SHA-384, SHA-512.
        :param validity: how long the security object stays valid.
        """
        if digest_algorithm not in DIGEST_ALGORITHMS:
            raise ValueError(
                f"The standard permits {sorted(DIGEST_ALGORITHMS)}, got "
                f"{digest_algorithm!r}"
            )
        self.doctype = doctype
        self.signer = signer
        self.digest_algorithm = digest_algorithm
        self.validity = validity

    @property
    def format(self) -> str:
        """The Credential Format Identifier."""
        return FORMAT_MSO_MDOC

    def metadata_fragment(self) -> dict[str, Any]:
        """Return the format-specific part of the credential configuration."""
        return {"format": FORMAT_MSO_MDOC, "doctype": self.doctype}

    async def issue(self, claims: dict[str, Any], *, holder_key: dict[str, Any]) -> str:
        """Return the base64url-encoded IssuerSigned structure.

        :param claims: namespace to data elements, e.g.
            ``{"org.iso.18013.5.1": {"family_name": "Musterfrau"}}``. Claims
            must be nested per namespace; the format has no place to put a
            data element that belongs to none.
        :param holder_key: public JWK the credential is bound to.
        :raises ValueError: if a claim sits outside a namespace.
        """
        for namespace, elements in claims.items():
            if not isinstance(elements, dict):
                raise ValueError(
                    f"Claims must be grouped per namespace; {namespace!r} carries "
                    f"{type(elements).__name__} rather than a mapping of data elements"
                )

        namespaces: dict[str, list[CBORTag]] = {}
        digests: dict[str, dict[int, bytes]] = {}
        digest = DIGEST_ALGORITHMS[self.digest_algorithm]

        for namespace, elements in claims.items():
            items: list[CBORTag] = []
            per_namespace: dict[int, bytes] = {}
            # Identifiers are drawn per namespace and must not correlate across
            # credentials, or the security object would leak which elements a
            # given mdoc carries.
            identifiers = self._digest_ids(len(elements))
            for digest_id, (identifier, value) in zip(identifiers, elements.items()):
                item = CBORTag(
                    TAG_EMBEDDED_CBOR,
                    cbor2.dumps(
                        {
                            "digestID": digest_id,
                            "random": secrets.token_bytes(MINIMUM_SALT_BYTES),
                            "elementIdentifier": identifier,
                            "elementValue": value,
                        }
                    ),
                )
                items.append(item)
                per_namespace[digest_id] = digest(cbor2.dumps(item)).digest()
            namespaces[namespace] = items
            digests[namespace] = per_namespace

        signed_at = datetime.now(timezone.utc)
        security_object = {
            "version": MSO_VERSION,
            "digestAlgorithm": self.digest_algorithm,
            "valueDigests": digests,
            "deviceKeyInfo": {"deviceKey": cose_key_from_jwk(holder_key)},
            "docType": self.doctype,
            "validityInfo": {
                "signed": _timestamp(signed_at),
                "validFrom": _timestamp(signed_at),
                "validUntil": _timestamp(signed_at + self.validity),
            },
        }

        payload = cbor2.dumps(CBORTag(TAG_EMBEDDED_CBOR, cbor2.dumps(security_object)))
        issuer_signed = {
            "nameSpaces": namespaces,
            "issuerAuth": self.signer.sign(payload),
        }
        encoded = base64.urlsafe_b64encode(cbor2.dumps(issuer_signed))
        return encoded.decode("ascii").rstrip("=")

    @staticmethod
    def _digest_ids(count: int) -> list[int]:
        """Return distinct digest identifiers within the permitted range."""
        identifiers: set[int] = set()
        while len(identifiers) < count:
            identifiers.add(secrets.randbelow(MAX_DIGEST_ID))
        return list(identifiers)
