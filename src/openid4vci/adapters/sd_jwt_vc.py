"""IETF SD-JWT VC profile, format identifier ``dc+sd-jwt`` (Appendix A.3).

Selective disclosure over a JWT. The issuer replaces each disclosable claim
with a salted digest and hands the holder the cleartext separately; the holder
then decides, at presentation time, which of them to pass on. The signature
covers the digests, so a verifier can check a subset the issuer never saw.

Two documents apply, and they are at different stages:

* the mechanism is RFC 9901, a published standard;
* the credential profile on top is draft-ietf-oauth-sd-jwt-vc-18 of
  2026-08-03, which is Standards Track but not yet an RFC.

The draft is named here on purpose: it can still change, and whoever reads this
later should know which version the code was written against.
"""

from ..crypto.signer import CredentialSigner
from collections.abc import Iterable
from typing import Any

import base64
import hashlib
import json
import secrets


#: Credential Format Identifier (Appendix A.3).
FORMAT_SD_JWT_VC = "dc+sd-jwt"

#: Value of the `typ` header (draft-18 Section 2.2.1).
#:
#: Until November 2024 this was `vc+sd-jwt`; it changed to avoid a clash with
#: the media type the W3C registered. Verifiers accept both for a transitional
#: period, but an issuer writes the current one.
SD_JWT_VC_TYP = "dc+sd-jwt"

#: Separator between the issuer-signed JWT, the disclosures and the optional
#: key binding JWT (RFC 9901 Section 4).
SEPARATOR = "~"

#: Hash algorithms, by their "Named Information Hash Algorithm" identifier.
HASH_ALGORITHMS = {
    "sha-256": hashlib.sha256,
    "sha-384": hashlib.sha384,
    "sha-512": hashlib.sha512,
}

#: Claim names the format reserves (RFC 9901 Section 4.2.1).
RESERVED_CLAIM_NAMES = ("_sd", "...")

#: Salt length in bytes. RFC 9901 Section 9.3 recommends 128 bits.
SALT_BYTES = 16


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def disclosure_digest(disclosure: str, algorithm: str = "sha-256") -> str:
    """Return the digest that stands in for a disclosure.

    RFC 9901 Section 4.2.3 is unusually specific here, and for good reason:
    the digest is taken over the **base64url string itself**, not over the
    bytes it encodes, and the result is base64url-encoded rather than
    hex-encoded. Getting either wrong produces a credential that looks
    entirely correct and that no verifier will accept.
    """
    digest = HASH_ALGORITHMS[algorithm](disclosure.encode("ascii")).digest()
    return _b64url(digest)


def make_disclosure(name: str, value: Any) -> str:
    """Return one disclosure for an object property (RFC 9901 Section 4.2.1).

    The array is salt, claim name, claim value, in that order. The salt is
    fresh for every claim and is never shown to anyone but the holder: it is
    what keeps the digest of a short, guessable value -- a date of birth, a
    yes-or-no flag -- from revealing that value.
    """
    if name in RESERVED_CLAIM_NAMES:
        raise ValueError(
            f"{name!r} is reserved by the format and cannot be a disclosed claim; "
            f"reserved names are {RESERVED_CLAIM_NAMES}"
        )
    salt = _b64url(secrets.token_bytes(SALT_BYTES))
    array = json.dumps([salt, name, value], ensure_ascii=False, separators=(", ", ": "))
    return _b64url(array.encode("utf-8"))


class SdJwtVcAdapter:
    """Issues credentials in the SD-JWT VC format."""

    def __init__(
        self,
        vct: str,
        signer: CredentialSigner,
        issuer: str | None = None,
        always_visible: Iterable[str] = (),
        hash_algorithm: str = "sha-256",
    ) -> None:
        """
        :param vct: the credential type, published to verifiers.
        :param signer: signs the issuer-signed JWT.
        :param issuer: our identifier, written to ``iss``.
        :param always_visible: claims that stay in the payload rather than
            becoming disclosures. Use it for what a verifier must see in order
            to make sense of the credential at all -- never for personal data,
            which is what the format exists to keep back.
        :param hash_algorithm: one of sha-256, sha-384, sha-512.
        """
        if hash_algorithm not in HASH_ALGORITHMS:
            raise ValueError(
                f"Supported hash algorithms are {sorted(HASH_ALGORITHMS)}, got "
                f"{hash_algorithm!r}"
            )
        self.vct = vct
        self.signer = signer
        self.issuer = issuer
        self.always_visible = frozenset(always_visible)
        self.hash_algorithm = hash_algorithm

    @property
    def format(self) -> str:
        """The Credential Format Identifier."""
        return FORMAT_SD_JWT_VC

    def metadata_fragment(self) -> dict[str, Any]:
        """Return the format-specific part of the credential configuration."""
        return {"format": FORMAT_SD_JWT_VC, "vct": self.vct}

    async def issue(self, claims: dict[str, Any], *, holder_key: dict[str, Any]) -> str:
        """Return the issued credential in its compact serialization.

        :param claims: the data to put into the credential. Everything not
            listed in ``always_visible`` becomes a disclosure.
        :param holder_key: public JWK the credential is bound to. It becomes
            the confirmation claim, which draft-18 requires whenever key
            binding is supported.
        """
        disclosures: list[str] = []
        payload: dict[str, Any] = {}

        for name, value in claims.items():
            if name in self.always_visible:
                payload[name] = value
            else:
                disclosures.append(make_disclosure(name, value))

        if disclosures:
            # Sorted rather than in claim order: Section 4.2.4.1 requires the
            # original order to be hidden, because the order alone would say
            # which claims a credential carries.
            payload["_sd"] = sorted(
                disclosure_digest(d, self.hash_algorithm) for d in disclosures
            )
        payload["_sd_alg"] = self.hash_algorithm

        payload["vct"] = self.vct
        if self.issuer is not None:
            payload["iss"] = self.issuer
        payload["cnf"] = {"jwk": holder_key}

        issuer_jwt = await self.signer.sign(
            payload=json.dumps(payload, ensure_ascii=False),
            header={"typ": SD_JWT_VC_TYP},
        )

        # The trailing separator is not decoration: it is how a verifier tells
        # an SD-JWT from an SD-JWT+KB, whose last element is a key binding JWT.
        return SEPARATOR.join([issuer_jwt, *disclosures, ""])
