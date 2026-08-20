"""W3C VCDM profiles (Appendix A.1).

Three variants exist: ``jwt_vc_json`` (a credential signed as a JWT, no
JSON-LD), ``jwt_vc_json-ld`` (the same, using JSON-LD) and ``ldp_vc`` (JSON-LD
with a Data Integrity proof, which requires canonicalization). This module
implements the first, which is the one that needs no JSON-LD machinery at all
-- the specification is explicit that for ``jwt_vc_json`` nothing is to be
processed under JSON-LD rules.

The JWT encoding of the data model duplicates parts of the credential into
registered JWT claims: the issuer appears as ``iss``, the credential
identifier as ``jti``, the subject as ``sub``, the issuance date as ``nbf``.
A verifier may read either copy, so this module writes both from one source
rather than letting them drift.
"""

from ..crypto.signer import CredentialSigner
from collections.abc import Iterable
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any

import base64
import json
import uuid


#: Credential Format Identifier (Appendix A.1.1).
FORMAT_JWT_VC_JSON = "jwt_vc_json"

#: The base context every credential of this data model carries.
CONTEXT_VC_V1 = "https://www.w3.org/2018/credentials/v1"

#: The type every credential carries, in addition to its own.
TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential"


def did_jwk(jwk: dict[str, Any]) -> str:
    """Return the ``did:jwk`` identifier for a public key.

    Binding a credential to its holder needs an identifier for that holder,
    and running a DID method of our own is a great deal of machinery for a
    question the key already answers. ``did:jwk`` is the key itself, encoded.
    """
    encoded = base64.urlsafe_b64encode(
        json.dumps(jwk, separators=(",", ":")).encode("utf-8")
    )
    return "did:jwk:" + encoded.decode("ascii").rstrip("=")


def _rfc3339(moment: datetime) -> str:
    """Format a moment the way the data model writes dates."""
    text = moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    return text.replace("+00:00", "Z")


class JwtVcAdapter:
    """Issues credentials in the ``jwt_vc_json`` format.

    The adapter is deliberately unopinionated about *what* is being attested:
    types and contexts are parameters, so an Open Badge, a micro-credential or
    a course certificate are the same code with different arguments.
    """

    def __init__(
        self,
        types: Iterable[str],
        signer: CredentialSigner,
        issuer: str,
        contexts: Iterable[str] = (),
        validity: timedelta | None = None,
        credential_id_prefix: str | None = None,
    ) -> None:
        """
        :param types: the credential types. ``VerifiableCredential`` is added
            in front unless it is already there; a credential that does not say
            it is one cannot be processed as one.
        :param signer: signs the credential.
        :param issuer: our identifier, written to ``iss`` and to ``issuer``.
        :param contexts: further contexts, after the base one.
        :param validity: how long the credential is valid. Left unset there is
            no expiry, which is right for an achievement: passing an exam does
            not stop having happened.
        :param credential_id_prefix: base URL for credential identifiers. A
            resolvable identifier is what lets a status list or a revocation
            entry point at one specific credential.
        """
        types = list(types)
        if TYPE_VERIFIABLE_CREDENTIAL in types:
            types.remove(TYPE_VERIFIABLE_CREDENTIAL)
        self.types = [TYPE_VERIFIABLE_CREDENTIAL, *types]
        self.contexts = [CONTEXT_VC_V1, *contexts]
        self.signer = signer
        self.issuer = issuer
        self.validity = validity
        self.credential_id_prefix = (
            credential_id_prefix or f"{issuer.rstrip('/')}/credentials"
        )

    @property
    def format(self) -> str:
        """The Credential Format Identifier."""
        return FORMAT_JWT_VC_JSON

    def metadata_fragment(self) -> dict[str, Any]:
        """Return the format-specific part of the credential configuration."""
        return {
            "format": FORMAT_JWT_VC_JSON,
            "credential_definition": {"type": list(self.types)},
        }

    async def issue(
        self,
        claims: dict[str, Any],
        *,
        holder_key: dict[str, Any],
        subject_id: str | None = None,
    ) -> str:
        """Return the issued credential as a JWT.

        :param claims: what the credential attests. They become the
            ``credentialSubject``.
        :param holder_key: public JWK the credential is bound to.
        :param subject_id: identifier for the subject. Defaults to the
            ``did:jwk`` of the holder key.
        """
        issued_at = datetime.now(timezone.utc)
        subject = subject_id or did_jwk(holder_key)
        credential_id = f"{self.credential_id_prefix}/{uuid.uuid4()}"

        credential: dict[str, Any] = {
            "@context": list(self.contexts),
            "id": credential_id,
            "type": list(self.types),
            "issuer": self.issuer,
            "issuanceDate": _rfc3339(issued_at),
            "credentialSubject": {"id": subject, **claims},
        }

        payload: dict[str, Any] = {
            "iss": self.issuer,
            "jti": credential_id,
            "sub": subject,
            "nbf": int(issued_at.timestamp()),
        }

        if self.validity is not None:
            expires_at = issued_at + self.validity
            credential["expirationDate"] = _rfc3339(expires_at)
            payload["exp"] = int(expires_at.timestamp())

        payload["vc"] = credential

        return await self.signer.sign(
            payload=json.dumps(payload, ensure_ascii=False),
            header={"typ": "JWT"},
        )
