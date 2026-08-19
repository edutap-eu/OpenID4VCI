"""Data types shared across the endpoint models.

The base model here fixes two decisions that apply to every message of the
protocol.

Unknown parameters are kept, not rejected. The specification says extensions
may add parameters and that a recipient ignores what it does not recognize, so
a strict model would turn a legitimate extension into an error.

Names go over the wire as the specification spells them, which is not always a
legal Python identifier: ``pre-authorized_code`` carries a hyphen, and grant
types are URNs. Field aliases carry the wire name, and serialization uses them.
"""

from pydantic import AfterValidator
from pydantic import BaseModel
from pydantic import ConfigDict
from typing import Annotated
from typing import Any
from urllib.parse import urlparse


#: Grant type identifiers used across the protocol (Sections 4.1.1 and 6.1).
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


class Model(BaseModel):
    """Base for every model of the protocol."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",
    )

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation that goes over the wire.

        Uses the wire names, converts values that JSON has no type for, and
        sends only what was actually set.

        The last part matters more than it looks. Several parameters have a
        default the specification states in prose -- an absent ``mandatory``
        means false, an absent ``input_mode`` means numeric. Writing those
        defaults out would change a document we received into a different one
        that happens to mean the same, which is the wrong thing to do to
        metadata that a Wallet may compare or that may carry a signature.
        """
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude_unset=True,
        )


class ErrorResponse(Model):
    """An error response, as used by several endpoints of the protocol."""

    error: str
    error_description: str | None = None


def _check_credential_issuer_identifier(value: str) -> str:
    """Validate a Credential Issuer Identifier without normalizing it.

    Section 12.2 requires that a Wallet compare the identifier in the metadata
    against the one it derived the metadata URL from "using a simple string
    comparison with no normalization", and discard the metadata when they
    differ. A URL type that appends a trailing slash, lowercases the host or
    reorders anything would therefore break interoperability rather than help
    it, so this stays a string and is only checked.

    Section 12.1: the identifier is a case-sensitive https URL with scheme,
    host and optionally port and path, but no query and no fragment.
    """
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise ValueError(
            f"A Credential Issuer Identifier must use the https scheme, got: {value!r}"
        )
    if not parsed.netloc:
        raise ValueError(
            f"A Credential Issuer Identifier must contain a host, got: {value!r}"
        )
    if parsed.query:
        raise ValueError(
            f"A Credential Issuer Identifier must not contain a query component, got: {value!r}"
        )
    if parsed.fragment:
        raise ValueError(
            f"A Credential Issuer Identifier must not contain a fragment component, got: {value!r}"
        )
    return value


#: The Credential Issuer Identifier (Section 12.1), kept verbatim.
CredentialIssuerIdentifier = Annotated[
    str, AfterValidator(_check_credential_issuer_identifier)
]
