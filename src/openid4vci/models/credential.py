"""Credential Endpoint (Section 8).

Access-token protected. The request names the credential -- either by the
``credential_identifier`` the Token Response handed out, or by the
``credential_configuration_id`` from the issuer metadata, never both -- and
carries the key proofs the credential will be bound to.

The response goes one of two ways: the credentials, or a ``transaction_id``
that moves the exchange to the Deferred Credential Endpoint.
"""

from .common import Model
from enum import Enum
from pydantic import Field
from pydantic import model_validator
from typing import Any


class CredentialErrorCode(str, Enum):
    """Error codes of the Credential Endpoint (Section 8.4)."""

    INVALID_CREDENTIAL_REQUEST = "invalid_credential_request"
    UNKNOWN_CREDENTIAL_CONFIGURATION = "unknown_credential_configuration"
    UNKNOWN_CREDENTIAL_IDENTIFIER = "unknown_credential_identifier"
    INVALID_PROOF = "invalid_proof"
    INVALID_NONCE = "invalid_nonce"
    INVALID_ENCRYPTION_PARAMETERS = "invalid_encryption_parameters"
    CREDENTIAL_REQUEST_DENIED = "credential_request_denied"


class RequestedCredentialResponseEncryption(Model):
    """Keys the Wallet supplies to have the response encrypted (Section 8.2)."""

    jwk: dict[str, Any]
    enc: str
    zip: str | None = None


class CredentialRequest(Model):
    """A Credential Request (Section 8.2)."""

    credential_identifier: str | None = None
    credential_configuration_id: str | None = None
    proofs: dict[str, list[Any]] | None = None
    credential_response_encryption: RequestedCredentialResponseEncryption | None = None

    @model_validator(mode="after")
    def _validate_identification_and_proofs(self) -> "CredentialRequest":
        if self.credential_identifier and self.credential_configuration_id:
            raise ValueError(
                "credential_identifier and credential_configuration_id are "
                "mutually exclusive"
            )
        if not self.credential_identifier and not self.credential_configuration_id:
            raise ValueError(
                "A Credential Request must carry either credential_identifier "
                "or credential_configuration_id"
            )
        if self.proofs is not None:
            if len(self.proofs) != 1:
                raise ValueError(
                    "proofs must contain exactly one parameter, named as the "
                    f"proof type, got: {sorted(self.proofs)}"
                )
            for proof_type, proofs in self.proofs.items():
                if not proofs:
                    raise ValueError(
                        f"The proof array for {proof_type!r} must not be empty"
                    )
        return self


class IssuedCredential(Model):
    """One issued credential inside a Credential Response.

    The encoding depends on the credential format and may be a string or an
    object; binary formats are base64url-encoded strings.
    """

    credential: str | dict[str, Any]


class CredentialResponse(Model):
    """A Credential Response (Section 8.3).

    Either the credentials are here, or a deferred transaction is opened. The
    validator enforces that, because the two states exclude each other in
    several directions and a response that mixes them cannot be acted on.
    """

    credentials: list[IssuedCredential] | None = Field(default=None, min_length=1)
    transaction_id: str | None = None
    interval: int | None = Field(default=None, gt=0)
    notification_id: str | None = None

    @model_validator(mode="after")
    def _validate_immediate_or_deferred(self) -> "CredentialResponse":
        if self.credentials is not None and self.transaction_id is not None:
            raise ValueError("credentials and transaction_id are mutually exclusive")
        if self.credentials is None and self.transaction_id is None:
            raise ValueError(
                "A Credential Response must carry either credentials or a "
                "transaction_id"
            )
        if self.transaction_id is not None and self.interval is None:
            raise ValueError("interval is required when transaction_id is present")
        if self.credentials is not None and self.interval is not None:
            raise ValueError("interval must not be used together with credentials")
        if self.notification_id is not None and self.credentials is None:
            raise ValueError(
                "notification_id must not be used when credentials is absent"
            )
        return self
