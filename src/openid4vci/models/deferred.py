"""Deferred Credential Endpoint (Section 9).

For issuance that cannot complete synchronously -- a manual review, an
external system, data that is not ready. The Wallet polls with the
``transaction_id`` it received, waiting at least ``interval`` seconds between
attempts.
"""

from .common import Model
from .credential import CredentialResponse
from .credential import RequestedCredentialResponseEncryption
from enum import Enum


class DeferredCredentialErrorCode(str, Enum):
    """Error codes of the Deferred Credential Endpoint (Section 9.3)."""

    INVALID_TRANSACTION_ID = "invalid_transaction_id"


class DeferredCredentialRequest(Model):
    """A Deferred Credential Request (Section 9.1)."""

    transaction_id: str
    credential_response_encryption: RequestedCredentialResponseEncryption | None = None


class DeferredCredentialResponse(CredentialResponse):
    """A Deferred Credential Response (Section 9.2).

    Same parameters as the Credential Response, and the same either/or: the
    credentials, or the transaction stays open with an unchanged
    ``transaction_id``.
    """
