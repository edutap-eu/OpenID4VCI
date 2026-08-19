"""Errors that map onto the error codes of the specification.

An issuer that rejects something must tell the Wallet *which* error occurred,
because the Wallet acts differently on each: ``invalid_nonce`` means fetch a
fresh nonce and retry, ``credential_request_denied`` means give up. Carrying
the code on the exception keeps that decision at the place that detected the
problem rather than at the place that formats the response.
"""

from .models.credential import CredentialErrorCode
from .models.deferred import DeferredCredentialErrorCode
from .models.notification import NotificationErrorCode


class OpenID4VCIError(Exception):
    """Base class for every error this library raises."""


class CredentialRequestError(OpenID4VCIError):
    """A Credential Request cannot be honoured.

    :param code: the error code to return to the Wallet.
    :param description: human-readable detail, ASCII, for the developer on the
        other side. It becomes ``error_description``.
    """

    def __init__(self, code: CredentialErrorCode, description: str) -> None:
        super().__init__(f"{code.value}: {description}")
        self.code = code
        self.description = description


class DeferredCredentialError(OpenID4VCIError):
    """A Deferred Credential Request cannot be honoured."""

    def __init__(self, code: DeferredCredentialErrorCode, description: str) -> None:
        super().__init__(f"{code.value}: {description}")
        self.code = code
        self.description = description


class NotificationError(OpenID4VCIError):
    """A Notification Request cannot be accepted."""

    def __init__(self, code: NotificationErrorCode, description: str) -> None:
        super().__init__(f"{code.value}: {description}")
        self.code = code
        self.description = description
