"""An in-memory reference implementation of the issuer's decisions.

The library leaves every decision to a deployment, which is right and also
inconvenient: an integration test needs *some* backend, and so does anyone
trying the package out. This module is that backend.

It keeps everything in the process: nonces, deferred transactions and the
notifications a Wallet sends back. That makes it useful for tests and for a
single-process development run, and unsuitable for anything else -- restart it
and every outstanding transaction is gone; run two of them and each knows only
its own nonces.
"""

from .exceptions import CredentialRequestError
from .exceptions import DeferredCredentialError
from .models.credential import CredentialErrorCode
from .models.credential import CredentialRequest
from .models.credential import CredentialResponse
from .models.deferred import DeferredCredentialErrorCode
from .models.deferred import DeferredCredentialRequest
from .models.metadata import CredentialIssuerMetadata
from .models.notification import NotificationRequest
from collections.abc import Awaitable
from collections.abc import Callable
from typing import Any

import secrets
import time


#: How long an issued nonce stays usable, in seconds.
DEFAULT_NONCE_TTL = 300


class InMemoryNonceStore:
    """Nonces with an expiry and single use.

    Both properties matter. The expiry bounds how long a stolen proof stays
    replayable; single use means a proof cannot be presented twice even inside
    that window.
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_NONCE_TTL,
        now: Callable[[], float] = time.time,
    ) -> None:
        """
        :param ttl_seconds: lifetime of an issued nonce.
        :param now: clock, injectable so tests need not sleep.
        """
        self._ttl = ttl_seconds
        self._now = now
        self._issued: dict[str, float] = {}

    def __len__(self) -> int:
        """Number of nonces still held."""
        return len(self._issued)

    def issue(self) -> str:
        """Return a fresh, unpredictable nonce."""
        self._forget_expired()
        nonce = secrets.token_urlsafe(24)
        self._issued[nonce] = self._now() + self._ttl
        return nonce

    def is_current(self, nonce: str) -> bool:
        """Return whether the nonce was issued by us and has not expired."""
        expiry = self._issued.get(nonce)
        return expiry is not None and expiry > self._now()

    def consume(self, nonce: str) -> bool:
        """Accept the nonce once, and never again.

        :returns: whether the nonce was current at the moment of the call.
        """
        if not self.is_current(nonce):
            return False
        del self._issued[nonce]
        return True

    def _forget_expired(self) -> None:
        """Drop expired entries, so the store does not grow without bound."""
        moment = self._now()
        for nonce in [n for n, expiry in self._issued.items() if expiry <= moment]:
            del self._issued[nonce]


class InMemoryTransactionStore:
    """Deferred issuance transactions."""

    def __init__(self) -> None:
        self._open: dict[str, Any] = {}

    def open(self, payload: Any) -> str:
        """Open a transaction and return its identifier."""
        transaction_id = secrets.token_urlsafe(18)
        self._open[transaction_id] = payload
        return transaction_id

    def payload(self, transaction_id: str) -> Any | None:
        """Return what was stored, or ``None`` if the transaction is unknown."""
        return self._open.get(transaction_id)

    def close(self, transaction_id: str) -> None:
        """Invalidate the transaction.

        The specification requires this once the credential has been collected;
        a transaction identifier that keeps working is a second way to ask for
        the same credential.
        """
        self._open.pop(transaction_id, None)


#: Signature of the callable that actually produces a credential.
Mint = Callable[[CredentialRequest, Any], Awaitable[CredentialResponse]]


class InMemoryIssuerBackend:
    """An ``IssuerBackend`` that holds its state in the process.

    Everything specific to a deployment is delegated to ``mint``, which is the
    part this module cannot supply: producing a credential needs a data source
    and a signing key.
    """

    def __init__(
        self,
        metadata: dict[str, Any] | CredentialIssuerMetadata,
        mint: Mint,
        nonce_ttl_seconds: int = DEFAULT_NONCE_TTL,
    ) -> None:
        """
        :param metadata: the issuer metadata to publish.
        :param mint: coroutine producing a Credential Response for a request.
        :param nonce_ttl_seconds: lifetime of issued nonces.
        """
        if isinstance(metadata, CredentialIssuerMetadata):
            self.metadata = metadata
        else:
            self.metadata = CredentialIssuerMetadata.model_validate(metadata)
        self._mint = mint
        self.nonces = InMemoryNonceStore(ttl_seconds=nonce_ttl_seconds)
        self.transactions = InMemoryTransactionStore()
        self.notifications: list[NotificationRequest] = []

    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        """Return the metadata document to publish."""
        return self.metadata

    async def create_nonce(self) -> str:
        """Return a fresh ``c_nonce``."""
        return self.nonces.issue()

    async def issue_credential(
        self, request: CredentialRequest, context: Any
    ) -> CredentialResponse:
        """Check that we know the configuration, then delegate to ``mint``."""
        configuration_id = request.credential_configuration_id
        if (
            configuration_id is not None
            and configuration_id
            not in self.metadata.credential_configurations_supported
        ):
            raise CredentialRequestError(
                CredentialErrorCode.UNKNOWN_CREDENTIAL_CONFIGURATION,
                f"This issuer does not offer {configuration_id!r}",
            )
        return await self._mint(request, context)

    async def issue_deferred(
        self, request: DeferredCredentialRequest, context: Any
    ) -> CredentialResponse:
        """Answer an open transaction, or refuse an unknown one."""
        payload = self.transactions.payload(request.transaction_id)
        if payload is None:
            raise DeferredCredentialError(
                DeferredCredentialErrorCode.INVALID_TRANSACTION_ID,
                "This transaction is unknown to us, or has already been collected",
            )
        response = await self._mint(payload, context)
        if response.credentials is not None:
            self.transactions.close(request.transaction_id)
        return response

    async def notify(self, request: NotificationRequest, context: Any) -> None:
        """Record what became of the issued credentials."""
        self.notifications.append(request)
