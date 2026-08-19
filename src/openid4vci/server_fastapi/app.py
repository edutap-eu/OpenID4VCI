"""FastAPI implementation of the Credential Issuer endpoints.

The router owns the protocol mechanics: media types, status codes, the
``Cache-Control`` the Nonce Endpoint requires, bearer token extraction, and
turning our exceptions into the error bodies the specification defines.

It owns none of the decisions. Whether a credential may be issued, which
nonce is current, what a transaction identifier refers to -- all of that is
deployment knowledge, and it lives behind :class:`IssuerBackend`. A library
that decided any of it would be deciding it for a deployment it cannot see.

The Authorization Endpoint and the Token Endpoint are deliberately absent:
they belong to the Authorization Server, which may be a separate deployment.
"""

from ..exceptions import CredentialRequestError
from ..exceptions import DeferredCredentialError
from ..exceptions import NotificationError
from ..models.credential import CredentialErrorCode
from ..models.credential import CredentialRequest
from ..models.credential import CredentialResponse
from ..models.deferred import DeferredCredentialRequest
from ..models.metadata import CredentialIssuerMetadata
from ..models.metadata import WELL_KNOWN_CREDENTIAL_ISSUER
from ..models.nonce import NonceResponse
from ..models.notification import NotificationErrorCode
from ..models.notification import NotificationRequest
from dataclasses import dataclass
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi import Response
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from pydantic import ValidationError
from typing import Any
from typing import Protocol
from typing import runtime_checkable


#: Header the Nonce Endpoint must send, and that credential responses carry
#: too: none of this is safe to keep.
NO_STORE = {"Cache-Control": "no-store"}


@dataclass(frozen=True)
class RequestContext:
    """What the transport knows about a request, handed to the backend.

    :param access_token: the bearer token, already extracted. Validating it is
        the backend's job: only it knows which Authorization Server issued it
        and what it grants.
    :param request: the underlying HTTP request, for backends that need more.
    """

    access_token: str
    request: Request


@runtime_checkable
class IssuerBackend(Protocol):
    """What a deployment must provide to become a Credential Issuer."""

    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        """Return the metadata document to publish."""

    async def create_nonce(self) -> str:
        """Return a fresh, unpredictable ``c_nonce``."""

    async def issue_credential(
        self, request: CredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        """Issue, or open a deferred transaction.

        :raises CredentialRequestError: to refuse with a specific error code.
        """

    async def issue_deferred(
        self, request: DeferredCredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        """Answer a deferred transaction, or keep it open.

        :raises DeferredCredentialError: if the transaction is unknown or used.
        """

    async def notify(
        self, request: NotificationRequest, context: RequestContext
    ) -> None:
        """Record what became of issued credentials.

        :raises NotificationError: if the notification identifier is unknown.
        """


_bearer = HTTPBearer(description="Access token obtained from the Token Endpoint")


def _context(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> RequestContext:
    return RequestContext(access_token=credentials.credentials, request=request)


def _error(code: Any, description: str) -> JSONResponse:
    """Render an error body as the specification defines it."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": code.value, "error_description": description},
        headers=NO_STORE,
    )


def _credential_response(response: CredentialResponse) -> JSONResponse:
    """Render a Credential Response, choosing the status code it implies.

    Section 8.3 makes this a MUST rather than a nicety: 202 is how a Wallet
    learns to come back to the Deferred Credential Endpoint instead of
    treating the answer as final.
    """
    deferred = response.transaction_id is not None
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED if deferred else status.HTTP_200_OK,
        content=response.to_dict(),
        headers=NO_STORE,
    )


def create_router(backend: IssuerBackend, prefix: str = "") -> APIRouter:
    """Return a router serving the Credential Issuer endpoints.

    :param backend: the deployment's implementation of the decisions.
    :param prefix: mount point, if the issuer does not live at the root.
    """
    router = APIRouter(prefix=prefix)

    @router.get(
        WELL_KNOWN_CREDENTIAL_ISSUER,
        summary="Credential Issuer Metadata (Section 12.2)",
    )
    async def issuer_metadata() -> JSONResponse:
        metadata = await backend.issuer_metadata()
        return JSONResponse(content=metadata.to_dict())

    @router.post("/nonce", summary="Nonce Endpoint (Section 7)")
    async def nonce() -> JSONResponse:
        c_nonce = await backend.create_nonce()
        return JSONResponse(
            content=NonceResponse(c_nonce=c_nonce).to_dict(),
            headers=NO_STORE,
        )

    @router.post("/credential", summary="Credential Endpoint (Section 8)")
    async def credential(
        payload: dict[str, Any],
        context: RequestContext = Depends(_context),
    ) -> JSONResponse:
        try:
            request = CredentialRequest.model_validate(payload)
        except ValidationError as error:
            return _error(CredentialErrorCode.INVALID_CREDENTIAL_REQUEST, str(error))
        try:
            response = await backend.issue_credential(request, context)
        except CredentialRequestError as error:
            return _error(error.code, error.description)
        return _credential_response(response)

    @router.post(
        "/deferred_credential",
        summary="Deferred Credential Endpoint (Section 9)",
    )
    async def deferred_credential(
        payload: dict[str, Any],
        context: RequestContext = Depends(_context),
    ) -> JSONResponse:
        try:
            request = DeferredCredentialRequest.model_validate(payload)
        except ValidationError as error:
            return _error(CredentialErrorCode.INVALID_CREDENTIAL_REQUEST, str(error))
        try:
            response = await backend.issue_deferred(request, context)
        except DeferredCredentialError as error:
            return _error(error.code, error.description)
        return _credential_response(response)

    @router.post(
        "/notification",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Notification Endpoint (Section 11)",
    )
    async def notification(
        payload: dict[str, Any],
        context: RequestContext = Depends(_context),
    ) -> Response:
        try:
            request = NotificationRequest.model_validate(payload)
        except ValidationError as error:
            return _error(
                NotificationErrorCode.INVALID_NOTIFICATION_REQUEST, str(error)
            )
        try:
            await backend.notify(request, context)
        except NotificationError as error:
            return _error(error.code, error.description)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
