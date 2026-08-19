# How to serve the issuer endpoints

This guide shows you how to mount the Credential Issuer endpoints in a FastAPI application.

## Install with the FastAPI extra

```shell
pip install "openid4vci[fastapi]"
```

## Implement the backend

The router owns the protocol; every decision is yours.
Implement the `IssuerBackend` protocol with the five methods the router calls:

```python
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.metadata import CredentialIssuerMetadata
from openid4vci.server_fastapi.app import RequestContext


class MyBackend:
    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        return CredentialIssuerMetadata.model_validate(MY_METADATA)

    async def create_nonce(self) -> str:
        nonce = secrets.token_urlsafe(24)
        await self.nonce_store.remember(nonce)
        return nonce

    async def issue_credential(self, request, context: RequestContext) -> CredentialResponse:
        ...

    async def issue_deferred(self, request, context: RequestContext) -> CredentialResponse:
        ...

    async def notify(self, request, context: RequestContext) -> None:
        ...
```

`RequestContext` carries the bearer token, already extracted, and the underlying request.
Validating the token is your job: only you know which Authorization Server issued it and what it grants.

## Mount the router

```python
from fastapi import FastAPI
from openid4vci.server_fastapi.app import create_router

app = FastAPI()
app.include_router(create_router(MyBackend()))
```

The router serves five paths:

| Path | Method | Section |
| --- | --- | --- |
| `/.well-known/openid-credential-issuer` | GET | 12.2 |
| `/nonce` | POST | 7 |
| `/credential` | POST | 8 |
| `/deferred_credential` | POST | 9 |
| `/notification` | POST | 11 |

Pass `prefix=` to `create_router` if the issuer does not live at the root.

## Refuse a request with the right error

Raise, and the router renders the error body the specification defines:

```python
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode

raise CredentialRequestError(
    CredentialErrorCode.INVALID_NONCE,
    "fetch a fresh challenge from the nonce endpoint",
)
```

```{important}
Choose the code deliberately.
A Wallet acts on it: `invalid_nonce` means fetch a fresh challenge and retry, while `credential_request_denied` means give up.
Collapsing the two strands a Wallet on a recoverable error.
```

## What the router does not serve

The Authorization Endpoint and the Token Endpoint.
They belong to the Authorization Server, which may be a separate deployment.
Point at it with the `authorization_servers` parameter of your issuer metadata.
