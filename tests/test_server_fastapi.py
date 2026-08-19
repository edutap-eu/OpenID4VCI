"""The Credential Issuer endpoints over HTTP, Sections 7 to 12."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from openid4vci.exceptions import CredentialRequestError
from openid4vci.exceptions import NotificationError
from openid4vci.models.credential import CredentialErrorCode
from openid4vci.models.credential import CredentialRequest
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.deferred import DeferredCredentialRequest
from openid4vci.models.metadata import CredentialIssuerMetadata
from openid4vci.models.notification import NotificationErrorCode
from openid4vci.models.notification import NotificationRequest
from openid4vci.server_fastapi.app import create_router
from openid4vci.server_fastapi.app import RequestContext

import pytest


ISSUER = "https://issuer.example.edu"

METADATA = {
    "credential_issuer": ISSUER,
    "credential_endpoint": f"{ISSUER}/credential",
    "nonce_endpoint": f"{ISSUER}/nonce",
    "credential_configurations_supported": {
        "StudentCredential": {"format": "dc+sd-jwt"}
    },
}


class FakeBackend:
    """A backend that records what it was asked and answers predictably."""

    def __init__(self):
        self.seen_context: RequestContext | None = None
        self.notifications: list[NotificationRequest] = []
        self.next_response = CredentialResponse.model_validate(
            {"credentials": [{"credential": "a-student-credential"}]}
        )
        self.failure: Exception | None = None

    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        return CredentialIssuerMetadata.model_validate(METADATA)

    async def create_nonce(self) -> str:
        return "wKI4LT-mI-nonce"

    async def issue_credential(
        self, request: CredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        self.seen_context = context
        if self.failure is not None:
            raise self.failure
        return self.next_response

    async def issue_deferred(
        self, request: DeferredCredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        return self.next_response

    async def notify(
        self, request: NotificationRequest, context: RequestContext
    ) -> None:
        if self.failure is not None:
            raise self.failure
        self.notifications.append(request)


@pytest.fixture
def backend():
    return FakeBackend()


@pytest.fixture
def client(backend):
    app = FastAPI()
    app.include_router(create_router(backend))
    return TestClient(app)


AUTH = {"Authorization": "Bearer czZCaGRSa3F0MzpnWDFmQmF0M2JW"}


def test_the_metadata_is_served_at_the_well_known_path(client):
    response = client.get("/.well-known/openid-credential-issuer")

    assert response.status_code == 200
    assert response.json()["credential_issuer"] == ISSUER


def test_the_metadata_does_not_grow_fields_it_was_not_given(client):
    """A Wallet may compare this document; it must be what we configured."""
    assert client.get("/.well-known/openid-credential-issuer").json() == METADATA


def test_the_nonce_endpoint_answers_a_post_and_forbids_caching(client):
    """Section 7.2: the response MUST carry Cache-Control: no-store."""
    response = client.post("/nonce")

    assert response.status_code == 200
    assert response.json() == {"c_nonce": "wKI4LT-mI-nonce"}
    assert "no-store" in response.headers["cache-control"]


def test_the_nonce_endpoint_is_unprotected(client):
    """Section 7.1: no access token is involved."""
    assert client.post("/nonce").status_code == 200


def test_an_immediate_issuance_answers_200(client):
    response = client.post(
        "/credential",
        json={"credential_configuration_id": "StudentCredential"},
        headers=AUTH,
    )

    assert response.status_code == 200
    assert response.json()["credentials"] == [{"credential": "a-student-credential"}]


def test_a_deferred_issuance_answers_202(client, backend):
    """Section 8.3: the Issuer MUST use 202 when it cannot issue immediately."""
    backend.next_response = CredentialResponse.model_validate(
        {"transaction_id": "8xLOxBtZp8", "interval": 5}
    )

    response = client.post(
        "/credential",
        json={"credential_configuration_id": "StudentCredential"},
        headers=AUTH,
    )

    assert response.status_code == 202
    assert response.json()["transaction_id"] == "8xLOxBtZp8"


def test_the_access_token_reaches_the_backend(client, backend):
    client.post(
        "/credential",
        json={"credential_configuration_id": "StudentCredential"},
        headers=AUTH,
    )

    assert backend.seen_context is not None
    assert backend.seen_context.access_token == "czZCaGRSa3F0MzpnWDFmQmF0M2JW"


def test_the_credential_endpoint_requires_an_access_token(client):
    response = client.post(
        "/credential", json={"credential_configuration_id": "StudentCredential"}
    )

    assert response.status_code == 401


def test_a_refused_request_becomes_the_error_code_the_backend_chose(client, backend):
    backend.failure = CredentialRequestError(
        CredentialErrorCode.INVALID_NONCE, "fetch a fresh one"
    )

    response = client.post(
        "/credential",
        json={"credential_configuration_id": "StudentCredential"},
        headers=AUTH,
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_nonce",
        "error_description": "fetch a fresh one",
    }


def test_a_malformed_request_is_an_invalid_credential_request(client):
    """Naming both identifiers is what Section 8.2 forbids."""
    response = client.post(
        "/credential",
        json={
            "credential_configuration_id": "StudentCredential",
            "credential_identifier": "StudentCredential-2026",
        },
        headers=AUTH,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_credential_request"


def test_the_deferred_endpoint_answers_the_transaction(client):
    response = client.post(
        "/deferred_credential", json={"transaction_id": "8xLOxBtZp8"}, headers=AUTH
    )

    assert response.status_code == 200
    assert response.json()["credentials"]


def test_a_notification_is_acknowledged_with_204(client, backend):
    """Section 11.2: 2xx, and 204 No Content is RECOMMENDED."""
    response = client.post(
        "/notification",
        json={"notification_id": "3fwe98js", "event": "credential_accepted"},
        headers=AUTH,
    )

    assert response.status_code == 204
    assert response.content == b""
    assert backend.notifications[0].notification_id == "3fwe98js"


def test_an_unknown_notification_id_is_rejected(client, backend):
    backend.failure = NotificationError(
        NotificationErrorCode.INVALID_NOTIFICATION_ID, "never issued"
    )

    response = client.post(
        "/notification",
        json={"notification_id": "unknown", "event": "credential_accepted"},
        headers=AUTH,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_notification_id"


def test_the_notification_endpoint_requires_an_access_token(client):
    response = client.post(
        "/notification",
        json={"notification_id": "3fwe98js", "event": "credential_accepted"},
    )

    assert response.status_code == 401
