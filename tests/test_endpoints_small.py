"""Nonce, Deferred Credential and Notification endpoints, Sections 7, 9 and 11."""

from openid4vci.models.deferred import DeferredCredentialRequest
from openid4vci.models.deferred import DeferredCredentialResponse
from openid4vci.models.nonce import NonceResponse
from openid4vci.models.notification import NotificationErrorCode
from openid4vci.models.notification import NotificationEvent
from openid4vci.models.notification import NotificationRequest
from pydantic import ValidationError

import pytest


def test_the_nonce_response_carries_the_challenge():
    assert NonceResponse(c_nonce="wKI4LT-mI").c_nonce == "wKI4LT-mI"


def test_a_nonce_is_required():
    with pytest.raises(ValidationError):
        NonceResponse.model_validate({})


def test_a_deferred_request_needs_the_transaction_id():
    request = DeferredCredentialRequest.model_validate({"transaction_id": "8xLOxBtZp8"})

    assert request.transaction_id == "8xLOxBtZp8"

    with pytest.raises(ValidationError):
        DeferredCredentialRequest.model_validate({})


def test_a_deferred_response_uses_the_same_shape_as_the_credential_response():
    response = DeferredCredentialResponse.model_validate(
        {"credentials": [{"credential": "LUpixVCWJk0eOt4CXQe1NXK"}]}
    )

    assert response.credentials is not None

    with pytest.raises(ValidationError, match="interval"):
        DeferredCredentialResponse.model_validate({"transaction_id": "8xLOxBtZp8"})


def test_the_notification_events_are_the_three_the_specification_defines():
    assert {event.value for event in NotificationEvent} == {
        "credential_accepted",
        "credential_failure",
        "credential_deleted",
    }


def test_a_notification_names_an_issuance_and_an_event():
    request = NotificationRequest.model_validate(
        {"notification_id": "3fwe98js", "event": "credential_accepted"}
    )

    assert request.notification_id == "3fwe98js"
    assert request.event is NotificationEvent.CREDENTIAL_ACCEPTED


def test_an_unknown_event_is_rejected():
    with pytest.raises(ValidationError):
        NotificationRequest.model_validate(
            {"notification_id": "3fwe98js", "event": "credential_ignored"}
        )


def test_the_notification_error_codes():
    assert {code.value for code in NotificationErrorCode} == {
        "invalid_notification_id",
        "invalid_notification_request",
    }
