"""Credential Endpoint, OpenID4VCI 1.0 Section 8."""

from openid4vci.models.credential import CredentialErrorCode
from openid4vci.models.credential import CredentialRequest
from openid4vci.models.credential import CredentialResponse
from pydantic import ValidationError

import pytest


PROOFS = {"jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.e30.signature"]}


def test_a_request_by_configuration_id():
    request = CredentialRequest.model_validate(
        {"credential_configuration_id": "org.iso.18013.5.1.mDL", "proofs": PROOFS}
    )

    assert request.credential_configuration_id == "org.iso.18013.5.1.mDL"
    assert request.credential_identifier is None
    assert request.proofs == PROOFS


def test_a_request_by_credential_identifier():
    request = CredentialRequest.model_validate(
        {"credential_identifier": "CivilEngineeringDegree-2023", "proofs": PROOFS}
    )

    assert request.credential_identifier == "CivilEngineeringDegree-2023"


def test_the_two_identifiers_are_mutually_exclusive():
    """Section 8.2: when one is used, the other MUST NOT be present."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        CredentialRequest.model_validate(
            {
                "credential_identifier": "CivilEngineeringDegree-2023",
                "credential_configuration_id": "org.iso.18013.5.1.mDL",
                "proofs": PROOFS,
            }
        )


def test_a_request_must_identify_the_credential_somehow():
    with pytest.raises(ValidationError):
        CredentialRequest.model_validate({"proofs": PROOFS})


def test_proofs_carry_exactly_one_proof_type():
    """Section 8.2: exactly one parameter, named as the proof type."""
    with pytest.raises(ValidationError, match="exactly one"):
        CredentialRequest.model_validate(
            {
                "credential_configuration_id": "org.iso.18013.5.1.mDL",
                "proofs": {"jwt": ["a"], "di_vp": [{}]},
            }
        )


def test_the_proof_array_must_not_be_empty():
    with pytest.raises(ValidationError):
        CredentialRequest.model_validate(
            {
                "credential_configuration_id": "org.iso.18013.5.1.mDL",
                "proofs": {"jwt": []},
            }
        )


def test_an_immediate_response_carries_credentials():
    response = CredentialResponse.model_validate(
        {"credentials": [{"credential": "LUpixVCWJk0eOt4CXQe1NXK"}]}
    )

    assert response.credentials is not None
    assert response.credentials[0].credential == "LUpixVCWJk0eOt4CXQe1NXK"
    assert response.transaction_id is None


def test_a_deferred_response_carries_a_transaction_id_and_an_interval():
    response = CredentialResponse.model_validate(
        {"transaction_id": "8xLOxBtZp8", "interval": 5}
    )

    assert response.transaction_id == "8xLOxBtZp8"
    assert response.interval == 5


def test_credentials_and_transaction_id_exclude_each_other():
    """Section 8.3: credentials MUST NOT be used if transaction_id is present."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        CredentialResponse.model_validate(
            {
                "credentials": [{"credential": "LUpixVCWJk0eOt4CXQe1NXK"}],
                "transaction_id": "8xLOxBtZp8",
            }
        )


def test_a_transaction_id_requires_an_interval():
    """Section 8.3: interval is REQUIRED if transaction_id is present."""
    with pytest.raises(ValidationError, match="interval"):
        CredentialResponse.model_validate({"transaction_id": "8xLOxBtZp8"})


def test_the_interval_must_be_positive():
    with pytest.raises(ValidationError):
        CredentialResponse.model_validate(
            {"transaction_id": "8xLOxBtZp8", "interval": 0}
        )


def test_a_notification_id_needs_credentials_to_refer_to():
    """Section 8.3: it MUST not be used if the credentials parameter is not present."""
    with pytest.raises(ValidationError, match="notification_id"):
        CredentialResponse.model_validate(
            {
                "transaction_id": "8xLOxBtZp8",
                "interval": 5,
                "notification_id": "3fwe98js",
            }
        )


def test_a_response_must_say_something():
    with pytest.raises(ValidationError):
        CredentialResponse.model_validate({})


def test_the_error_codes_are_the_ones_the_specification_lists():
    assert CredentialErrorCode.INVALID_PROOF.value == "invalid_proof"
    assert CredentialErrorCode.INVALID_NONCE.value == "invalid_nonce"
    assert {code.value for code in CredentialErrorCode} == {
        "invalid_credential_request",
        "unknown_credential_configuration",
        "unknown_credential_identifier",
        "invalid_proof",
        "invalid_nonce",
        "invalid_encryption_parameters",
        "credential_request_denied",
    }
