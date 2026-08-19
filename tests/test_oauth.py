"""Authorization and Token Endpoint, OpenID4VCI 1.0 Sections 5 and 6."""

from openid4vci.models.common import GRANT_TYPE_AUTHORIZATION_CODE
from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
from openid4vci.models.oauth import AuthorizationDetail
from openid4vci.models.oauth import IssuedAuthorizationDetail
from openid4vci.models.oauth import TokenRequest
from openid4vci.models.oauth import TokenResponse
from pydantic import ValidationError

import pytest


def test_authorization_details_use_the_type_this_specification_defines():
    detail = AuthorizationDetail.model_validate(
        {
            "type": "openid_credential",
            "credential_configuration_id": "StudentCredential",
        }
    )

    assert detail.type == "openid_credential"
    assert detail.credential_configuration_id == "StudentCredential"


def test_another_authorization_details_type_is_rejected():
    with pytest.raises(ValidationError):
        AuthorizationDetail.model_validate(
            {"type": "payment_initiation", "credential_configuration_id": "x"}
        )


def test_unknown_fields_are_kept():
    """Section 5.1.1 says this type is never invalid due to unknown fields."""
    detail = AuthorizationDetail.model_validate(
        {
            "type": "openid_credential",
            "credential_configuration_id": "StudentCredential",
            "something_new": "value",
        }
    )

    assert detail.to_dict()["something_new"] == "value"


def test_claims_narrow_the_request():
    detail = AuthorizationDetail.model_validate(
        {
            "type": "openid_credential",
            "credential_configuration_id": "StudentCredential",
            "claims": [{"path": ["given_name"]}, {"path": ["address", "locality"]}],
        }
    )

    assert detail.claims is not None
    assert detail.claims[1].path == ["address", "locality"]


def test_the_token_response_details_carry_credential_identifiers():
    detail = IssuedAuthorizationDetail.model_validate(
        {
            "type": "openid_credential",
            "credential_configuration_id": "StudentCredential",
            "credential_identifiers": ["StudentCredential-2026"],
        }
    )

    assert detail.credential_identifiers == ["StudentCredential-2026"]


def test_credential_identifiers_are_required_in_the_token_response():
    with pytest.raises(ValidationError):
        IssuedAuthorizationDetail.model_validate(
            {
                "type": "openid_credential",
                "credential_configuration_id": "StudentCredential",
            }
        )


def test_a_pre_authorized_code_token_request():
    request = TokenRequest.model_validate(
        {
            "grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE,
            "pre-authorized_code": "adhjhdjajkdkhjhdj",
            "tx_code": "493536",
        }
    )

    assert request.pre_authorized_code == "adhjhdjajkdkhjhdj"
    assert request.tx_code == "493536"
    assert request.to_dict()["pre-authorized_code"] == "adhjhdjajkdkhjhdj"


def test_the_pre_authorized_grant_needs_its_code():
    """Section 6.1: the parameter MUST be present for this grant type."""
    with pytest.raises(ValidationError, match="pre-authorized_code"):
        TokenRequest.model_validate({"grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE})


def test_a_transaction_code_belongs_to_the_pre_authorized_grant_only():
    """Section 6.1: MUST only be used if the grant type is the pre-authorized one."""
    with pytest.raises(ValidationError, match="tx_code"):
        TokenRequest.model_validate(
            {
                "grant_type": GRANT_TYPE_AUTHORIZATION_CODE,
                "code": "SplxlOBeZQQYbYS6WxSbIA",
                "tx_code": "493536",
            }
        )


def test_the_authorization_code_grant_needs_its_code():
    with pytest.raises(ValidationError, match="code"):
        TokenRequest.model_validate({"grant_type": GRANT_TYPE_AUTHORIZATION_CODE})


def test_a_token_response():
    response = TokenResponse.model_validate(
        {
            "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NiJ9",
            "token_type": "Bearer",
            "expires_in": 86400,
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "credential_configuration_id": "StudentCredential",
                    "credential_identifiers": ["StudentCredential-2026"],
                }
            ],
        }
    )

    assert response.token_type == "Bearer"
    assert response.authorization_details is not None
    assert response.authorization_details[0].credential_identifiers == [
        "StudentCredential-2026"
    ]
