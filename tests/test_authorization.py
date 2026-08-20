"""The pre-authorized code flow, OpenID4VCI 1.0 Section 6."""

from openid4vci.authorization import InMemoryAuthorizationServer
from openid4vci.authorization import TokenError
from openid4vci.exceptions import OAuthErrorCode
from openid4vci.models.common import GRANT_TYPE_AUTHORIZATION_CODE
from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
from openid4vci.models.oauth import TokenRequest

import pytest


ISSUER = "https://issuer.example.edu"
CONFIGURATION = "StudentCredential"


class Clock:
    def __init__(self, now=1_766_000_000):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def server(clock):
    return InMemoryAuthorizationServer(credential_issuer=ISSUER, now=clock)


def token_request(code, **extra):
    return TokenRequest.model_validate(
        {
            "grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE,
            "pre-authorized_code": code,
            **extra,
        }
    )


# --- offering ---------------------------------------------------------------


def test_an_offer_names_the_issuer_and_the_configuration(server):
    offer, _ = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    assert offer.credential_issuer == ISSUER
    assert offer.credential_configuration_ids == [CONFIGURATION]
    assert offer.grants is not None
    assert offer.grants.pre_authorized_code is not None


def test_the_code_in_the_offer_is_the_code_that_redeems(server):
    offer, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    assert offer.grants.pre_authorized_code.pre_authorized_code == code


def test_a_transaction_code_is_announced_in_the_offer(server):
    offer, _ = server.offer(
        subject="erika",
        credential_configuration_ids=[CONFIGURATION],
        tx_code="493536",
        tx_code_description="Sent to your university mail address",
    )

    tx_code = offer.grants.pre_authorized_code.tx_code
    assert tx_code is not None
    assert tx_code.length == 6
    assert tx_code.input_mode == "numeric"
    assert "493536" not in offer.to_dict()["grants"][
        GRANT_TYPE_PRE_AUTHORIZED_CODE
    ].get("tx_code", {}).get("description", ""), (
        "the offer describes the code, it does not carry it"
    )


def test_a_non_numeric_transaction_code_is_announced_as_text(server):
    offer, _ = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION], tx_code="AB12-CD"
    )

    assert offer.grants.pre_authorized_code.tx_code.input_mode == "text"


# --- redeeming --------------------------------------------------------------


def test_redeeming_yields_an_access_token(server):
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    response = server.redeem(token_request(code))

    assert response.token_type == "Bearer"
    assert response.access_token
    assert response.expires_in and response.expires_in > 0


def test_the_token_response_says_which_credentials_it_covers(server):
    """Section 6.2: credential_identifiers is what the Wallet sends back."""
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    response = server.redeem(token_request(code))

    assert response.authorization_details is not None
    detail = response.authorization_details[0]
    assert detail.credential_configuration_id == CONFIGURATION
    assert len(detail.credential_identifiers) == 1


def test_the_access_token_resolves_to_what_was_granted(server):
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )
    response = server.redeem(token_request(code))

    grant = server.grant_for(response.access_token)

    assert grant is not None
    assert grant.subject == "erika"
    assert grant.credential_configuration_ids == [CONFIGURATION]


def test_an_unknown_code_is_refused(server):
    with pytest.raises(TokenError) as caught:
        server.redeem(token_request("never-issued"))

    assert caught.value.code is OAuthErrorCode.INVALID_GRANT


def test_a_code_is_single_use(server):
    """Section 4.1.1: the code MUST be short lived and single use."""
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )
    server.redeem(token_request(code))

    with pytest.raises(TokenError) as caught:
        server.redeem(token_request(code))

    assert caught.value.code is OAuthErrorCode.INVALID_GRANT


def test_a_code_expires(server, clock):
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    clock.now += 601

    with pytest.raises(TokenError):
        server.redeem(token_request(code))


# --- transaction codes ------------------------------------------------------


def test_the_transaction_code_must_match(server):
    """Section 6.3: the wrong code is invalid_grant, not invalid_request."""
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION], tx_code="493536"
    )

    with pytest.raises(TokenError) as caught:
        server.redeem(token_request(code, tx_code="000000"))

    assert caught.value.code is OAuthErrorCode.INVALID_GRANT


def test_a_missing_transaction_code_is_a_bad_request(server):
    """Section 6.3: expected but not provided is invalid_request.

    The distinction is not cosmetic. invalid_request says the Wallet built the
    request wrongly; invalid_grant says the End-User typed the wrong digits.
    """
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION], tx_code="493536"
    )

    with pytest.raises(TokenError) as caught:
        server.redeem(token_request(code))

    assert caught.value.code is OAuthErrorCode.INVALID_REQUEST


def test_an_unexpected_transaction_code_is_also_a_bad_request(server):
    """Section 6.3: not expected but provided is invalid_request too."""
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    with pytest.raises(TokenError) as caught:
        server.redeem(token_request(code, tx_code="493536"))

    assert caught.value.code is OAuthErrorCode.INVALID_REQUEST


def test_a_correct_transaction_code_lets_the_exchange_through(server):
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION], tx_code="493536"
    )

    response = server.redeem(token_request(code, tx_code="493536"))

    assert response.access_token


# --- other grants -----------------------------------------------------------


def test_another_grant_type_is_refused(server):
    """This server implements one flow, and says so rather than half-doing another."""
    request = TokenRequest.model_validate(
        {"grant_type": GRANT_TYPE_AUTHORIZATION_CODE, "code": "whatever"}
    )

    with pytest.raises(TokenError) as caught:
        server.redeem(request)

    assert caught.value.code is OAuthErrorCode.UNSUPPORTED_GRANT_TYPE


def test_anonymous_redemption_is_allowed_by_default(server):
    """Section 6.1: a client_id is not required for this grant.

    A Wallet that never registered with us is the normal case, not an
    exception: the pre-authorized code is what carries the authorization.
    """
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    assert server.redeem(token_request(code)).access_token


def test_anonymous_redemption_can_be_switched_off(clock):
    server = InMemoryAuthorizationServer(
        credential_issuer=ISSUER, allow_anonymous=False, now=clock
    )
    _, code = server.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )

    with pytest.raises(TokenError) as caught:
        server.redeem(token_request(code))

    assert caught.value.code is OAuthErrorCode.INVALID_CLIENT
