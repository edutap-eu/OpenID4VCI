"""Credential Offer, OpenID4VCI 1.0 Section 4."""

from openid4vci.models.offer import CredentialOffer
from openid4vci.models.offer import GRANT_TYPE_PRE_AUTHORIZED_CODE
from openid4vci.models.offer import offer_uri_by_reference
from openid4vci.models.offer import offer_uri_by_value
from pydantic import ValidationError
from urllib.parse import parse_qs
from urllib.parse import urlparse

import json
import pytest


# Structure taken from the non-normative example in Section 4.1 of the
# specification; the values are our own.
OFFER_PRE_AUTHORIZED = {
    "credential_issuer": "https://credential-issuer.example.edu",
    "credential_configuration_ids": [
        "UniversityDegreeCredential",
        "org.iso.18013.5.1.mDL",
    ],
    "grants": {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
            "tx_code": {
                "length": 4,
                "input_mode": "numeric",
                "description": "Please provide the one-time code sent by e-mail",
            },
        }
    },
}


def test_parses_a_pre_authorized_code_offer():
    offer = CredentialOffer.model_validate(OFFER_PRE_AUTHORIZED)

    assert str(offer.credential_issuer) == "https://credential-issuer.example.edu"
    assert offer.credential_configuration_ids == [
        "UniversityDegreeCredential",
        "org.iso.18013.5.1.mDL",
    ]
    assert offer.grants is not None
    assert offer.grants.pre_authorized_code is not None
    assert (
        offer.grants.pre_authorized_code.pre_authorized_code == "oaKazRN8I0IbtZ0C7JuMn5"
    )
    assert offer.grants.pre_authorized_code.tx_code is not None
    assert offer.grants.pre_authorized_code.tx_code.length == 4


def test_serializes_back_to_the_wire_names():
    """The grant type URN and the hyphen in pre-authorized_code must survive."""
    offer = CredentialOffer.model_validate(OFFER_PRE_AUTHORIZED)

    assert offer.to_dict() == OFFER_PRE_AUTHORIZED


def test_transaction_code_input_mode_defaults_to_numeric():
    offer = CredentialOffer.model_validate(
        {
            "credential_issuer": "https://credential-issuer.example.edu",
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            "grants": {
                GRANT_TYPE_PRE_AUTHORIZED_CODE: {
                    "pre-authorized_code": "adhjhdjajkdkhjhdj",
                    "tx_code": {},
                }
            },
        }
    )

    assert offer.grants is not None
    grant = offer.grants.pre_authorized_code
    assert grant is not None
    assert grant.tx_code is not None
    assert grant.tx_code.input_mode == "numeric"
    assert grant.tx_code.length is None


def test_transaction_code_description_is_capped_at_300_characters():
    with pytest.raises(ValidationError):
        CredentialOffer.model_validate(
            {
                "credential_issuer": "https://credential-issuer.example.edu",
                "credential_configuration_ids": ["UniversityDegreeCredential"],
                "grants": {
                    GRANT_TYPE_PRE_AUTHORIZED_CODE: {
                        "pre-authorized_code": "adhjhdjajkdkhjhdj",
                        "tx_code": {"description": "x" * 301},
                    }
                },
            }
        )


def test_credential_configuration_ids_must_not_be_empty():
    with pytest.raises(ValidationError):
        CredentialOffer.model_validate(
            {
                "credential_issuer": "https://credential-issuer.example.edu",
                "credential_configuration_ids": [],
            }
        )


def test_unknown_parameters_are_kept_rather_than_rejected():
    """Section 4.1.1: additional parameters may be defined."""
    offer = CredentialOffer.model_validate(
        {**OFFER_PRE_AUTHORIZED, "something_new": "value"}
    )

    assert offer.to_dict()["something_new"] == "value"


def test_offer_by_value_percent_encodes_the_offer_into_the_query():
    offer = CredentialOffer.model_validate(OFFER_PRE_AUTHORIZED)

    uri = offer_uri_by_value(offer)

    assert uri.startswith("openid-credential-offer://?")
    query = parse_qs(urlparse(uri).query)
    assert json.loads(query["credential_offer"][0]) == OFFER_PRE_AUTHORIZED


def test_offer_by_reference_carries_the_url_instead_of_the_object():
    uri = offer_uri_by_reference("https://server.example.edu/offer/GkurKxf5T0Y")

    query = parse_qs(urlparse(uri).query)
    assert query["credential_offer_uri"] == [
        "https://server.example.edu/offer/GkurKxf5T0Y"
    ]
    assert "credential_offer" not in query


def test_offer_by_reference_requires_https():
    """Section 4.1: the URI is a URL using the https scheme."""
    with pytest.raises(ValueError):
        offer_uri_by_reference("http://server.example.edu/offer/GkurKxf5T0Y")


def test_a_custom_scheme_can_be_used():
    offer = CredentialOffer.model_validate(OFFER_PRE_AUTHORIZED)

    uri = offer_uri_by_value(offer, scheme="haip://")

    assert uri.startswith("haip://?")
