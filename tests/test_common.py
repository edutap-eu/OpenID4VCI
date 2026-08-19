"""Shared data types, OpenID4VCI 1.0 Section 12.1."""

from openid4vci.models.common import CredentialIssuerIdentifier
from pydantic import TypeAdapter
from pydantic import ValidationError

import pytest


identifier = TypeAdapter(CredentialIssuerIdentifier)


def test_the_identifier_is_kept_verbatim():
    """Section 12.2 compares it with no normalization, so we must not normalize.

    A URL type would append a trailing slash here, and a Wallet doing the
    string comparison the specification prescribes would then discard our
    metadata.
    """
    assert identifier.validate_python("https://issuer.example.edu") == (
        "https://issuer.example.edu"
    )


def test_a_path_component_is_allowed_and_kept():
    assert identifier.validate_python("https://issuer.example.edu/tenant") == (
        "https://issuer.example.edu/tenant"
    )


def test_case_is_significant():
    assert identifier.validate_python("https://Issuer.Example.edu/Tenant") == (
        "https://Issuer.Example.edu/Tenant"
    )


@pytest.mark.parametrize(
    "value",
    [
        "http://issuer.example.edu",
        "https:///no-host",
        "https://issuer.example.edu?tenant=1",
        "https://issuer.example.edu#fragment",
    ],
)
def test_rejects_what_the_specification_excludes(value):
    with pytest.raises(ValidationError):
        identifier.validate_python(value)
