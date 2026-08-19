"""Credential Issuer Metadata, OpenID4VCI 1.0 Section 12."""

from openid4vci.models.metadata import AuthorizationServerMetadata
from openid4vci.models.metadata import credential_issuer_metadata_url
from openid4vci.models.metadata import CredentialIssuerMetadata
from pydantic import ValidationError

import pytest


# Structure taken from the non-normative example in Section 12.2.3; the values
# are our own.
ISSUER_METADATA = {
    "credential_issuer": "https://issuer.example.edu",
    "credential_endpoint": "https://issuer.example.edu/credential",
    "nonce_endpoint": "https://issuer.example.edu/nonce",
    "credential_configurations_supported": {
        "StudentCredential": {
            "format": "dc+sd-jwt",
            "scope": "StudentCredential",
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"],
                    "key_attestations_required": {
                        "key_storage": ["iso_18045_moderate"],
                    },
                }
            },
            "vct": "StudentCredential",
            "credential_metadata": {
                "display": [
                    {
                        "name": "Student Credential",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
                "claims": [
                    {"path": ["given_name"], "mandatory": True},
                    {"path": ["address", "locality"]},
                ],
            },
        }
    },
}


def test_parses_issuer_metadata():
    metadata = CredentialIssuerMetadata.model_validate(ISSUER_METADATA)

    assert metadata.credential_issuer == "https://issuer.example.edu"
    configuration = metadata.credential_configurations_supported["StudentCredential"]
    assert configuration.format == "dc+sd-jwt"
    assert configuration.proof_types_supported is not None
    assert configuration.proof_types_supported[
        "jwt"
    ].proof_signing_alg_values_supported == ["ES256"]


def test_format_specific_parameters_survive():
    """`vct` belongs to the SD-JWT VC profile and sits on the configuration."""
    metadata = CredentialIssuerMetadata.model_validate(ISSUER_METADATA)

    configuration = metadata.credential_configurations_supported["StudentCredential"]
    assert configuration.model_extra is not None
    assert configuration.model_extra["vct"] == "StudentCredential"
    assert metadata.to_dict() == ISSUER_METADATA


def test_proof_types_require_a_binding_method():
    """Section 12.2.3: present if cryptographic_binding_methods_supported is, omitted otherwise."""
    broken = {
        "credential_issuer": "https://issuer.example.edu",
        "credential_endpoint": "https://issuer.example.edu/credential",
        "credential_configurations_supported": {
            "StudentCredential": {
                "format": "dc+sd-jwt",
                "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                },
            }
        },
    }

    with pytest.raises(
        ValidationError, match="cryptographic_binding_methods_supported"
    ):
        CredentialIssuerMetadata.model_validate(broken)


def test_a_binding_method_requires_proof_types():
    broken = {
        "credential_issuer": "https://issuer.example.edu",
        "credential_endpoint": "https://issuer.example.edu/credential",
        "credential_configurations_supported": {
            "StudentCredential": {
                "format": "dc+sd-jwt",
                "cryptographic_binding_methods_supported": ["jwk"],
            }
        },
    }

    with pytest.raises(ValidationError, match="proof_types_supported"):
        CredentialIssuerMetadata.model_validate(broken)


def test_batch_size_must_be_two_or_greater():
    with pytest.raises(ValidationError):
        CredentialIssuerMetadata.model_validate(
            {**ISSUER_METADATA, "batch_credential_issuance": {"batch_size": 1}}
        )


def test_only_one_display_object_per_locale():
    """Section 12.2.3: there MUST be only one object for each language identifier."""
    with pytest.raises(ValidationError, match="locale"):
        CredentialIssuerMetadata.model_validate(
            {
                **ISSUER_METADATA,
                "display": [
                    {"name": "Example University", "locale": "en-US"},
                    {"name": "Beispiel-Universitaet", "locale": "en-US"},
                ],
            }
        )


def test_two_display_objects_for_different_locales_are_fine():
    metadata = CredentialIssuerMetadata.model_validate(
        {
            **ISSUER_METADATA,
            "display": [
                {"name": "Example University", "locale": "en-US"},
                {"name": "Beispiel-Universitaet", "locale": "de-DE"},
            ],
        }
    )

    assert metadata.display is not None
    assert len(metadata.display) == 2


def test_endpoints_must_use_https():
    with pytest.raises(ValidationError):
        CredentialIssuerMetadata.model_validate(
            {
                **ISSUER_METADATA,
                "credential_endpoint": "http://issuer.example.edu/credential",
            }
        )


def test_authorization_servers_must_not_be_empty_when_present():
    with pytest.raises(ValidationError):
        CredentialIssuerMetadata.model_validate(
            {**ISSUER_METADATA, "authorization_servers": []}
        )


def test_authorization_server_metadata_carries_the_hyphenated_parameter():
    metadata = AuthorizationServerMetadata.model_validate(
        {
            "issuer": "https://issuer.example.edu",
            "pre-authorized_grant_anonymous_access_supported": True,
        }
    )

    assert metadata.pre_authorized_grant_anonymous_access_supported is True
    assert metadata.to_dict()["pre-authorized_grant_anonymous_access_supported"] is True


def test_anonymous_access_defaults_to_false():
    metadata = AuthorizationServerMetadata.model_validate(
        {"issuer": "https://issuer.example.edu"}
    )

    assert metadata.pre_authorized_grant_anonymous_access_supported is False


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        (
            "https://tenant.issuer.example.edu",
            "https://tenant.issuer.example.edu/.well-known/openid-credential-issuer",
        ),
        (
            "https://issuer.example.edu/tenant",
            "https://issuer.example.edu/.well-known/openid-credential-issuer/tenant",
        ),
    ],
)
def test_the_well_known_string_goes_between_host_and_path(identifier, expected):
    """Section 12.2: inserted between the host component and the path component.

    This is the step that trips implementations up: the well-known string is
    inserted, not appended, so a tenant path ends up after it.
    """
    assert credential_issuer_metadata_url(identifier) == expected
