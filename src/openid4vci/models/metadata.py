"""Credential Issuer Metadata and Authorization Server Metadata (Section 12).

Two separate documents at two separate well-known locations:

* ``/.well-known/openid-credential-issuer`` -- our own metadata, most notably
  ``credential_configurations_supported``, which is what a Wallet reads to
  learn which credentials we offer and in which format.
* ``/.well-known/oauth-authorization-server`` (RFC 8414) -- the Authorization
  Server. It may be us or a separate deployment; the metadata parameter
  ``authorization_servers`` is what ties the two together.

Format profiles add their own parameters to a credential configuration --
``vct`` for SD-JWT VC, ``doctype`` for ISO mdoc. They are not enumerated here;
the base model keeps them.
"""

from .common import CredentialIssuerIdentifier
from .common import Model
from pydantic import Field
from pydantic import model_validator
from typing import Annotated
from typing import Any
from urllib.parse import urlparse


#: Path segment inserted between host and path to reach the issuer metadata.
WELL_KNOWN_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"

#: Well-known path of the OAuth 2.0 Authorization Server metadata (RFC 8414).
WELL_KNOWN_AUTHORIZATION_SERVER = "/.well-known/oauth-authorization-server"


def _check_https_url(value: str) -> str:
    """Endpoint URLs must use https and may carry port, path and query."""
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise ValueError(f"Endpoint URLs must use the https scheme, got: {value!r}")
    if not parsed.netloc:
        raise ValueError(f"Endpoint URLs must contain a host, got: {value!r}")
    return value


HttpsUrl = Annotated[str, Field(json_schema_extra={"format": "uri"})]


def _one_object_per_locale(displays: list[Any] | None) -> None:
    """Reject two display objects claiming the same language.

    The specification says there MUST be only one object per language
    identifier. Two would leave a Wallet to pick, and different Wallets would
    pick differently.
    """
    if not displays:
        return
    locales = [display.locale for display in displays]
    duplicates = {locale for locale in locales if locales.count(locale) > 1}
    if duplicates:
        raise ValueError(
            "There must be only one display object per locale, "
            f"got more than one for: {sorted(str(locale) for locale in duplicates)}"
        )


class Logo(Model):
    """Logo of an issuer or a credential."""

    uri: str
    alt_text: str | None = None


class BackgroundImage(Model):
    """Background image of a credential."""

    uri: str


class IssuerDisplay(Model):
    """Display properties of the Credential Issuer for one language."""

    name: str | None = None
    locale: str | None = None
    logo: Logo | None = None


class CredentialDisplay(Model):
    """Display properties of a credential for one language."""

    name: str
    locale: str | None = None
    logo: Logo | None = None
    description: str | None = None
    background_color: str | None = None
    background_image: BackgroundImage | None = None
    text_color: str | None = None


class ClaimDisplay(Model):
    """Display properties of a single claim for one language."""

    name: str | None = None
    locale: str | None = None


class ClaimsDescription(Model):
    """How one claim of the credential is displayed (Section 12.2.4)."""

    path: list[str | int | None] = Field(min_length=1)
    mandatory: bool = False
    display: list[ClaimDisplay] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_display_locales(self) -> "ClaimsDescription":
        _one_object_per_locale(self.display)
        return self


class CredentialMetadata(Model):
    """Information relevant to the usage and display of issued credentials.

    Format-specific mechanisms, such as SD-JWT VC display metadata, take
    precedence over this; it is the fallback.
    """

    display: list[CredentialDisplay] | None = Field(default=None, min_length=1)
    claims: list[ClaimsDescription] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_display_locales(self) -> "CredentialMetadata":
        _one_object_per_locale(self.display)
        return self


class KeyAttestationsRequired(Model):
    """Key attestation the Issuer expects inside the proofs (Appendix D).

    An empty object is meaningful: it demands an attestation without further
    constraints.
    """

    key_storage: list[str] | None = Field(default=None, min_length=1)
    user_authentication: list[str] | None = Field(default=None, min_length=1)


class ProofTypeMetadata(Model):
    """What the Issuer accepts for one key proof type."""

    proof_signing_alg_values_supported: list[str] = Field(min_length=1)
    key_attestations_required: KeyAttestationsRequired | None = None


class CredentialConfiguration(Model):
    """One entry of ``credential_configurations_supported`` (Section 12.2.3).

    Format profiles add parameters here -- ``vct``, ``doctype`` and others --
    which the base model keeps rather than rejecting.
    """

    format: str
    scope: str | None = None
    credential_signing_alg_values_supported: list[str] | None = Field(
        default=None, min_length=1
    )
    cryptographic_binding_methods_supported: list[str] | None = Field(
        default=None, min_length=1
    )
    proof_types_supported: dict[str, ProofTypeMetadata] | None = None
    credential_metadata: CredentialMetadata | None = None

    @model_validator(mode="after")
    def _binding_and_proofs_go_together(self) -> "CredentialConfiguration":
        """Key binding and key proofs are one decision, stated twice.

        The specification ties the two parameters to each other in both
        directions: proof types MUST be present if a binding method is, and
        omitted otherwise. A configuration that declares only one of them
        leaves a Wallet unable to tell whether a proof is expected.
        """
        binding = self.cryptographic_binding_methods_supported
        proofs = self.proof_types_supported
        if binding is not None and proofs is None:
            raise ValueError(
                "proof_types_supported must be present when "
                "cryptographic_binding_methods_supported is present"
            )
        if proofs is not None and binding is None:
            raise ValueError(
                "proof_types_supported must be omitted when "
                "cryptographic_binding_methods_supported is absent"
            )
        return self


class CredentialRequestEncryption(Model):
    """Encryption of the Credential Request on top of TLS."""

    jwks: dict[str, Any]
    enc_values_supported: list[str] = Field(min_length=1)
    zip_values_supported: list[str] | None = Field(default=None, min_length=1)
    encryption_required: bool


class CredentialResponseEncryption(Model):
    """Encryption of the Credential Response on top of TLS."""

    alg_values_supported: list[str] = Field(min_length=1)
    enc_values_supported: list[str] = Field(min_length=1)
    zip_values_supported: list[str] | None = Field(default=None, min_length=1)
    encryption_required: bool


class BatchCredentialIssuance(Model):
    """Support for more than one key proof in a single Credential Request."""

    batch_size: int = Field(ge=2)


class CredentialIssuerMetadata(Model):
    """The Credential Issuer Metadata document (Section 12.2.3)."""

    credential_issuer: CredentialIssuerIdentifier
    authorization_servers: list[str] | None = Field(default=None, min_length=1)
    credential_endpoint: HttpsUrl
    nonce_endpoint: HttpsUrl | None = None
    deferred_credential_endpoint: HttpsUrl | None = None
    notification_endpoint: HttpsUrl | None = None
    credential_request_encryption: CredentialRequestEncryption | None = None
    credential_response_encryption: CredentialResponseEncryption | None = None
    batch_credential_issuance: BatchCredentialIssuance | None = None
    display: list[IssuerDisplay] | None = Field(default=None, min_length=1)
    credential_configurations_supported: dict[str, CredentialConfiguration]

    @model_validator(mode="after")
    def _validate_urls_and_locales(self) -> "CredentialIssuerMetadata":
        for name in (
            "credential_endpoint",
            "nonce_endpoint",
            "deferred_credential_endpoint",
            "notification_endpoint",
        ):
            value = getattr(self, name)
            if value is not None:
                _check_https_url(value)
        _one_object_per_locale(self.display)
        return self


class AuthorizationServerMetadata(Model):
    """The OAuth 2.0 Authorization Server metadata parameter this specification adds.

    Only the added parameter is modelled; everything else RFC 8414 defines is
    kept by the base model, because the Authorization Server may well be a
    deployment we do not control.
    """

    issuer: str
    pre_authorized_grant_anonymous_access_supported: bool = Field(
        default=False,
        alias="pre-authorized_grant_anonymous_access_supported",
    )


def credential_issuer_metadata_url(identifier: str) -> str:
    """Return the URL the issuer metadata is published at (Section 12.2).

    The well-known string is *inserted between the host component and the path
    component*, not appended. An issuer identified by
    ``https://issuer.example.edu/tenant`` therefore publishes at
    ``https://issuer.example.edu/.well-known/openid-credential-issuer/tenant``.

    :param identifier: the Credential Issuer Identifier.
    """
    parsed = urlparse(identifier)
    return (
        f"{parsed.scheme}://{parsed.netloc}"
        f"{WELL_KNOWN_CREDENTIAL_ISSUER}{parsed.path.rstrip('/')}"
    )
