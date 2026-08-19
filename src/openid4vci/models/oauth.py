"""Authorization Endpoint (Section 5) and Token Endpoint (Section 6).

Both are ordinary OAuth 2.0 endpoints. This specification adds three things to
them: the ``authorization_details`` type ``openid_credential``, the
``issuer_state`` a Credential Offer may carry into the Authorization Request,
and the pre-authorized code grant with its Transaction Code.

The Authorization Server may well be a deployment we do not control, which is
why these models describe the additions and keep the rest rather than
attempting to restate RFC 6749 and RFC 9396.
"""

from .common import GRANT_TYPE_AUTHORIZATION_CODE
from .common import GRANT_TYPE_PRE_AUTHORIZED_CODE
from .common import Model
from pydantic import Field
from pydantic import model_validator
from typing import Literal


#: The authorization details type this specification introduces (Section 5.1.1).
AUTHORIZATION_DETAILS_TYPE = "openid_credential"


class AuthorizationDetailsClaim(Model):
    """A claims description as used in authorization details (Section 5.1.2)."""

    path: list[str | int | None] = Field(min_length=1)


class AuthorizationDetail(Model):
    """An ``openid_credential`` authorization detail (Section 5.1.1).

    The specification notes that this type is never invalid due to unknown
    fields, which the base model already provides.
    """

    type: Literal["openid_credential"] = AUTHORIZATION_DETAILS_TYPE
    credential_configuration_id: str
    claims: list[AuthorizationDetailsClaim] | None = Field(default=None, min_length=1)


class IssuedAuthorizationDetail(AuthorizationDetail):
    """An authorization detail as returned in the Token Response (Section 6.2).

    Adds the identifiers of the credential datasets the access token now
    covers. The Wallet sends one of them back as ``credential_identifier`` in
    the Credential Request.
    """

    credential_identifiers: list[str] = Field(min_length=1)


class AuthorizationRequest(Model):
    """The parameters of an Authorization Request that concern issuance (Section 5.1).

    Sent as query parameters, not as a body. Only the issuance-relevant
    parameters are named; the OAuth 2.0 ones the Authorization Server handles
    are kept as they arrive.
    """

    issuer_state: str | None = None
    scope: str | None = None
    authorization_details: list[AuthorizationDetail] | None = Field(
        default=None, min_length=1
    )


class TokenRequest(Model):
    """A Token Request (Section 6.1).

    Sent form-encoded rather than as JSON; this models the parameters, not the
    encoding.
    """

    grant_type: str
    code: str | None = None
    code_verifier: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    pre_authorized_code: str | None = Field(default=None, alias="pre-authorized_code")
    tx_code: str | None = None
    authorization_details: list[AuthorizationDetail] | None = Field(
        default=None, min_length=1
    )

    @model_validator(mode="after")
    def _validate_grant(self) -> "TokenRequest":
        """Each grant type brings its own required parameter.

        The Transaction Code is checked in the other direction too: it belongs
        to the pre-authorized flow alone, and the specification makes sending
        one where none is expected an `invalid_request`.
        """
        if self.grant_type == GRANT_TYPE_PRE_AUTHORIZED_CODE:
            if not self.pre_authorized_code:
                raise ValueError(
                    "pre-authorized_code is required for grant type "
                    f"{GRANT_TYPE_PRE_AUTHORIZED_CODE}"
                )
        elif self.tx_code is not None:
            raise ValueError(
                "tx_code must only be used with grant type "
                f"{GRANT_TYPE_PRE_AUTHORIZED_CODE}"
            )
        if self.grant_type == GRANT_TYPE_AUTHORIZATION_CODE and not self.code:
            raise ValueError(
                f"code is required for grant type {GRANT_TYPE_AUTHORIZATION_CODE}"
            )
        return self


class TokenResponse(Model):
    """A Token Response (Section 6.2)."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    authorization_details: list[IssuedAuthorizationDetail] | None = Field(
        default=None, min_length=1
    )
