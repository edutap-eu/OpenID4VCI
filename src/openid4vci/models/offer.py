"""Credential Offer (Section 4).

The Credential Offer is how issuance starts: the Credential Issuer hands the
Wallet an object naming itself, the credential configurations on offer and the
grant types the Wallet may use. It travels as a query parameter on a URI the
Wallet is registered for -- rendered as a link the End-User taps, or as a QR
code they scan.

It goes either by value, with the whole object percent-encoded into the query,
or by reference, with a URL the Wallet fetches. A QR code usually carries the
reference, because the object rarely fits.
"""

from .common import CredentialIssuerIdentifier
from .common import Model
from pydantic import Field
from typing import Literal
from urllib.parse import urlencode

import json


#: Grant type identifiers usable in a Credential Offer (Section 4.1.1).
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

#: URI scheme a Wallet deployed as a native app registers for Credential Offers.
OFFER_URI_SCHEME = "openid-credential-offer://"


class TransactionCode(Model):
    """Requirements for a Transaction Code (Section 4.1.1).

    Present, even empty, means a Transaction Code is required. Absent means it
    is not; that is the default. The code binds the Pre-Authorized Code to one
    transaction, so that someone who photographed the QR code over the
    End-User's shoulder cannot replay it.
    """

    input_mode: Literal["numeric", "text"] = "numeric"
    length: int | None = None
    description: str | None = Field(default=None, max_length=300)


class AuthorizationCodeGrant(Model):
    """Parameters of the ``authorization_code`` grant in an offer."""

    issuer_state: str | None = None
    authorization_server: str | None = None


class PreAuthorizedCodeGrant(Model):
    """Parameters of the pre-authorized code grant in an offer.

    The code is short lived and single use.
    """

    pre_authorized_code: str = Field(alias="pre-authorized_code")
    tx_code: TransactionCode | None = None
    authorization_server: str | None = None


class Grants(Model):
    """Grant types the Issuer's Authorization Server will process for this offer.

    Every grant is a name/value pair whose name is the grant type identifier.
    One of them is a URN, which is why both fields carry an alias.
    """

    authorization_code: AuthorizationCodeGrant | None = Field(
        default=None,
        alias=GRANT_TYPE_AUTHORIZATION_CODE,
    )
    pre_authorized_code: PreAuthorizedCodeGrant | None = Field(
        default=None,
        alias=GRANT_TYPE_PRE_AUTHORIZED_CODE,
    )


class CredentialOffer(Model):
    """The Credential Offer object (Section 4.1.1)."""

    credential_issuer: CredentialIssuerIdentifier
    credential_configuration_ids: list[str] = Field(min_length=1)
    grants: Grants | None = None


def offer_uri_by_value(
    offer: CredentialOffer,
    scheme: str = OFFER_URI_SCHEME,
) -> str:
    """Return a URI carrying the offer itself in the ``credential_offer`` parameter.

    :param offer: the Credential Offer to hand to the Wallet.
    :param scheme: URI scheme the target Wallet is registered for. Ecosystems
        register their own, so this is overridable.
    """
    query = urlencode({"credential_offer": json.dumps(offer.to_dict())})
    return f"{scheme}?{query}"


def offer_uri_by_reference(
    offer_uri: str,
    scheme: str = OFFER_URI_SCHEME,
) -> str:
    """Return a URI referencing the offer via the ``credential_offer_uri`` parameter.

    Use this when the offer is large or has to fit into a QR code.

    :param offer_uri: URL the Wallet fetches the offer from. Must use https.
    :param scheme: URI scheme the target Wallet is registered for.
    :raises ValueError: if ``offer_uri`` does not use the https scheme.
    """
    if not offer_uri.startswith("https://"):
        raise ValueError(
            f"A credential_offer_uri must use the https scheme, got: {offer_uri!r}"
        )
    query = urlencode({"credential_offer_uri": offer_uri})
    return f"{scheme}?{query}"
