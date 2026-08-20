"""The pre-authorized code flow (Sections 4.1.1 and 6).

Two flows lead to an access token. The authorization code flow sends the
End-User through an OAuth Authorization Server; the pre-authorized code flow
does not, because the issuer has already established who it is talking to by
other means -- a login on our own portal, a desk, a letter.

That second flow is what this module implements, and it is the one that fits
an issuer which already authenticates its users. Authentication stays outside:
this module is handed a subject and decides nothing about who that is.

The authorization code flow is deliberately absent. It belongs to an
Authorization Server, and half of one is worse than none.
"""

from .exceptions import OAuthErrorCode
from .exceptions import OpenID4VCIError
from .models.common import CredentialIssuerIdentifier
from .models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
from .models.oauth import IssuedAuthorizationDetail
from .models.oauth import TokenRequest
from .models.oauth import TokenResponse
from .models.offer import CredentialOffer
from collections.abc import Callable
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field

import secrets
import time


#: How long a pre-authorized code stays redeemable, in seconds.
#:
#: The specification says "short lived" without a number. Ten minutes is long
#: enough for a person to move from a screen to their phone, and short enough
#: that a code photographed over their shoulder is usually already dead.
DEFAULT_CODE_TTL = 600

#: How long an issued access token stays valid, in seconds.
DEFAULT_TOKEN_TTL = 3600


class TokenError(OpenID4VCIError):
    """A Token Request cannot be honoured."""

    def __init__(self, code: OAuthErrorCode, description: str) -> None:
        super().__init__(f"{code.value}: {description}")
        self.code = code
        self.description = description


@dataclass
class Grant:
    """What a pre-authorized code, and later an access token, stands for.

    :param subject: whoever the issuer authenticated. Opaque here.
    :param credential_configuration_ids: what may be issued.
    :param credential_identifiers: the datasets, per configuration.
    :param tx_code: the Transaction Code the End-User must present, if any.
    :param expires_at: when this stops being redeemable.
    """

    subject: str
    credential_configuration_ids: list[str]
    credential_identifiers: dict[str, list[str]] = field(default_factory=dict)
    tx_code: str | None = None
    expires_at: float = 0.0


class InMemoryAuthorizationServer:
    """A pre-authorized code flow with its state in the process.

    Suitable for a single-process deployment and for tests. Anything larger
    replaces the two stores; the rules encoded here do not change with them.
    """

    def __init__(
        self,
        credential_issuer: CredentialIssuerIdentifier,
        code_ttl_seconds: int = DEFAULT_CODE_TTL,
        token_ttl_seconds: int = DEFAULT_TOKEN_TTL,
        allow_anonymous: bool = True,
        now: Callable[[], float] = time.time,
    ) -> None:
        """
        :param credential_issuer: our identifier, written into every offer.
        :param code_ttl_seconds: lifetime of a pre-authorized code.
        :param token_ttl_seconds: lifetime of an issued access token.
        :param allow_anonymous: whether a Token Request may omit ``client_id``.
            True by default, because a Wallet that never registered with us is
            the normal case in this flow rather than an exception.
        :param now: clock, injectable so tests need not sleep.
        """
        self.credential_issuer = credential_issuer
        self.code_ttl = code_ttl_seconds
        self.token_ttl = token_ttl_seconds
        self.allow_anonymous = allow_anonymous
        self._now = now
        self._codes: dict[str, Grant] = {}
        self._tokens: dict[str, Grant] = {}

    def offer(
        self,
        subject: str,
        credential_configuration_ids: Sequence[str],
        tx_code: str | None = None,
        tx_code_description: str | None = None,
    ) -> tuple[CredentialOffer, str]:
        """Create a Credential Offer and the code that redeems it.

        :param subject: whoever the issuer authenticated.
        :param credential_configuration_ids: what is being offered.
        :param tx_code: a Transaction Code the End-User must present. Deliver
            it over a different channel than the offer -- that is the entire
            point of it.
        :param tx_code_description: how the End-User obtains the code, shown
            next to the input field.
        :returns: the offer, and the pre-authorized code it carries.
        """
        code = secrets.token_urlsafe(24)
        self._codes[code] = Grant(
            subject=subject,
            credential_configuration_ids=list(credential_configuration_ids),
            credential_identifiers={
                configuration_id: [f"{configuration_id}-{secrets.token_urlsafe(9)}"]
                for configuration_id in credential_configuration_ids
            },
            tx_code=tx_code,
            expires_at=self._now() + self.code_ttl,
        )

        grant: dict[str, object] = {"pre-authorized_code": code}
        if tx_code is not None:
            # The offer describes the code so the Wallet can render an input
            # field; it never carries the code itself.
            announcement: dict[str, object] = {
                "length": len(tx_code),
                "input_mode": "numeric" if tx_code.isdigit() else "text",
            }
            if tx_code_description is not None:
                announcement["description"] = tx_code_description
            grant["tx_code"] = announcement

        offer = CredentialOffer.model_validate(
            {
                "credential_issuer": self.credential_issuer,
                "credential_configuration_ids": list(credential_configuration_ids),
                "grants": {GRANT_TYPE_PRE_AUTHORIZED_CODE: grant},
            }
        )
        return offer, code

    def redeem(self, request: TokenRequest) -> TokenResponse:
        """Exchange a pre-authorized code for an access token.

        :raises TokenError: with the code RFC 6749 defines and Section 6.3
            gives meaning to for this flow.
        """
        if request.grant_type != GRANT_TYPE_PRE_AUTHORIZED_CODE:
            raise TokenError(
                OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
                f"This authorization server implements only "
                f"{GRANT_TYPE_PRE_AUTHORIZED_CODE}",
            )

        if not self.allow_anonymous and not request.client_id:
            raise TokenError(
                OAuthErrorCode.INVALID_CLIENT,
                "This authorization server does not accept anonymous token requests",
            )

        code = request.pre_authorized_code or ""
        grant = self._codes.get(code)
        if grant is None or grant.expires_at <= self._now():
            # Unknown and expired are one answer on purpose: telling them apart
            # would say whether a guessed code ever existed.
            self._codes.pop(code, None)
            raise TokenError(
                OAuthErrorCode.INVALID_GRANT,
                "The pre-authorized code is unknown, already used, or expired",
            )

        self._check_transaction_code(grant, request.tx_code)

        # Single use: consumed the moment it is accepted, not when issuance
        # succeeds. A code that survives a failed exchange is a code twice.
        del self._codes[code]

        access_token = secrets.token_urlsafe(32)
        grant.expires_at = self._now() + self.token_ttl
        self._tokens[access_token] = grant

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.token_ttl,
            authorization_details=[
                IssuedAuthorizationDetail(
                    credential_configuration_id=configuration_id,
                    credential_identifiers=grant.credential_identifiers[
                        configuration_id
                    ],
                )
                for configuration_id in grant.credential_configuration_ids
            ],
        )

    def grant_for(self, access_token: str) -> Grant | None:
        """Return what an access token stands for, or ``None`` if it is not ours."""
        grant = self._tokens.get(access_token)
        if grant is None or grant.expires_at <= self._now():
            self._tokens.pop(access_token, None)
            return None
        return grant

    def _check_transaction_code(self, grant: Grant, presented: str | None) -> None:
        """Compare the presented Transaction Code with the expected one.

        Section 6.3 distinguishes three failures and gives two different codes
        to them, which is worth keeping: a missing or unexpected code means the
        Wallet built the request wrongly, a wrong one means the End-User typed
        the wrong digits. Only the second is worth asking them to try again.
        """
        if grant.tx_code is None:
            if presented is not None:
                raise TokenError(
                    OAuthErrorCode.INVALID_REQUEST,
                    "No Transaction Code was expected for this pre-authorized code",
                )
            return

        if presented is None:
            raise TokenError(
                OAuthErrorCode.INVALID_REQUEST,
                "This pre-authorized code requires a Transaction Code",
            )
        if not secrets.compare_digest(presented, grant.tx_code):
            raise TokenError(
                OAuthErrorCode.INVALID_GRANT,
                "The Transaction Code does not match",
            )
