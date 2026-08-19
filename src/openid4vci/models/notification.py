"""Notification Endpoint (Section 11).

The Wallet reports back what became of the credentials it fetched. Optional in
the specification, but it is the only feedback an issuer gets, so it is what
makes issuance statistics and re-issuance possible at all.
"""

from .common import Model
from enum import Enum


class NotificationEvent(str, Enum):
    """What the Wallet reports (Section 11.1).

    A partial failure when issuing a batch counts as failure of the whole
    flow, not as a partial success.
    """

    CREDENTIAL_ACCEPTED = "credential_accepted"
    CREDENTIAL_FAILURE = "credential_failure"
    CREDENTIAL_DELETED = "credential_deleted"


class NotificationErrorCode(str, Enum):
    """Error codes of the Notification Endpoint (Section 11.3)."""

    INVALID_NOTIFICATION_ID = "invalid_notification_id"
    INVALID_NOTIFICATION_REQUEST = "invalid_notification_request"


class NotificationRequest(Model):
    """A Notification Request (Section 11.1)."""

    notification_id: str
    event: NotificationEvent
    event_description: str | None = None
