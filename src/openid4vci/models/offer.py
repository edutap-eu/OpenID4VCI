"""Credential Offer (Section 4).

The Credential Offer is how issuance *starts*: we hand the Wallet a
``credential_offer`` object (or a ``credential_offer_uri`` pointing at one),
usually as a deep link or QR code. It names the ``credential_issuer``, the
``credential_configuration_ids`` on offer and the ``grants`` the Wallet may
use -- authorization code flow, or the pre-authorized code flow with an
optional ``tx_code``.

This is the standard equivalent of a vendor "add to wallet" button and
therefore the module the platform-specific packages build on.
"""
