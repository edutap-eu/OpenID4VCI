"""Deferred Credential Endpoint (Section 9).

For issuance that cannot complete synchronously -- manual approval, an
external system, a pending identity check. The Wallet polls with the
``transaction_id`` it received, honouring ``interval``.
"""
