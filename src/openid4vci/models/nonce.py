"""Nonce Endpoint (Section 7).

Unprotected POST with an empty body. It hands out a fresh ``c_nonce`` for the
Wallet to embed in its key proof, which is what lets us detect a replayed
proof later.

The response must not be cached: the Credential Issuer sets ``Cache-Control:
no-store``, and new challenge values must be unpredictable.
"""

from .common import Model


class NonceResponse(Model):
    """The Nonce Response (Section 7.2)."""

    c_nonce: str
