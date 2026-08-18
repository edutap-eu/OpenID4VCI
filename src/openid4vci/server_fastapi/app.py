"""FastAPI application exposing the Credential Issuer endpoints.

Routers per section, so a deployment can mount only what it needs:
metadata (12), credential offer (4), nonce (7), credential (8),
deferred credential (9) and notification (11).

The Authorization Endpoint (5) and Token Endpoint (6) belong to the
Authorization Server. Whether that is this application or a separate service
is a deployment decision; the metadata field ``authorization_servers`` carries
it either way.
"""
