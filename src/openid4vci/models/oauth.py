"""Authorization Endpoint (Section 5) and Token Endpoint (Section 6).

Both are ordinary OAuth 2.0 endpoints; OpenID4VCI adds the
``authorization_details`` type ``openid_credential`` (carrying
``credential_configuration_id`` and optional ``claims``), the ``issuer_state``
taken from a Credential Offer, and the pre-authorized code grant
``urn:ietf:params:oauth:grant-type:pre-authorized_code``.

The token response may return ``credential_identifiers``, which the Credential
Endpoint then expects instead of a configuration id.
"""
