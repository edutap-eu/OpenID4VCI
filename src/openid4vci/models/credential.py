"""Credential Endpoint (Section 8).

Access-token protected. The request carries either ``credential_identifier``
or ``credential_configuration_id``, plus ``proofs`` of key possession, and may
request an encrypted response via ``credential_response_encryption``.

The response either contains the issued credential, or a ``transaction_id``
that moves the exchange to the Deferred Credential Endpoint.
"""
