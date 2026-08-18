"""Credential Issuer Metadata and Authorization Server Metadata (Section 12).

Two separate documents at two separate well-known locations:

* ``/.well-known/openid-credential-issuer`` -- our own metadata, most notably
  ``credential_configurations_supported``, which is what a Wallet reads to
  learn which credentials we offer and in which format.
* ``/.well-known/oauth-authorization-server`` (RFC 8414) -- the Authorization
  Server. It may be us or a separate deployment; the metadata field
  ``authorization_servers`` is what ties the two together.
"""
