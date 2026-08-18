"""Key possession proofs (Appendix F) and key attestation (Appendix D).

Three proof types are defined: ``jwt`` (media type
``application/openid4vci-proof+jwt``), ``di_vp`` (Data Integrity proof in a
Verifiable Presentation) and ``attestation``.

Validation is the security-critical part of the issuer: a proof binds the
credential to a key the Wallet actually holds, and the ``c_nonce`` from the
Nonce Endpoint is what keeps it from being replayed.
"""
