"""Adapter interface for the Credential Format Profiles (Appendix A).

An adapter has two jobs: serialize claims into one concrete credential format,
and contribute the format-specific fragment of
``credential_configurations_supported`` to the issuer metadata. Everything
else in the protocol is format agnostic.
"""
