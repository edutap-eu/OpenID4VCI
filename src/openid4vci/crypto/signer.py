"""Signing abstraction for issued credentials.

Kept behind an interface on purpose: the key may live in a file, in an HSM or
behind a remote signing service, and the document signer certificate is
governed by a trust anchor (IACA for ISO mdoc) that we do not control.

ES256 (ECDSA P-256 / SHA-256) is the interoperability floor.
"""
