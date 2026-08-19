"""Signing issued credentials.

Kept behind a protocol on purpose. The key may live in a file, in an HSM, or
behind a remote signing service, and the document signer certificate above it
is governed by a trust anchor we do not control. Signing is also the one
operation an issuer cannot fake in a test environment, so being able to
substitute it matters.

The protocol is async because the interesting implementations are: an HSM and
a remote signer are I/O, and a synchronous interface would force them to block
the event loop.
"""

from .jwk import is_asymmetric
from joserfc import jws
from joserfc.jwk import ECKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
from typing import Any
from typing import Protocol
from typing import runtime_checkable


#: Interoperability floor for issuer signatures: ECDSA P-256 with SHA-256.
DEFAULT_SIGNING_ALGORITHM = "ES256"


@runtime_checkable
class CredentialSigner(Protocol):
    """What a credential format adapter needs in order to sign."""

    @property
    def algorithm(self) -> str:
        """The signature algorithm this signer produces, e.g. ``ES256``."""

    async def sign(
        self, payload: str | bytes, header: dict[str, Any] | None = None
    ) -> str:
        """Return the compact JWS over ``payload``."""

    def public_jwk(self) -> dict[str, Any]:
        """Return the public key, for publication in a key set."""


class LocalJwsSigner:
    """A signer holding its private key in this process.

    Appropriate for development and for deployments where the key lives on the
    same host. Anything with stronger key handling implements
    :class:`CredentialSigner` instead.
    """

    def __init__(
        self,
        key: ECKey | RSAKey | OKPKey,
        algorithm: str = DEFAULT_SIGNING_ALGORITHM,
    ) -> None:
        """
        :param key: the private key to sign with.
        :param algorithm: JWS algorithm identifier.
        :raises ValueError: if the key is symmetric. A credential signed with a
            shared secret could be forged by everyone able to verify it.
        """
        if not is_asymmetric(key.as_dict(private=False)):
            raise ValueError(
                "Credentials must be signed with an asymmetric key; a shared "
                "secret would let every verifier forge one"
            )
        self._key = key
        self._algorithm = algorithm

    @property
    def algorithm(self) -> str:
        """The signature algorithm this signer produces."""
        return self._algorithm

    async def sign(
        self, payload: str | bytes, header: dict[str, Any] | None = None
    ) -> str:
        """Return the compact JWS over ``payload``.

        The caller contributes header parameters its format needs -- ``typ``
        for SD-JWT VC, a certificate chain elsewhere -- but not ``alg``: the
        algorithm belongs to the key, and letting a caller change one without
        the other is how a signature ends up unverifiable.

        :raises ValueError: if ``header`` tries to set ``alg``.
        """
        protected: dict[str, Any] = dict(header or {})
        if "alg" in protected and protected["alg"] != self._algorithm:
            raise ValueError(
                f"The signer is configured for alg={self._algorithm!r}; it "
                "cannot sign with a different one"
            )
        protected["alg"] = self._algorithm
        if self._key.kid and "kid" not in protected:
            protected["kid"] = self._key.kid
        return jws.serialize_compact(protected, payload, self._key)

    def public_jwk(self) -> dict[str, Any]:
        """Return the public key, for publication in a key set."""
        return self._key.as_dict(private=False)
