"""Adapter interface for the Credential Format Profiles (Appendix A).

An adapter has two jobs: turn claims into one concrete credential format, and
contribute the format-specific fragment of
``credential_configurations_supported`` to the issuer metadata. Everything
else in the protocol is format agnostic, which is why this interface is small.
"""

from typing import Any
from typing import Protocol
from typing import runtime_checkable


@runtime_checkable
class CredentialFormatAdapter(Protocol):
    """What every credential format profile provides."""

    @property
    def format(self) -> str:
        """The Credential Format Identifier, e.g. ``mso_mdoc``."""

    async def issue(
        self, claims: dict[str, Any], *, holder_key: dict[str, Any]
    ) -> str | dict[str, Any]:
        """Return the value of the ``credential`` claim in a Credential Response.

        :param claims: the data to put into the credential.
        :param holder_key: public JWK the credential is bound to, as returned
            by key proof validation.
        """

    def metadata_fragment(self) -> dict[str, Any]:
        """Return the format-specific part of a credential configuration."""
