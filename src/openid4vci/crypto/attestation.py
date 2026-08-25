"""Key attestations (Appendix D).

A key attestation is a statement -- by the Wallet Provider, or by the key
storage component itself -- about *where* a key lives and *how well* it is
protected. It answers a question a key proof cannot: a proof shows that
someone holds the private key, not that the key sits in hardware that will
not surrender it.

An issuer decides from its own trust framework what it demands, and says so
through ``key_attestations_required`` in its metadata. This module checks an
attestation against that demand; it does not decide what the demand is.
"""

from ..exceptions import CredentialRequestError
from ..models.credential import CredentialErrorCode
from .registry import DEFAULT_JOSE_REGISTRY
from collections.abc import Callable
from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum
from joserfc import jwt
from joserfc.errors import ExceededSizeError
from joserfc.errors import JoseError
from joserfc.jws import JWSRegistry
from typing import Any

import base64
import json
import time


#: The `typ` every key attestation must carry (Appendix D.1).
KEY_ATTESTATION_TYP = "key-attestation+jwt"


class AttackPotentialResistance(str, Enum):
    """Resistance levels for key storage and user authentication (Appendix D.2).

    The values map to attack potentials of ISO/IEC 18045. Ecosystems may define
    their own values, so this enumeration is a vocabulary rather than a
    closed set: metadata and attestations carry plain strings.
    """

    ISO_18045_HIGH = "iso_18045_high"
    ISO_18045_MODERATE = "iso_18045_moderate"
    ISO_18045_ENHANCED_BASIC = "iso_18045_enhanced-basic"
    ISO_18045_BASIC = "iso_18045_basic"


@dataclass(frozen=True)
class KeyAttestation:
    """A validated key attestation.

    :param attested_keys: the public keys this attestation covers.
    :param key_storage: asserted resistance of the key storage component.
    :param user_authentication: asserted resistance of the authentication
        methods guarding the keys.
    :param claims: the full JWT body, for issuers evaluating more than this.
    """

    attested_keys: list[dict[str, Any]]
    key_storage: list[str] | None
    user_authentication: list[str] | None
    claims: dict[str, Any]


def _invalid_proof(description: str) -> CredentialRequestError:
    return CredentialRequestError(CredentialErrorCode.INVALID_PROOF, description)


def _decode_header(token: str) -> dict[str, Any]:
    try:
        segment = token.split(".")[0]
        padding = "=" * (-len(segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(segment + padding))
    except (ValueError, IndexError) as error:
        raise _invalid_proof(f"The key attestation is not a well-formed JWT: {error}")
    if not isinstance(header, dict):
        raise _invalid_proof("The JOSE header of the key attestation is not an object")
    return header


def validate_key_attestation(
    attestation: str,
    *,
    resolve_key: Callable[[dict[str, Any]], Any],
    c_nonce: str | None = None,
    required_key_storage: Collection[str] | None = None,
    required_user_authentication: Collection[str] | None = None,
    require_expiry: bool = False,
    now: int | None = None,
    registry: JWSRegistry | None = None,
) -> KeyAttestation:
    """Validate a key attestation in JWT format.

    :param attestation: the attestation JWT.
    :param resolve_key: callback turning the JOSE header into the Wallet
        Provider's verification key. Required: an attestation is signed by a
        party we must decide to trust, and that decision is not ours to make
        silently.
    :param c_nonce: our challenge. When set, the attestation must carry it,
        which is what proves it was minted for this exchange.
    :param required_key_storage: values we accept for ``key_storage``. The
        attestation must assert at least one of them.
    :param required_user_authentication: same, for ``user_authentication``.
    :param require_expiry: demand an ``exp`` claim. Appendix D makes it
        mandatory when the attestation accompanies a ``jwt`` key proof.
    :param now: current UNIX time, for testing.
    :param registry: JOSE registry, if the default header size limit does not
        suit this deployment. An attestation whose signer identifies itself by
        a certificate chain carries that chain in its own header, which is what
        makes the default limit matter here too.
    :raises CredentialRequestError: with ``invalid_proof`` or ``invalid_nonce``.
    """
    registry = registry if registry is not None else DEFAULT_JOSE_REGISTRY
    header = _decode_header(attestation)

    if header.get("typ") != KEY_ATTESTATION_TYP:
        raise _invalid_proof(
            f"A key attestation must be typed {KEY_ATTESTATION_TYP!r}, got "
            f"{header.get('typ')!r}"
        )

    algorithm = header.get("alg")
    if not algorithm or algorithm == "none" or algorithm.startswith("HS"):
        raise _invalid_proof(
            "A key attestation must be signed with an asymmetric algorithm, got "
            f"alg={algorithm!r}"
        )

    try:
        token = jwt.decode(
            attestation,
            resolve_key(header),
            algorithms=[algorithm],
            registry=registry,
        )
    except ExceededSizeError as error:
        # Not a signature failure, and saying so matters: an attestation whose
        # signer presents a three-certificate chain runs to roughly six
        # kilobytes of header, and "the signature does not verify" sends
        # whoever debugs it to the wrong place entirely.
        raise _invalid_proof(
            f"The key attestation is larger than this issuer accepts: {error}. "
            "Raise max_header_length on the registry if this is a legitimate "
            "attestation, for instance one carrying a certificate chain."
        )
    except JoseError as error:
        raise _invalid_proof(f"The key attestation signature does not verify: {error}")

    claims = token.claims

    if "iat" not in claims:
        raise _invalid_proof("A key attestation must carry an iat claim")

    expiry = claims.get("exp")
    if require_expiry and expiry is None:
        raise _invalid_proof(
            "A key attestation accompanying a key proof must carry an exp claim"
        )
    if expiry is not None:
        moment = now if now is not None else int(time.time())
        if expiry <= moment:
            raise _invalid_proof("The key attestation has expired")

    attested_keys = claims.get("attested_keys")
    if not attested_keys or not isinstance(attested_keys, list):
        raise _invalid_proof(
            "A key attestation must carry a non-empty attested_keys array"
        )

    if c_nonce is not None and claims.get("nonce") != c_nonce:
        raise CredentialRequestError(
            CredentialErrorCode.INVALID_NONCE,
            "The nonce in the key attestation is not the challenge we issued",
        )

    _require_level(claims, "key_storage", required_key_storage)
    _require_level(claims, "user_authentication", required_user_authentication)

    return KeyAttestation(
        attested_keys=attested_keys,
        key_storage=claims.get("key_storage"),
        user_authentication=claims.get("user_authentication"),
        claims=claims,
    )


def _require_level(
    claims: dict[str, Any], name: str, accepted: Collection[str] | None
) -> None:
    """Check one asserted resistance level against what we accept.

    Absence is a failure when we asked, not a pass: an attestation that says
    nothing about its key storage has not told us the keys are protected.
    """
    if accepted is None:
        return
    asserted = claims.get(name) or []
    if not set(asserted) & set(accepted):
        raise _invalid_proof(
            f"The key attestation asserts {name}={asserted!r}, but this issuer "
            f"requires one of {sorted(accepted)}"
        )
