"""Key possession proofs (Appendix F) and key attestation (Appendix D).

Three proof types exist: ``jwt``, ``di_vp`` (a W3C Verifiable Presentation
with a Data Integrity proof) and ``attestation``. This module implements the
``jwt`` type, which is the one both other profiles in common use rely on.

Validating a proof is the security-critical step of an issuer. The proof binds
the credential to a key the Wallet actually holds, the audience keeps a proof
made for another issuer from being replayed here, and the ``c_nonce`` keeps an
old proof for *this* issuer from being replayed either.
"""

from ..exceptions import CredentialRequestError
from ..models.credential import CredentialErrorCode
from .attestation import KeyAttestation
from .attestation import validate_key_attestation
from .jwk import public_key_from_jwk
from .registry import DEFAULT_JOSE_REGISTRY
from collections.abc import Callable
from collections.abc import Collection
from dataclasses import dataclass
from joserfc import jwt
from joserfc.errors import ExceededSizeError
from joserfc.errors import JoseError
from joserfc.jws import JWSRegistry
from typing import Any

import base64
import json


#: Proof type identifiers defined in Appendix F.
PROOF_TYPE_JWT = "jwt"
PROOF_TYPE_DI_VP = "di_vp"
PROOF_TYPE_ATTESTATION = "attestation"

#: The `typ` every `jwt` key proof must carry (Appendix F.1).
JWT_PROOF_TYP = "openid4vci-proof+jwt"

#: JOSE header parameters that identify the key, at most one of which may appear.
KEY_HEADERS = ("kid", "jwk", "x5c")

#: The registry key proofs are parsed with. Kept as a name here because callers
#: import it from this module; see crypto.registry for what it carries and why.
PROOF_REGISTRY = DEFAULT_JOSE_REGISTRY

#: MAC algorithm identifiers (RFC 7518). Appendix F.1 forbids them for key
#: proofs, and the reason is worth stating: both sides of a MAC hold the same
#: secret, so a verifying signature says only that someone who knows the secret
#: produced it -- not that the Wallet holds a key nobody else has.
MAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


@dataclass(frozen=True)
class ProofResult:
    """What a validated key proof yields.

    :param bound_key: public JWK the issued credential must be bound to.
        Always present: it is the reason a proof is validated at all.
    :param header: the JOSE header.
    :param claims: the JWT claims.
    :param attestation: the validated key attestation, if the proof carried one.
    """

    bound_key: dict[str, Any]
    header: dict[str, Any]
    claims: dict[str, Any]
    attestation: KeyAttestation | None = None


def _invalid_proof(description: str) -> CredentialRequestError:
    return CredentialRequestError(CredentialErrorCode.INVALID_PROOF, description)


def _decode_header(proof: str) -> dict[str, Any]:
    """Read the JOSE header before verifying anything.

    We have to look before we verify, because the header is what tells us
    which key to verify with. Nothing read here is trusted until the signature
    checks out.
    """
    try:
        segment = proof.split(".")[0]
        padding = "=" * (-len(segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(segment + padding))
    except (ValueError, IndexError) as error:
        raise _invalid_proof(f"The key proof is not a well-formed JWT: {error}")
    if not isinstance(header, dict):
        raise _invalid_proof("The JOSE header of the key proof is not an object")
    return header


def validate_jwt_proof(
    proof: str,
    *,
    credential_issuer: str,
    c_nonce: str | None = None,
    supported_algorithms: Collection[str] | None = None,
    client_id: str | None = None,
    resolve_key: Callable[[dict[str, Any]], Any] | None = None,
    attestation_resolve_key: Callable[[dict[str, Any]], Any] | None = None,
    required_key_storage: Collection[str] | None = None,
    required_user_authentication: Collection[str] | None = None,
    now: int | None = None,
    registry: JWSRegistry | None = None,
) -> ProofResult:
    """Validate one `jwt` key proof and return the key it binds to.

    :param proof: the key proof JWT as it arrived in the ``proofs`` parameter.
    :param credential_issuer: our own Credential Issuer Identifier. The proof's
        ``aud`` must be exactly this.
    :param c_nonce: the challenge we handed out, or ``None`` if we run no Nonce
        Endpoint. When set, the proof must carry it.
    :param supported_algorithms: what we advertised in
        ``proof_signing_alg_values_supported``. When set, ``alg`` must be one
        of these.
    :param client_id: the client the access token belongs to. When set, an
        ``iss`` claim in the proof must match it.
    :param resolve_key: callback turning a JOSE header into a verification key.
        Required for proofs identifying their key by ``kid`` or ``x5c``, since
        resolving a DID URL or a certificate chain needs trust decisions this
        library does not make.
    :param attestation_resolve_key: the same, for the Wallet Provider key that
        signed a ``key_attestation`` in the JOSE header. Without it, a proof
        carrying an attestation is refused rather than silently accepted with
        the attestation ignored.
    :param required_key_storage: resistance levels we accept, checked against
        the attestation.
    :param required_user_authentication: the same, for user authentication.
    :param now: current UNIX time, for testing.
    :param registry: JOSE registry, if the default header size limit does not
        suit this deployment. See :mod:`openid4vci.crypto.registry`.
    :raises CredentialRequestError: with ``invalid_proof`` or ``invalid_nonce``.
    """
    registry = registry if registry is not None else PROOF_REGISTRY
    header = _decode_header(proof)

    if header.get("typ") != JWT_PROOF_TYP:
        raise _invalid_proof(
            f"A key proof must be typed {JWT_PROOF_TYP!r}, got {header.get('typ')!r}"
        )

    algorithm = header.get("alg")
    if not algorithm or algorithm == "none":
        raise _invalid_proof("A key proof must be signed; alg must not be 'none'")
    if algorithm in MAC_ALGORITHMS:
        raise _invalid_proof(
            f"A key proof must be signed with an asymmetric algorithm, got the "
            f"MAC algorithm {algorithm!r}"
        )
    if supported_algorithms is not None and algorithm not in supported_algorithms:
        raise _invalid_proof(
            f"The key proof is signed with {algorithm!r}, which is not among the "
            f"advertised algorithms: {sorted(supported_algorithms)}"
        )

    present = [name for name in KEY_HEADERS if name in header]
    if len(present) > 1:
        raise _invalid_proof(
            f"The JOSE header parameters {KEY_HEADERS} are mutually exclusive, "
            f"got: {present}"
        )
    if not present:
        raise _invalid_proof(
            "The JOSE header must identify the key through one of "
            f"{KEY_HEADERS}, so that the signature can be verified against it"
        )

    bound_key: dict[str, Any]
    if present[0] == "jwk":
        try:
            key = public_key_from_jwk(header["jwk"])
        except ValueError as error:
            raise _invalid_proof(str(error))
        bound_key = header["jwk"]
    else:
        if resolve_key is None:
            raise _invalid_proof(
                f"The key proof identifies its key by {present[0]!r}, which this "
                "issuer cannot resolve; supply a resolve_key callback"
            )
        key = resolve_key(header)
        # The caller validates a proof in order to learn which key to bind the
        # credential to, so this must be answered however the key arrived. A
        # key we resolved well enough to verify a signature with can be written
        # down as a JWK.
        try:
            bound_key = key.as_dict(private=False)
        except (AttributeError, TypeError) as error:
            raise _invalid_proof(
                f"The resolved key cannot be expressed as a JWK: {error}"
            )

    try:
        token = jwt.decode(proof, key, algorithms=[algorithm], registry=registry)
    except ExceededSizeError as error:
        # Reported apart from a signature failure on purpose: the first time
        # this fired, it read as "the signature does not verify", and anyone
        # debugging that looks at keys and certificates rather than at a
        # parser limit.
        raise _invalid_proof(
            f"The key proof is larger than this issuer accepts: {error}. "
            "Raise max_header_length on the registry if this is a legitimate "
            "proof, for instance one carrying a certificate chain."
        )
    except JoseError as error:
        raise _invalid_proof(f"The key proof signature does not verify: {error}")

    claims = token.claims

    audience = claims.get("aud")
    if audience != credential_issuer:
        raise _invalid_proof(
            f"A key proof must be addressed to {credential_issuer!r}, got {audience!r}"
        )

    if "iat" not in claims:
        raise _invalid_proof("A key proof must carry an iat claim")

    if client_id is not None and "iss" in claims and claims["iss"] != client_id:
        raise _invalid_proof(
            f"The iss claim of the key proof is {claims['iss']!r}, but the "
            f"request is made by {client_id!r}"
        )

    if c_nonce is not None:
        nonce = claims.get("nonce")
        if nonce is None:
            raise _invalid_proof(
                "This issuer runs a Nonce Endpoint, so a key proof must carry a "
                "nonce claim"
            )
        if nonce != c_nonce:
            raise CredentialRequestError(
                CredentialErrorCode.INVALID_NONCE,
                "The nonce in the key proof is not the challenge we issued; "
                "fetch a fresh one from the Nonce Endpoint",
            )

    attestation = None
    if "key_attestation" in header:
        if attestation_resolve_key is None:
            raise _invalid_proof(
                "The key proof carries a key_attestation, but no way to resolve "
                "the Wallet Provider key was supplied; ignoring an attestation "
                "we cannot check would accept it silently"
            )
        attestation = validate_key_attestation(
            header["key_attestation"],
            resolve_key=attestation_resolve_key,
            c_nonce=c_nonce,
            required_key_storage=required_key_storage,
            required_user_authentication=required_user_authentication,
            require_expiry=True,
            now=now,
            registry=registry,
        )
        _require_key_is_attested(key, attestation)

    return ProofResult(
        bound_key=bound_key,
        header=header,
        claims=claims,
        attestation=attestation,
    )


def _require_key_is_attested(key: Any, attestation: KeyAttestation) -> None:
    """Check that the proof was signed by a key the attestation covers.

    Appendix F.1 makes this a MUST, and it is what ties the two together: an
    attestation about keys nobody used would let a Wallet borrow someone
    else's hardware guarantees for a key kept in software.

    Comparison is by RFC 7638 thumbprint rather than by dict equality, because
    the same key may arrive with different member order or extra parameters.
    """
    try:
        thumbprint = key.thumbprint()
    except Exception as error:  # pragma: no cover - defensive
        raise _invalid_proof(f"The proof key cannot be fingerprinted: {error}")

    attested = set()
    for attested_key in attestation.attested_keys:
        try:
            attested.add(public_key_from_jwk(attested_key).thumbprint())
        except ValueError:
            continue

    if thumbprint not in attested:
        raise _invalid_proof(
            "The key proof is signed by a key the attestation does not attest"
        )


def validate_attestation_proof(
    proofs: list[Any],
    *,
    resolve_key: Callable[[dict[str, Any]], Any],
    c_nonce: str | None = None,
    required_key_storage: Collection[str] | None = None,
    required_user_authentication: Collection[str] | None = None,
    now: int | None = None,
) -> KeyAttestation:
    """Validate an ``attestation`` proof (Appendix F.3).

    This proof type carries a key attestation *without* a proof of possession:
    the Wallet asserts which keys it holds and how they are protected, but
    performs no signature with them. That is the point of it -- the keys need
    not be exercised, so the End-User is not asked to authenticate once per key.

    :param proofs: the array behind the ``attestation`` key. Appendix F requires
        exactly one JWT in it.
    :raises CredentialRequestError: if the array is not exactly one attestation,
        or the attestation does not validate.
    """
    if len(proofs) != 1:
        raise _invalid_proof(
            "The attestation proof type takes an array of exactly one JWT, got "
            f"{len(proofs)}"
        )
    return validate_key_attestation(
        proofs[0],
        resolve_key=resolve_key,
        c_nonce=c_nonce,
        required_key_storage=required_key_storage,
        required_user_authentication=required_user_authentication,
        now=now,
    )
