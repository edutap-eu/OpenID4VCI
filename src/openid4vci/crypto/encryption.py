"""Encrypted Credential Requests and Responses (Section 10).

Encryption sits on top of TLS, not instead of it. What it buys is that the
message stays unreadable to anything between the Wallet and us that terminates
TLS -- a reverse proxy, a load balancer, a logging gateway.

Both directions are a JWT: the message is a compact JWE and the media type is
``application/jwt``.
"""

from ..exceptions import CredentialRequestError
from ..models.credential import CredentialErrorCode
from ..models.credential import CredentialResponse
from ..models.credential import RequestedCredentialResponseEncryption
from .jwk import public_key_from_jwk
from joserfc import jwe
from joserfc.errors import JoseError
from typing import Any

import json


#: Media type of an encrypted Credential Request or Response (Section 10).
ENCRYPTED_MESSAGE_MEDIA_TYPE = "application/jwt"


def _encryption_error(description: str) -> CredentialRequestError:
    return CredentialRequestError(
        CredentialErrorCode.INVALID_ENCRYPTION_PARAMETERS, description
    )


def encrypt_credential_response(
    response: CredentialResponse,
    encryption: RequestedCredentialResponseEncryption,
) -> str:
    """Encrypt a Credential Response for the Wallet that asked for it.

    :param response: the response to encrypt.
    :param encryption: the ``credential_response_encryption`` object from the
        Credential Request, carrying the Wallet's public key.
    :returns: the compact JWE, to be served as ``application/jwt``.
    :raises CredentialRequestError: with ``invalid_encryption_parameters`` if
        the key cannot be used.
    """
    key_data = dict(encryption.jwk)

    algorithm = key_data.get("alg")
    if not algorithm:
        raise _encryption_error(
            "The public key in credential_response_encryption must carry an "
            "alg parameter; Section 10 requires the JWE alg to equal it"
        )

    header: dict[str, Any] = {"alg": algorithm, "enc": encryption.enc}
    if encryption.zip is not None:
        header["zip"] = encryption.zip
    if "kid" in key_data:
        # Section 10: carrying the kid through is what lets the Wallet tell
        # which of its keys we used, without trial decryption.
        header["kid"] = key_data["kid"]

    try:
        # Section 10 calls this "a single public key", so the asymmetric check
        # in public_key_from_jwk is the right gate rather than an accident.
        key = public_key_from_jwk(key_data)
        return jwe.encrypt_compact(header, json.dumps(response.to_dict()), key)
    except (JoseError, ValueError) as error:
        raise _encryption_error(f"The response could not be encrypted: {error}")


def decrypt_credential_request(token: str, key: Any) -> dict[str, Any]:
    """Decrypt an encrypted Credential Request.

    :param token: the compact JWE as it arrived in the request body.
    :param key: our private key, or a key set to select from.
    :returns: the decrypted request parameters.
    :raises CredentialRequestError: with ``invalid_encryption_parameters`` if
        the message cannot be decrypted or does not contain a JSON object.
    """
    try:
        decrypted = jwe.decrypt_compact(token, key)
    except (JoseError, ValueError) as error:
        raise _encryption_error(f"The request could not be decrypted: {error}")

    if decrypted.plaintext is None:
        raise _encryption_error("The decrypted request carries no payload")

    try:
        payload = json.loads(decrypted.plaintext)
    except ValueError as error:
        raise _encryption_error(f"The decrypted request is not JSON: {error}")

    if not isinstance(payload, dict):
        raise _encryption_error(
            f"The decrypted request must be a JSON object, got {type(payload).__name__}"
        )
    return payload
