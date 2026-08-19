"""Encrypted Credential Requests and Responses, OpenID4VCI 1.0 Section 10."""

from joserfc import jwe
from joserfc.jwk import ECKey
from openid4vci.crypto.encryption import decrypt_credential_request
from openid4vci.crypto.encryption import encrypt_credential_response
from openid4vci.crypto.encryption import ENCRYPTED_MESSAGE_MEDIA_TYPE
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.credential import RequestedCredentialResponseEncryption

import json
import pytest


RESPONSE = CredentialResponse.model_validate(
    {"credentials": [{"credential": "a-student-credential"}]}
)


@pytest.fixture
def wallet_key():
    return ECKey.generate_key("P-256", auto_kid=True)


def encryption_for(key, *, alg="ECDH-ES+A128KW", enc="A128GCM", zip=None, kid=True):
    jwk = key.as_dict(private=False)
    jwk["alg"] = alg
    if alg is None:
        jwk.pop("alg")
    if not kid:
        # as_dict already carries the kid of an auto_kid key, so a key without
        # one has to be built by taking it away
        jwk.pop("kid", None)
    payload = {"jwk": jwk, "enc": enc}
    if zip is not None:
        payload["zip"] = zip
    return RequestedCredentialResponseEncryption.model_validate(payload)


def test_the_media_type_is_the_one_the_specification_prescribes():
    assert ENCRYPTED_MESSAGE_MEDIA_TYPE == "application/jwt"


def test_the_wallet_can_decrypt_what_we_encrypted(wallet_key):
    token = encrypt_credential_response(RESPONSE, encryption_for(wallet_key))

    decrypted = jwe.decrypt_compact(token, wallet_key)

    assert decrypted.plaintext is not None
    assert json.loads(decrypted.plaintext) == RESPONSE.to_dict()


def test_the_jwe_algorithm_is_the_one_the_key_declares(wallet_key):
    """Section 10: the JWE alg MUST equal the alg value of the chosen JWK."""
    token = encrypt_credential_response(
        RESPONSE, encryption_for(wallet_key, alg="ECDH-ES+A256KW")
    )

    assert jwe.decrypt_compact(token, wallet_key).protected["alg"] == "ECDH-ES+A256KW"


def test_a_key_without_an_algorithm_is_refused(wallet_key):
    """Section 10: the alg parameter MUST be present."""
    with pytest.raises(CredentialRequestError) as caught:
        encrypt_credential_response(RESPONSE, encryption_for(wallet_key, alg=None))

    assert caught.value.code is CredentialErrorCode.INVALID_ENCRYPTION_PARAMETERS


def test_the_key_identifier_is_carried_into_the_jwe_header(wallet_key):
    """Section 10: the JWE MUST include the same kid, so the key is identifiable."""
    token = encrypt_credential_response(RESPONSE, encryption_for(wallet_key))

    assert jwe.decrypt_compact(token, wallet_key).protected["kid"] == wallet_key.kid


def test_no_key_identifier_is_invented_when_the_key_has_none(wallet_key):
    token = encrypt_credential_response(RESPONSE, encryption_for(wallet_key, kid=False))

    assert "kid" not in jwe.decrypt_compact(token, wallet_key).protected


def test_the_content_encryption_algorithm_comes_from_the_request(wallet_key):
    token = encrypt_credential_response(
        RESPONSE, encryption_for(wallet_key, enc="A256GCM")
    )

    assert jwe.decrypt_compact(token, wallet_key).protected["enc"] == "A256GCM"


def test_compression_is_applied_only_when_asked_for(wallet_key):
    plain = encrypt_credential_response(RESPONSE, encryption_for(wallet_key))
    assert "zip" not in jwe.decrypt_compact(plain, wallet_key).protected

    compressed = encrypt_credential_response(
        RESPONSE, encryption_for(wallet_key, zip="DEF")
    )
    decrypted = jwe.decrypt_compact(compressed, wallet_key)
    assert decrypted.protected["zip"] == "DEF"
    assert decrypted.plaintext is not None
    assert json.loads(decrypted.plaintext) == RESPONSE.to_dict()


def test_an_encrypted_request_is_decrypted_into_its_payload():
    issuer_key = ECKey.generate_key("P-256", auto_kid=True)
    request = {"credential_configuration_id": "StudentCredential"}
    token = jwe.encrypt_compact(
        {"alg": "ECDH-ES+A128KW", "enc": "A128GCM", "kid": issuer_key.kid},
        json.dumps(request),
        issuer_key,
    )

    assert decrypt_credential_request(token, issuer_key) == request


def test_a_request_we_cannot_decrypt_is_an_encryption_parameter_error():
    issuer_key = ECKey.generate_key("P-256")
    other_key = ECKey.generate_key("P-256")
    token = jwe.encrypt_compact(
        {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"},
        json.dumps({"credential_configuration_id": "StudentCredential"}),
        other_key,
    )

    with pytest.raises(CredentialRequestError) as caught:
        decrypt_credential_request(token, issuer_key)

    assert caught.value.code is CredentialErrorCode.INVALID_ENCRYPTION_PARAMETERS


def test_a_payload_that_is_not_an_object_is_refused():
    issuer_key = ECKey.generate_key("P-256")
    token = jwe.encrypt_compact(
        {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}, json.dumps([1, 2]), issuer_key
    )

    with pytest.raises(CredentialRequestError):
        decrypt_credential_request(token, issuer_key)
