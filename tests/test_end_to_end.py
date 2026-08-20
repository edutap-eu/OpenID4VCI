"""One credential, all the way through.

Every other test exercises a layer. This one runs the whole exchange the way a
Wallet does it -- offer, token, nonce, proof, credential -- because layers that
each work do not necessarily fit together, and nothing so far has said whether
they do.

It doubles as the smallest complete example of what a deployment has to write.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import ECKey
from openid4vci.adapters.sd_jwt_vc import SdJwtVcAdapter
from openid4vci.authorization import InMemoryAuthorizationServer
from openid4vci.crypto.proofs import validate_jwt_proof
from openid4vci.crypto.signer import LocalJwsSigner
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.metadata import CredentialIssuerMetadata
from openid4vci.models.offer import offer_uri_by_value
from openid4vci.reference import InMemoryNonceStore
from openid4vci.server_fastapi.app import create_router

import base64
import json
import pytest


ISSUER = "https://issuer.example.edu"
CONFIGURATION = "StudentCredential"
VCT = "https://credentials.example.edu/student"

METADATA = {
    "credential_issuer": ISSUER,
    "credential_endpoint": f"{ISSUER}/credential",
    "nonce_endpoint": f"{ISSUER}/nonce",
    "credential_configurations_supported": {
        CONFIGURATION: {
            "format": "dc+sd-jwt",
            "scope": CONFIGURATION,
            "vct": VCT,
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
        }
    },
}


class Issuer:
    """The glue a deployment writes: what to issue, to whom, and when.

    Everything here is a decision the library refuses to make for us -- which
    is the point of the boundary, and this is what the other side of it costs.
    """

    def __init__(self, issuer_key):
        self.authorization = InMemoryAuthorizationServer(credential_issuer=ISSUER)
        self.nonces = InMemoryNonceStore()
        self.adapter = SdJwtVcAdapter(
            vct=VCT, signer=LocalJwsSigner(issuer_key), issuer=ISSUER
        )
        self.records = {
            "erika": {"given_name": "Erika", "matriculation_number": "12345678"}
        }

    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        return CredentialIssuerMetadata.model_validate(METADATA)

    async def create_nonce(self) -> str:
        return self.nonces.issue()

    async def issue_credential(self, request, context) -> CredentialResponse:
        grant = self.authorization.grant_for(context.access_token)
        if grant is None:
            raise CredentialRequestError(
                CredentialErrorCode.CREDENTIAL_REQUEST_DENIED,
                "The access token is not one of ours, or has expired",
            )

        proofs = (request.proofs or {}).get("jwt") or []
        if not proofs:
            raise CredentialRequestError(
                CredentialErrorCode.INVALID_PROOF,
                "This credential is key bound, so a key proof is required",
            )

        # The nonce is consumed here rather than merely read: a proof presented
        # twice must not yield a second credential.
        #
        # Note the ordering. It is spent before the signature is checked, so a
        # malformed proof also burns it and the Wallet has to fetch another.
        # That is the safe direction -- the alternative lets an attacker probe
        # signatures against one nonce indefinitely -- and the Wallet recovers,
        # because invalid_nonce is exactly the error that tells it to.
        result = validate_jwt_proof(
            proofs[0],
            credential_issuer=ISSUER,
            c_nonce=self._current_nonce(proofs[0]),
            supported_algorithms=["ES256"],
        )

        credential = await self.adapter.issue(
            self.records[grant.subject], holder_key=result.bound_key
        )
        return CredentialResponse.model_validate(
            {"credentials": [{"credential": credential}]}
        )

    def _current_nonce(self, proof: str) -> str:
        """Return the nonce the proof carries, if we issued it and it is unused."""
        payload = proof.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        presented = json.loads(base64.urlsafe_b64decode(payload)).get("nonce")
        if presented is None or not self.nonces.consume(presented):
            raise CredentialRequestError(
                CredentialErrorCode.INVALID_NONCE,
                "Fetch a fresh challenge from the nonce endpoint",
            )
        return presented

    async def issue_deferred(self, request, context):  # pragma: no cover
        raise NotImplementedError

    async def notify(self, request, context) -> None:
        pass


@pytest.fixture
def issuer_key():
    return ECKey.generate_key("P-256", auto_kid=True)


@pytest.fixture
def issuer(issuer_key):
    return Issuer(issuer_key)


@pytest.fixture
def client(issuer):
    app = FastAPI()
    app.include_router(create_router(issuer))
    return TestClient(app)


def wallet_proof(holder_key, nonce):
    """Build the key proof a Wallet sends."""
    return jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": holder_key.as_dict(private=False),
        },
        {"aud": ISSUER, "iat": 1_766_000_000, "nonce": nonce},
        holder_key,
    )


async def test_a_credential_travels_from_offer_to_wallet(client, issuer, issuer_key):
    # 1. The issuer offers, having authenticated Erika by its own means.
    offer, code = issuer.authorization.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )
    link = offer_uri_by_value(offer)
    assert link.startswith("openid-credential-offer://?")

    # 2. The Wallet reads the offer and redeems the code.
    from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
    from openid4vci.models.oauth import TokenRequest

    token = issuer.authorization.redeem(
        TokenRequest.model_validate(
            {
                "grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE,
                "pre-authorized_code": code,
            }
        )
    )
    assert token.authorization_details[0].credential_configuration_id == CONFIGURATION

    # 3. The Wallet fetches a challenge.
    nonce = client.post("/nonce").json()["c_nonce"]

    # 4. It proves possession of a fresh key and asks for the credential.
    holder_key = ECKey.generate_key("P-256")
    response = client.post(
        "/credential",
        json={
            "credential_configuration_id": CONFIGURATION,
            "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
        },
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.status_code == 200
    credential = response.json()["credentials"][0]["credential"]

    # 5. What arrived is a credential bound to the Wallet's key, carrying
    #    Erika's data as disclosures rather than in the clear.
    from joserfc import jws

    issuer_jwt, *disclosures, key_binding = credential.split("~")
    assert key_binding == ""
    payload = json.loads(jws.deserialize_compact(issuer_jwt, issuer_key).payload)

    assert payload["vct"] == VCT
    assert payload["cnf"]["jwk"] == holder_key.as_dict(private=False)
    assert "12345678" not in json.dumps(payload)

    disclosed = {}
    for disclosure in disclosures:
        padded = disclosure + "=" * (-len(disclosure) % 4)
        _, name, value = json.loads(base64.urlsafe_b64decode(padded))
        disclosed[name] = value
    assert disclosed == {"given_name": "Erika", "matriculation_number": "12345678"}


async def test_the_same_proof_cannot_be_used_twice(client, issuer):
    """A replayed proof is what the nonce exists to stop, end to end."""
    from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
    from openid4vci.models.oauth import TokenRequest

    _, code = issuer.authorization.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )
    token = issuer.authorization.redeem(
        TokenRequest.model_validate(
            {"grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE, "pre-authorized_code": code}
        )
    )
    nonce = client.post("/nonce").json()["c_nonce"]
    holder_key = ECKey.generate_key("P-256")
    body = {
        "credential_configuration_id": CONFIGURATION,
        "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
    }
    headers = {"Authorization": f"Bearer {token.access_token}"}

    assert client.post("/credential", json=body, headers=headers).status_code == 200

    replay = client.post("/credential", json=body, headers=headers)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_nonce"


async def test_a_stolen_token_without_a_proof_gets_nothing(client, issuer):
    from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
    from openid4vci.models.oauth import TokenRequest

    _, code = issuer.authorization.offer(
        subject="erika", credential_configuration_ids=[CONFIGURATION]
    )
    token = issuer.authorization.redeem(
        TokenRequest.model_validate(
            {"grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE, "pre-authorized_code": code}
        )
    )

    response = client.post(
        "/credential",
        json={"credential_configuration_id": CONFIGURATION},
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_proof"


async def test_an_invented_access_token_is_refused(client):
    response = client.post(
        "/credential",
        json={"credential_configuration_id": CONFIGURATION},
        headers={"Authorization": "Bearer not-a-token-we-issued"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "credential_request_denied"
