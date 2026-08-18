# OpenID4VCI

Python implementation of the OpenID4VCI specification for eduTAP.

This implementation follows the final specification of OpenID4VCI 1.0
(<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>).

## Scope: the Issuer role

The specification defines three roles: Wallet, Credential Issuer and
Authorization Server. **This library implements the Credential Issuer.** The
Wallet role belongs to Google Wallet, Apple Wallet, the EUDI Wallet and
others; we talk to them, we do not implement them.

Whether the Authorization Server is this application or a separate deployment
is left open — the issuer metadata field `authorization_servers` carries
either answer.

## Credential formats

Adapters exist for the three Credential Format Profiles of Appendix A. Note
the exact format identifiers, because they are what a Wallet matches against:

| Profile | Identifier | Reference |
| --- | --- | --- |
| ISO mdoc | `mso_mdoc` | ISO/IEC 18013-5 |
| IETF SD-JWT VC | `dc+sd-jwt` | <https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt-vc/> |
| W3C VCDM | `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc` | <https://www.w3.org/TR/vc-data-model-2.0/> |

Earlier drafts used `vc+sd-jwt` for SD-JWT VC. Current profiles — among them
the [OpenID4VC High Assurance Interoperability Profile
1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
— use `dc+sd-jwt`.

## Installation

```shell
pip install openid4vci
```

CBOR and COSE are only needed by the ISO mdoc profile, so they sit behind an
extra. Install it when you issue `mso_mdoc`:

```shell
pip install "openid4vci[mdoc]"
```

JOSE is not optional and ships with the base install: key possession proofs,
signed issuer metadata and encrypted responses are all JWS/JWE/JWK.

## Endpoints and their modules

| Section | Endpoint | Module |
| --- | --- | --- |
| 4 | Credential Offer | `models/offer.py` |
| 5 / 6 | Authorization, Token | `models/oauth.py` |
| 7 | Nonce | `models/nonce.py` |
| 8 | Credential | `models/credential.py` |
| 9 | Deferred Credential | `models/deferred.py` |
| 10 | Encrypted requests and responses | `crypto/encryption.py` |
| 11 | Notification | `models/notification.py` |
| 12 | Metadata (issuer and authorization server) | `models/metadata.py` |

## Status

Skeleton. The module layout and the specification mapping above are settled;
no behaviour is implemented yet.

## Relationship to the platform packages

Wallet vendors accept OpenID4VCI alongside their own proprietary provisioning
APIs. The platform packages depend on this library and add only what is
vendor-specific — the offer delivery mechanism, the metadata profile a given
wallet accepts, and its trust anchors:

    edutap.wallet_google_identity  ->  openid4vci
    edutap.wallet_apple            ->  (own protocol)

The dependency points one way. Nothing vendor-specific belongs in this
package.
