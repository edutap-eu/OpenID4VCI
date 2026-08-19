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

The model layer is implemented and tested against the specification: every
request, response and metadata document of Sections 4 to 12, with the rules
the specification states in prose enforced by validators rather than left to
the caller.

`jwt` key proof validation (Appendix F.1) is implemented, as is the FastAPI
router serving the Nonce, Credential, Deferred Credential and Notification
endpoints and the metadata document. The router owns the protocol mechanics
and delegates every decision to an `IssuerBackend` a deployment provides.

Message encryption (Section 10) and signing are implemented too. The signer is
a protocol with a local implementation, so an HSM or a remote signing service
can take its place.

Not implemented yet: the credential format adapters (`adapters/`) and the
`di_vp` and `attestation` proof types.

Built against the specification source at tag `1.0-final` of
[openid/OpenID4VCI](https://github.com/openid/OpenID4VCI). 1.0 is the Final
Specification and is not subject to further revision; 1.1 exists only as a
working group draft.

## Relationship to the platform packages

Wallet vendors accept OpenID4VCI alongside their own proprietary provisioning
APIs. The platform packages depend on this library and add only what is
vendor-specific — the offer delivery mechanism, the metadata profile a given
wallet accepts, and its trust anchors:

    edutap.wallet_google_identity  ->  openid4vci
    edutap.wallet_apple            ->  (own protocol)

The dependency points one way. Nothing vendor-specific belongs in this
package.
