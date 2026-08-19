# Modules and specification sections

Every module states which section of the specification it implements.
This table is the map in the other direction.

## Protocol messages

| Section | Subject | Module |
| --- | --- | --- |
| 4 | Credential Offer | `openid4vci.models.offer` |
| 5, 6 | Authorization and Token Endpoint | `openid4vci.models.oauth` |
| 7 | Nonce Endpoint | `openid4vci.models.nonce` |
| 8 | Credential Endpoint | `openid4vci.models.credential` |
| 9 | Deferred Credential Endpoint | `openid4vci.models.deferred` |
| 11 | Notification Endpoint | `openid4vci.models.notification` |
| 12 | Metadata | `openid4vci.models.metadata` |

## Cryptography

| Section | Subject | Module |
| --- | --- | --- |
| 10 | Encrypted requests and responses | `openid4vci.crypto.encryption` |
| Appendix D | Key attestations | `openid4vci.crypto.attestation` |
| Appendix F | Key proofs | `openid4vci.crypto.proofs` |
| — | Signing issued credentials | `openid4vci.crypto.signer` |
| — | Key handling | `openid4vci.crypto.jwk` |

## Serving

| Subject | Module |
| --- | --- |
| FastAPI router and the `IssuerBackend` protocol | `openid4vci.server_fastapi.app` |

## Credential formats

Adapters for the three Credential Format Profiles of Appendix A live in `openid4vci.adapters`.
None is implemented yet.

| Profile | Identifier |
| --- | --- |
| ISO mdoc | `mso_mdoc` |
| IETF SD-JWT VC | `dc+sd-jwt` |
| W3C VCDM | `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc` |

```{note}
Earlier drafts used `vc+sd-jwt` for SD-JWT VC.
Current profiles, among them the [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html), use `dc+sd-jwt`.
```

## Two decisions that shape the models

`Model.to_dict()` emits only what was set.
Several parameters have defaults the specification states in prose — an absent `mandatory` means false, an absent `input_mode` means numeric.
Writing them out turns a document you received into a different one that means the same, which is the wrong thing to do to metadata a Wallet may compare byte for byte, or that carries a signature.

The Credential Issuer Identifier is a validated string, not a URL type.
Section 12.2 requires a Wallet to compare it "using a simple string comparison with no normalization" and to discard the metadata when the values differ.
A type that appends a trailing slash would break interoperability rather than help it.
