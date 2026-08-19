# Errors

The library raises typed errors that carry the error code the specification defines, so the code is chosen where the problem is detected rather than where the response is formatted.

`OpenID4VCIError`
:   Base class for everything this library raises.

`CredentialRequestError`
:   A Credential Request cannot be honoured.
    Carries a `CredentialErrorCode` and a description.
    The FastAPI router renders it as a 400 with the specified body.

`DeferredCredentialError`
:   A Deferred Credential Request cannot be honoured.
    Carries a `DeferredCredentialErrorCode`.

`NotificationError`
:   A Notification Request cannot be accepted.
    Carries a `NotificationErrorCode`.

## Choosing a credential error code

| Code | Meaning |
| --- | --- |
| `invalid_credential_request` | Missing, unsupported, repeated or malformed parameters |
| `unknown_credential_configuration` | The requested configuration is not one of ours |
| `unknown_credential_identifier` | The requested credential identifier is not one of ours |
| `invalid_proof` | The `proofs` parameter is missing, or a key proof is invalid, or one carries no `c_nonce` |
| `invalid_nonce` | A key proof carries a `c_nonce` that is not current |
| `invalid_encryption_parameters` | Encryption parameters are invalid or missing |
| `credential_request_denied` | Refused. The Wallet should treat this as unrecoverable |

The distinction between the two proof errors matters to the Wallet: `invalid_nonce` tells it to fetch a fresh challenge and retry, `invalid_proof` does not.
