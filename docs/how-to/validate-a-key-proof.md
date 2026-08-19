# How to validate a key proof

This guide shows you how to check the proof of possession a Wallet sends with a Credential Request, and how to get the key the credential must be bound to.

## Validate the proof

```python
from openid4vci.crypto.proofs import validate_jwt_proof

result = validate_jwt_proof(
    proof,
    credential_issuer="https://issuer.example.edu",
    c_nonce=current_nonce,
    supported_algorithms=["ES256"],
)

bind_credential_to(result.bound_key)
```

The call raises `CredentialRequestError` with `invalid_proof` or `invalid_nonce` when anything fails, so there is no success value to check.

## Handle proofs that name their key indirectly

A proof carrying its key in the `jwk` header works out of the box.
A proof naming it by `kid` or `x5c` does not, and that is deliberate: turning a DID URL or a certificate chain into a *trusted* key is a trust decision, and a library making it silently would be making it wrongly.

Supply a callback:

```python
result = validate_jwt_proof(
    proof,
    credential_issuer="https://issuer.example.edu",
    c_nonce=current_nonce,
    resolve_key=my_did_resolver,
)
```

## Demand a key attestation

If your trust framework requires keys held in protected storage, say so in your metadata and enforce it here:

```python
from openid4vci.crypto.attestation import AttackPotentialResistance

result = validate_jwt_proof(
    proof,
    credential_issuer="https://issuer.example.edu",
    c_nonce=current_nonce,
    attestation_resolve_key=my_wallet_provider_trust_list,
    required_key_storage=[
        AttackPotentialResistance.ISO_18045_HIGH,
        AttackPotentialResistance.ISO_18045_MODERATE,
    ],
)

assert result.attestation is not None
```

An attestation that says *nothing* about its key storage fails the requirement rather than passing it.

```{note}
A proof carrying a `key_attestation` is refused when no `attestation_resolve_key` is supplied.
Accepting the proof while ignoring an attestation we cannot check would be worse than refusing it.
```

## Accept an attestation without a proof of possession

The `attestation` proof type carries a key attestation and no signature by the attested keys.
Wallets use it so the End-User is not asked to authenticate once per key:

```python
from openid4vci.crypto.proofs import validate_attestation_proof

attestation = validate_attestation_proof(
    request.proofs["attestation"],
    resolve_key=my_wallet_provider_trust_list,
    c_nonce=current_nonce,
)
```
