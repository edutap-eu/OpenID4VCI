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

## Accept proofs that carry a certificate chain

A JOSE header is read before anything in the message is verified, so a strict
library caps how much of it it will parse.
The default cap is 512 bytes, which is generous for an ordinary header and far
too small here: this protocol puts a whole signed JWT inside a header, and an
attestation whose signer identifies itself by `x5c` carries that chain too.

Measured sizes of realistic proofs:

| | Header |
| --- | ---: |
| proof without an attestation | 236 |
| attestation, one attested key | 952 |
| attestation, twenty attested keys | 5 242 |
| attestation with a one-certificate chain | 3 582 |
| attestation with a three-certificate chain | 8 811 |
| ten keys and a three-certificate chain | 10 843 |

The default limit sits above all of these.
Change it when your deployment differs in either direction:

```python
from openid4vci.crypto.registry import jose_registry

result = validate_jwt_proof(
    proof,
    credential_issuer="https://issuer.example.edu",
    c_nonce=current_nonce,
    registry=jose_registry(max_header_length=1024),
)
```

An issuer that expects no attestations has no reason to parse kilobytes, and
tightening the limit is the cheaper half of this decision.

```{important}
The header limit is not your protection against a large request.
It bounds one header, and a Credential Request may carry a batch of proofs.
The ceiling that matters is the HTTP body limit in your reverse proxy or ASGI
server, and that one is yours to set.
```

## Build a proof in a test

The registry is needed to *construct* a proof, not only to read one: the size
limit applies at encoding as well.

```python
from joserfc import jwt
from openid4vci.crypto.registry import DEFAULT_JOSE_REGISTRY

proof = jwt.encode(header, claims, key, registry=DEFAULT_JOSE_REGISTRY)
```
