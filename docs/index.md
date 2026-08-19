# openid4vci

Python implementation of [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

The specification defines three roles: Wallet, Credential Issuer and Authorization Server.
**This library implements the Credential Issuer.**
The Wallet role belongs to Google Wallet, Apple Wallet, the EUDI Wallet and others; we talk to them, we do not implement them.

```{warning}
Pre-release.
The protocol layer is complete and tested — every request, response and metadata document, key proof validation, message encryption, signing, and an HTTP router.
The credential format adapters are not written yet, so nothing can be issued end to end.
```

```{toctree}
:maxdepth: 2

tutorials/index
how-to/index
reference/index
explanation/index
```
