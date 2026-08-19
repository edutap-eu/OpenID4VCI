# About what this library decides, and what it leaves to you

The library is deliberately incomplete in one direction.
It implements the protocol exhaustively and decides almost nothing about issuance.

## The split

The FastAPI router owns protocol mechanics: media types, bearer extraction, the `Cache-Control: no-store` the Nonce Endpoint requires, the status code that distinguishes an immediate response from a deferred one, and the shape of an error body.

It owns none of the decisions.
Whether a credential may be issued, which nonce is current, what a transaction identifier refers to, whether an access token grants what it claims — all of that lives behind the `IssuerBackend` protocol.

The reason is not modesty.
A library that decided any of it would be deciding it for a deployment it cannot see: it does not know your Authorization Server, your student records, your retention rules, or whether a given person is entitled to the credential they asked for.

## What that means in practice

You will write more code than a "batteries included" issuer would ask for, and the code you write is the part that is genuinely yours.
The parts that are the same for everyone — the parameter that must not appear beside another, the status code a Wallet reads as "come back later", the nonce that must match — are already done, and done against the specification text rather than an example.

## Where the boundary is drawn on purpose

Three places are worth naming, because each is somewhere a library could plausibly have helped and deliberately does not.

**Resolving a key from `kid` or `x5c`.**
Turning a DID URL or a certificate chain into a key is easy; turning it into a *trusted* key is a trust decision. A library that made it silently would be making it wrongly.

**Validating the access token.**
Only you know which Authorization Server issued it, whether it is a JWT or opaque, and what it grants.

**The Authorization Endpoint and the Token Endpoint.**
They belong to the Authorization Server, which may well be a deployment you do not control. The issuer metadata parameter `authorization_servers` is what points at it.
