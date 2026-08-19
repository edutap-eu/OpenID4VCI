# About key proofs and key attestations

Two mechanisms sit next to each other in the specification and answer different questions.
Confusing them is easy, and the consequence is a credential bound to a key that is not protected the way you assumed.

## What a key proof shows

A key proof is a signature made with the private key the credential will be bound to.
It shows that whoever made the request **holds** that key right now.

Three things in it do work that is easy to overlook:

The **audience** is your Credential Issuer Identifier.
Without it, a proof the Wallet made for another issuer could be replayed at yours.

The **nonce** is the challenge you handed out.
Without it, a proof made for *your* issuer last month could be replayed today.
This is why the specification separates `invalid_nonce` from `invalid_proof`: the first is recoverable and tells the Wallet to fetch a fresh challenge.

The **algorithm** must be asymmetric.
Both sides of a MAC hold the same secret, so a verifying MAC signature proves only that someone who knows the secret produced it — not that the Wallet holds a key nobody else has.

## What a key attestation shows

An attestation is a statement by the Wallet Provider, or by the key storage component itself, about **where the key lives and how well it is protected**: hardware or software, and what user authentication guards it.

A key proof cannot tell you this.
A key held in plain application storage produces exactly the same signature as one held in a secure element.

## Why they belong together

Used alone, each has a gap.
A proof says a key is held but not how well it is kept.
An attestation says how keys are kept, but nothing about whether the key in *this* request is one of them.

The specification closes the gap by requiring that a proof accompanied by an attestation be signed by a key that attestation covers.
Without that check, a Wallet could present an attestation about its secure element while proving possession of a key kept in software, and inherit guarantees it does not have.

## Deciding what to demand

The library enforces what you ask for; it does not choose it.
That choice comes from your trust framework, and it belongs in your issuer metadata under `key_attestations_required`, so a Wallet learns the requirement before it builds a request rather than after being refused.

One asymmetry is deliberate: an attestation that says **nothing** about its key storage fails a requirement rather than passing it.
Saying nothing is not the same as saying enough.
