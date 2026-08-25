"""The JOSE registry this protocol needs.

Two things separate a key proof from an ordinary JWS, and both live here
because the proof path and the attestation path need the same answers.

The specification adds header parameters that a strict JOSE library does not
know, and it puts a whole signed JWT inside a header, which runs past the size
a strict JOSE library expects.
"""

from joserfc.jws import JWSRegistry
from joserfc.registry import HeaderParameter


#: JOSE header parameters this specification adds (Appendix F.1).
#:
#: ``trust_chain`` is accepted but not resolved: turning an OpenID Federation
#: trust chain into a trusted key is a decision this library does not make, and
#: callers supply a resolver instead. It is carried so that a proof using it is
#: not rejected out of hand.
OPENID4VCI_HEADERS = {
    "key_attestation": HeaderParameter("Key attestation JWT", "str", False),
    "trust_chain": HeaderParameter("OpenID Federation Trust Chain", "list[str]", False),
}

#: Largest JOSE header accepted by default, in bytes.
#:
#: joserfc defaults to 512, which is generous for a plain JOSE header and far
#: too small here. Measured sizes of realistic key proofs:
#:
#: =========================================  ======
#: proof without an attestation                  236
#: attestation, one attested key                 952
#: attestation, five attested keys             1 855
#: attestation, twenty attested keys           5 242
#: attestation with a one-certificate chain    3 582
#: attestation with a three-certificate chain  8 811
#: ten keys and a three-certificate chain     10 843
#: =========================================  ======
#:
#: The default leaves room above the largest of these. It is a bound, not a
#: budget: the header limit protects the parser from unauthenticated input, and
#: the real ceiling is the HTTP body limit a deployment sets in its reverse
#: proxy -- which is also the only one that helps when a Credential Request
#: carries a batch of proofs rather than one.
DEFAULT_MAX_HEADER_LENGTH = 16384

#: The measurements the default is derived from, kept as data so a test can
#: assert the default still clears them rather than trusting the table above.
PROOF_HEADER_MEASUREMENTS = {
    "proof without an attestation": 236,
    "attestation, one attested key": 952,
    "attestation, five attested keys": 1855,
    "attestation, twenty attested keys": 5242,
    "attestation with a one-certificate chain": 3582,
    "attestation with a three-certificate chain": 8811,
    "ten keys and a three-certificate chain": 10843,
}


def jose_registry(max_header_length: int = DEFAULT_MAX_HEADER_LENGTH) -> JWSRegistry:
    """Return a JWS registry for key proofs and key attestations.

    :param max_header_length: bytes of JOSE header to accept. Lower it when the
        deployment neither expects key attestations nor federation trust
        chains; there is no reason to parse more than can arrive.
    """
    registry = JWSRegistry(header_registry=OPENID4VCI_HEADERS)
    registry.max_header_length = max_header_length
    return registry


#: The registry used unless a caller passes another. Public, because anything
#: constructing a key proof -- a Wallet, or a test -- needs the same one.
DEFAULT_JOSE_REGISTRY = jose_registry()
