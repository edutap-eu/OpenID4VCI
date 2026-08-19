"""The in-memory reference backend."""

from openid4vci.exceptions import CredentialRequestError
from openid4vci.exceptions import DeferredCredentialError
from openid4vci.models.credential import CredentialRequest
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.notification import NotificationRequest
from openid4vci.reference import InMemoryIssuerBackend
from openid4vci.reference import InMemoryNonceStore
from openid4vci.reference import InMemoryTransactionStore

import pytest


ISSUER = "https://issuer.example.edu"

METADATA = {
    "credential_issuer": ISSUER,
    "credential_endpoint": f"{ISSUER}/credential",
    "nonce_endpoint": f"{ISSUER}/nonce",
    "credential_configurations_supported": {
        "StudentCredential": {"format": "dc+sd-jwt"}
    },
}


class Clock:
    """A clock the tests move by hand."""

    def __init__(self, now=1_766_000_000):
        self.now = now

    def __call__(self):
        return self.now


# --- nonce store ------------------------------------------------------------


def test_a_freshly_issued_nonce_is_current():
    store = InMemoryNonceStore(now=Clock())

    nonce = store.issue()

    assert store.is_current(nonce)


def test_nonces_differ():
    store = InMemoryNonceStore(now=Clock())

    assert store.issue() != store.issue()


def test_an_unknown_nonce_is_not_current():
    store = InMemoryNonceStore(now=Clock())

    assert not store.is_current("never-issued")


def test_a_nonce_expires():
    clock = Clock()
    store = InMemoryNonceStore(ttl_seconds=300, now=clock)
    nonce = store.issue()

    clock.now += 301

    assert not store.is_current(nonce)


def test_a_consumed_nonce_cannot_be_used_twice():
    """A replayed proof is exactly what the nonce exists to prevent."""
    store = InMemoryNonceStore(now=Clock())
    nonce = store.issue()

    assert store.consume(nonce)
    assert not store.consume(nonce)
    assert not store.is_current(nonce)


def test_expired_nonces_do_not_accumulate():
    clock = Clock()
    store = InMemoryNonceStore(ttl_seconds=10, now=clock)
    for _ in range(5):
        store.issue()

    clock.now += 11
    store.issue()

    assert len(store) == 1


# --- transaction store ------------------------------------------------------


def test_a_transaction_can_be_opened_and_answered():
    store = InMemoryTransactionStore()
    transaction_id = store.open({"subject": "student-1"})

    assert store.payload(transaction_id) == {"subject": "student-1"}

    store.close(transaction_id)
    assert store.payload(transaction_id) is None


def test_an_unknown_transaction_is_unknown():
    assert InMemoryTransactionStore().payload("nope") is None


# --- backend ----------------------------------------------------------------


async def mint(request, context):
    return CredentialResponse.model_validate(
        {
            "credentials": [
                {"credential": f"credential-for-{request.credential_configuration_id}"}
            ]
        }
    )


@pytest.fixture
def backend():
    return InMemoryIssuerBackend(metadata=METADATA, mint=mint)


async def test_the_backend_serves_the_metadata_it_was_given(backend):
    metadata = await backend.issuer_metadata()

    assert metadata.credential_issuer == ISSUER


async def test_the_backend_issues_a_nonce_that_its_store_knows(backend):
    nonce = await backend.create_nonce()

    assert backend.nonces.is_current(nonce)


async def test_issuing_delegates_to_the_mint(backend):
    request = CredentialRequest.model_validate(
        {"credential_configuration_id": "StudentCredential"}
    )

    response = await backend.issue_credential(request, context=None)

    assert response.credentials is not None
    assert response.credentials[0].credential == "credential-for-StudentCredential"


async def test_an_unknown_configuration_is_refused(backend):
    """The backend answers with the code the specification defines for this."""
    request = CredentialRequest.model_validate(
        {"credential_configuration_id": "SomethingElse"}
    )

    with pytest.raises(CredentialRequestError) as caught:
        await backend.issue_credential(request, context=None)

    assert caught.value.code.value == "unknown_credential_configuration"


async def test_an_unknown_transaction_is_refused(backend):
    from openid4vci.models.deferred import DeferredCredentialRequest

    with pytest.raises(DeferredCredentialError):
        await backend.issue_deferred(
            DeferredCredentialRequest(transaction_id="never-opened"), context=None
        )


async def test_notifications_are_recorded(backend):
    await backend.notify(
        NotificationRequest.model_validate(
            {"notification_id": "3fwe98js", "event": "credential_accepted"}
        ),
        context=None,
    )

    assert backend.notifications[0].notification_id == "3fwe98js"
