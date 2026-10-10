import pytest
from offline_pilot import (
    InMemoryBindingStore,
    OfflinePublisher,
    PublishOutcomeUnknown,
)


@pytest.mark.asyncio
async def test_publish_response_loss_does_not_bind_or_retry():
    store = InMemoryBindingStore()
    publisher = OfflinePublisher(store)
    with pytest.raises(PublishOutcomeUnknown):
        await publisher.publish_checkpoint('T', 'C', 'cp_1', lossy=True)
    assert publisher.message_counter == 1
    assert publisher.sent_messages[0]['public_id'] == 'cp_1'
    assert store.store == {}

@pytest.mark.asyncio
async def test_publish_binds_returned_message():
    store = InMemoryBindingStore()
    publisher = OfflinePublisher(store)
    ts = await publisher.publish_checkpoint('T', 'C', 'cp_1')
    assert await store.resolve('T', 'C', ts) == 'cp_1'
    assert publisher.message_counter == 1
