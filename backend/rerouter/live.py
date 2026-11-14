"""In-process publish/subscribe hub feeding the WebSocket stream."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, AsyncIterator


class LiveHub:
    def __init__(self, queue_size: int = 256):
        self._subscribers: set[asyncio.Queue] = set()
        self._queue_size = queue_size

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, topic: str, data: Any) -> None:
        msg = {"topic": topic, "data": data}
        for q in list(self._subscribers):
            if q.full():
                # Slow consumer: drop its oldest message rather than block producers.
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            q.put_nowait(msg)

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(q)
        try:
            yield q
        finally:
            self._subscribers.discard(q)
