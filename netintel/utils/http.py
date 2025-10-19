from __future__ import annotations

import asyncio
import os
from typing import Any, Dict

import httpx


def default_headers() -> Dict[str, str]:
    return {
        "User-Agent": os.getenv("NETINTEL_UA", "netintel/0.1 (+https://example.invalid)"),
        "Accept": "application/json",
    }


def create_client(timeout: float = 15.0) -> httpx.AsyncClient:
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    transport = httpx.AsyncHTTPTransport(retries=0)
    return httpx.AsyncClient(
        headers=default_headers(),
        http2=True,
        timeout=httpx.Timeout(timeout),
        limits=limits,
        transport=transport,
        verify=True,
    )


class RateLimiter:
    def __init__(self, rate: int = 5):
        self._sem = asyncio.Semaphore(rate)

    async def __aenter__(self) -> "RateLimiter":
        await self._sem.acquire()
        return self

    async def __aexit__(self, *_: Any) -> None:
        self._sem.release()

