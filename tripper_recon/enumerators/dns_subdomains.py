from __future__ import annotations

import asyncio
from typing import List

from tripper_recon.utils.validation import dedupe_preserve_order


async def enumerate_subdomains(domain: str, *, max_results: int = 200) -> List[str]:
    try:
        import sublist3r  # type: ignore
    except Exception:
        return []

    def _run() -> List[str]:
        try:
            # sublist3r has a synchronous interface; limit bruteforce, threads for safety.
            results = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            return dedupe_preserve_order(results)[:max_results]
        except Exception:
            return []

    return await asyncio.to_thread(_run)


