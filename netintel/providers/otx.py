from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from netintel.utils.backoff import with_exponential_backoff


OTX_BASE = "https://otx.alienvault.com/api/v1"


async def otx_ip_pulses(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{OTX_BASE}/indicators/IPv4/{ip}/general", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        j = r.json()
        pulses = j.get("pulse_info", {}).get("pulses", [])
        return {
            "ok": True,
            "data": {
                "otx_pulse_count": len(pulses),
                "otx_pulse_titles": [p.get("name") for p in pulses[:5]],
            },
        }

    return await with_exponential_backoff(_call)

