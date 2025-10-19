from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


VT_BASE = "https://www.virustotal.com/api/v3"


async def vt_ip_summary(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = {"x-apikey": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        data = r.json().get("data", {})
        attr = data.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation")
        return {
            "ok": True,
            "data": {
                "vt_last_analysis_stats": stats,
                "vt_reputation": reputation,
                "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
            },
        }

    return await with_exponential_backoff(_call)


