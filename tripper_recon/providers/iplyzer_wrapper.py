from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from typing import Any, Dict

from tripper_recon.utils.validation import is_valid_ip


async def run_iplyzer_cli(ip: str) -> Dict[str, Any]:
    if not is_valid_ip(ip):
        return {"ok": False, "error": "invalid_ip"}

    exe = shutil.which("iplyzer")
    if not exe:
        return {"ok": False, "error": "iplyzer_not_found"}

    # Best-effort JSON mode; if iplyzer doesn't support --json, this will fail gracefully.
    def _call() -> Dict[str, Any]:
        try:
            proc = subprocess.run([exe, ip, "--json"], check=True, capture_output=True, text=True)
            return {"ok": True, "data": json.loads(proc.stdout)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return await asyncio.to_thread(_call)


