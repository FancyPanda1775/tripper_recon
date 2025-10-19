from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List

from netintel.providers.abuseipdb import abuseipdb_check
from netintel.providers.cloudflare_radar import fetch_asn_metadata
from netintel.providers.ipinfo import ipinfo_ip, ipinfo_asn
from netintel.providers.otx import otx_ip_pulses
from netintel.providers.shodan_api import shodan_host
from netintel.providers.virustotal import vt_ip_summary
from netintel.types.models import ApiKeys, InvestigationResult
from netintel.utils.dns import resolve_domain, reverse_ptr
from netintel.utils.http import RateLimiter, create_client
from netintel.utils.logging import logger
from netintel.utils.validation import dedupe_preserve_order, is_valid_asn, is_valid_domain, is_valid_ip
from netintel.providers.bgpview import bgpview_asn
from netintel.providers.ripestat import as_overview, abuse_contact, routing_status, asn_neighbours, announced_prefixes
from netintel.providers.caida import caida_asrank
from netintel.providers.peeringdb import peeringdb_ixps_for_asn
from netintel.providers.cloudflare_rest import bgp_incidents


log = logger("orchestrators")


def _env_keys() -> ApiKeys:
    return ApiKeys(
        cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN"),
        vt_api_key=os.getenv("VT_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipinfo_token=os.getenv("IPINFO_TOKEN"),
        otx_api_key=os.getenv("OTX_API_KEY"),
    )


async def investigate_ip(ip: str) -> InvestigationResult:
    if not is_valid_ip(ip):
        return InvestigationResult(ok=False, errors=["Invalid IP address"], data={})

    keys = _env_keys()
    async with create_client() as client:
        limiter = RateLimiter(rate=5)
        vt_task = ipi_task = sh_task = ab_task = otx_task = None

        async with limiter:
            vt_task = asyncio.create_task(vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip))
        async with limiter:
            ipi_task = asyncio.create_task(ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip))
        async with limiter:
            sh_task = asyncio.create_task(shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip))
        async with limiter:
            ab_task = asyncio.create_task(abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip))
        async with limiter:
            otx_task = asyncio.create_task(otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip))

        vt = await vt_task
        ipi = await ipi_task
        sh = await sh_task
        ab = await ab_task
        otx = await otx_task

        asn_meta: Dict[str, Any] = {}
        if ipi.get("ok") and ipi["data"].get("asn"):
            asn = int(ipi["data"]["asn"])  # type: ignore[arg-type]
            cf = await fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn)
            if cf.get("ok"):
                asn_meta = cf["data"]

        data: Dict[str, Any] = {
            "ipinfo": ipi.get("data", {}) if ipi.get("ok") else {},
            "virustotal": vt.get("data", {}) if vt.get("ok") else {},
            "shodan": sh.get("data", {}) if sh.get("ok") else {},
            "abuseipdb": ab.get("data", {}) if ab.get("ok") else {},
            "otx": otx.get("data", {}) if otx.get("ok") else {},
            "asn_meta": asn_meta,
        }

        return InvestigationResult(ok=True, data=data)


async def investigate_domain(domain: str) -> InvestigationResult:
    if not is_valid_domain(domain):
        return InvestigationResult(ok=False, errors=["Invalid domain"], data={})
    ips = await resolve_domain(domain)
    ips = dedupe_preserve_order(ips)
    keys = _env_keys()
    out: List[Dict[str, Any]] = []
    async with create_client() as client:
        for ip in ips:
            ptr = await reverse_ptr(ip)
            vt = await vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip)
            sh = await shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip)
            ipi = await ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip)
            ab = await abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip)

            asn_meta: Dict[str, Any] = {}
            if ipi.get("ok") and ipi["data"].get("asn"):
                asn = int(ipi["data"]["asn"])  # type: ignore[arg-type]
                cf = await fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn)
                if cf.get("ok"):
                    asn_meta = cf["data"]
                else:
                    bgp = await bgpview_asn(client=client, asn=asn)
                    if bgp.get("ok"):
                        bv = bgp.get("data", {})
                        asn_meta = {
                            "asn": asn,
                            "name": bv.get("name"),
                            "organization": bv.get("organization"),
                            "ixps": bv.get("ixps", []),
                        }

            out.append(
                {
                    "ip": ip,
                    "ptr": ptr,
                    "virustotal": vt.get("data", {}) if vt.get("ok") else {},
                    "shodan": sh.get("data", {}) if sh.get("ok") else {},
                    "ipinfo": ipi.get("data", {}) if ipi.get("ok") else {},
                    "abuseipdb": ab.get("data", {}) if ab.get("ok") else {},
                    "asn_meta": asn_meta,
                }
            )

    return InvestigationResult(ok=True, data={"domain": domain, "ips": out})


async def investigate_asn(asn: int | str, *, resolve_neighbors: int = 0, enrich: bool = False, enrich_limit: int = 50) -> InvestigationResult:
    if not is_valid_asn(asn):
        return InvestigationResult(ok=False, errors=["Invalid ASN"], data={})
    asn_int = int(asn)
    keys = _env_keys()
    async with create_client() as client:
        # Kick off IPinfo ASN in parallel with Cloudflare when possible
        ipi_task = asyncio.create_task(ipinfo_asn(client=client, token=keys.ipinfo_token, asn=asn_int))
        bgp_task = asyncio.create_task(bgpview_asn(client=client, asn=asn_int))
        ripe_overview_task = asyncio.create_task(as_overview(client=client, asn=asn_int))
        ripe_abuse_task = asyncio.create_task(abuse_contact(client=client, asn=asn_int))
        caida_task = asyncio.create_task(caida_asrank(client=client, asn=asn_int))
        pdb_task = asyncio.create_task(peeringdb_ixps_for_asn(client=client, asn=asn_int))
        cf_bgp_task = asyncio.create_task(bgp_incidents(client=client, api_token=keys.cloudflare_api_token, asn=asn_int))

        cf_task = None
        if keys.cloudflare_api_token:
            cf_task = asyncio.create_task(fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn_int))

        ipi = await ipi_task
        bgp = await bgp_task
        ripe = await ripe_overview_task
        rp_abuse = await ripe_abuse_task
        caida = await caida_task
        pdb = await pdb_task
        cf_bgp = await cf_bgp_task
        rs_task = asyncio.create_task(routing_status(client=client, asn=asn_int))
        nb_task = asyncio.create_task(asn_neighbours(client=client, asn=asn_int))
        ap_task = asyncio.create_task(announced_prefixes(client=client, asn=asn_int))
        rs = await rs_task
        nb = await nb_task
        ap = await ap_task
        cf = await cf_task if cf_task else {"ok": False}

        meta: Dict[str, Any] = {}
        # Prefer Cloudflare values when present; fall back to IPinfo
        if cf.get("ok"):
            meta.update(cf["data"])  # type: ignore[index]
        if ipi.get("ok"):
            # Only set fields that are missing from CF
            for k, v in ipi["data"].items():  # type: ignore[index]
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if bgp.get("ok"):
            for k, v in bgp["data"].items():  # type: ignore[index]
                if k == "ixps":
                    # Merge IXP lists
                    existing = meta.get("ixps") or []
                    existing_names = {i.get("name") for i in existing if isinstance(i, dict) and i.get("name")}
                    new_names = {i.get("name") for i in v if isinstance(i, dict) and i.get("name")} if isinstance(v, list) else set()
                    names = sorted(existing_names | new_names)
                    if names:
                        meta["ixps"] = [{"name": n} for n in names]
                else:
                    if k not in meta or meta.get(k) in (None, ""):
                        meta[k] = v
        if ripe.get("ok"):
            holder = ripe["data"].get("holder")
            name = holder
            if name and ("-" in name):
                name = name.split(" - ", 1)[-1]
            if name and (not meta.get("name")):
                meta["name"] = name
            # Country code could be combined into name like asn tool; keep separate
        if rp_abuse.get("ok"):
            contacts = rp_abuse["data"].get("abuse_contacts") or []
            if contacts:
                meta["abuseContacts"] = contacts
        if caida.get("ok"):
            for k, v in caida["data"].items():
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if pdb.get("ok"):
            ixps = pdb["data"].get("ixps") or []
            existing = meta.get("ixps") or []
            existing_names = {i.get("name") for i in existing if isinstance(i, dict) and i.get("name")}
            new_names = {i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")}
            names = sorted(existing_names | new_names)
            if names:
                meta["ixps"] = [{"name": n} for n in names]

        # Attach CF BGP incidents summary if available
        meta_bgp: Dict[str, Any] = {}
        if cf_bgp.get("ok"):
            meta_bgp = cf_bgp.get("data", {})
        # Add RIPE routing counts
        if rs.get("ok"):
            d = rs.get("data", {})
            v4p = (d.get("announced_space", {}).get("v4", {}) or {}).get("prefixes")
            v6p = (d.get("announced_space", {}).get("v6", {}) or {}).get("prefixes")
            neigh = d.get("observed_neighbours")
            meta_bgp.update({
                "ripe_announced_prefixes_v4": v4p,
                "ripe_announced_prefixes_v6": v6p,
                "ripe_observed_neighbours": neigh,
            })
        # Add RIPE neighbours lists
        if nb.get("ok"):
            neighs = nb.get("data", {}).get("neighbours", [])
            upstream = [n.get("asn") for n in neighs if n.get("type") == "left"]
            downstream = [n.get("asn") for n in neighs if n.get("type") == "right"]
            uncertain = [n.get("asn") for n in neighs if n.get("type") == "uncertain"]
            meta_bgp.update({
                "ripe_upstream_asns": upstream,
                "ripe_downstream_asns": downstream,
                "ripe_uncertain_asns": uncertain,
            })
            # Optionally resolve first N neighbor names via RIPE as-overview
            if resolve_neighbors and resolve_neighbors > 0:
                to_resolve = set()
                for seq in (upstream[:resolve_neighbors], downstream[:resolve_neighbors], uncertain[:resolve_neighbors]):
                    for a in seq:
                        if isinstance(a, int):
                            to_resolve.add(a)
                name_map: Dict[int, str] = {}
                tasks = [asyncio.create_task(as_overview(client=client, asn=int(a))) for a in to_resolve]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for a, reso in zip(to_resolve, results):
                    if isinstance(reso, dict) and reso.get("ok"):
                        holder = reso.get("data", {}).get("holder")
                        if holder:
                            # Trim "ASNAME - Company" style
                            name = holder.split(" - ", 1)[-1] if " - " in holder else holder
                            name_map[int(a)] = name
                def _name_list(lst: list[int]) -> list[str]:
                    out: list[str] = []
                    for a in lst[:resolve_neighbors]:
                        nm = name_map.get(int(a))
                        out.append(f"{nm} ({a})" if nm else str(a))
                    return out
                meta_bgp.update({
                    "ripe_upstream_named": _name_list(upstream),
                    "ripe_downstream_named": _name_list(downstream),
                    "ripe_uncertain_named": _name_list(uncertain),
                })
        # Add announced prefixes lists (limited)
        if ap.get("ok"):
            prefs = ap.get("data", {}).get("prefixes", [])
            v4_list = [p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" not in p.get("prefix")]
            v6_list = [p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" in p.get("prefix")]
            meta_bgp.update({
                "ripe_prefixes_v4": v4_list,
                "ripe_prefixes_v6": v6_list,
            })
            # Optional enrichment: placeholder aggregation (fast). Full whois/pWhois can be added later.
            if enrich:
                inetnums = {
                    "v4": v4_list[:enrich_limit],
                    "v6": v6_list[:enrich_limit],
                    "other_v4": [],
                    "other_v6": [],
                }
                meta_bgp.update({"inetnums": inetnums})

        warnings: list[str] = []
        if not cf.get("ok"):
            warnings.append("cloudflare_query_failed_or_missing")
        if not ipi.get("ok"):
            warnings.append("ipinfo_query_failed_or_missing")
        if not bgp.get("ok"):
            warnings.append("bgpview_query_failed")
        if not ripe.get("ok"):
            warnings.append("ripestat_overview_failed")
        if not rp_abuse.get("ok"):
            warnings.append("ripestat_abuse_failed")
        if not caida.get("ok"):
            warnings.append("caida_failed")
        if not pdb.get("ok"):
            warnings.append("peeringdb_failed")

        return InvestigationResult(ok=True, data={"asn": asn_int, "meta": meta, "bgp": meta_bgp}, warnings=warnings)
