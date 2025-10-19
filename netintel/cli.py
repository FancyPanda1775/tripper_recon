from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any
from pathlib import Path
from urllib.parse import urlparse

from netintel import __version__
from netintel.orchestrators import investigate_asn, investigate_domain, investigate_ip
from netintel.reporting.console import render_ip_analysis, render_asn_header
from netintel.utils.logging import logger
from netintel.utils.env import load_env


log = logger("cli")


def _print(s: str) -> None:
    os.sys.stdout.write(s)


async def _cmd_ip(ip: str, *, output: str = "console", ports_limit: str = "25") -> int:
    res = await investigate_ip(ip)
    if not res.ok:
        log["error"]("IP investigation failed", ip=ip, errors=res.errors)
        return 1
    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
    else:
        _print(render_ip_analysis(ip, res.data, ports_limit=ports_limit))
    return 0


async def _cmd_domain(domain: str, *, output: str = "console", ports_limit: str = "25") -> int:
    from urllib.parse import urlparse
    parsed = urlparse(domain)
    norm_domain = parsed.hostname or domain.strip().strip("/")

    res = await investigate_domain(norm_domain)
    if not res.ok:
        log["error"]("Domain investigation failed", domain=domain, errors=res.errors)
        return 1

    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
        return 0

    ips = res.data.get("ips", [])

# Dynamic boxed header (ASCII to avoid encoding issues)
    line = f"| Domain lookup for {norm_domain} |"
    top = "+" + ("-" * (len(line) - 2)) + "+"
    bottom = "+" + ("-" * (len(line) - 2)) + "+"
    _print(top + "\n" + line + "\n" + bottom + "\n\n")

    _print(f'- Resolving "{norm_domain}"... {len(ips)} IP addresses found:\n\n\n')

    for item in ips:
        ip = item.get("ip")
        if ip:
            _print(f"ip: {ip}\n")

        ipinfo = item.get("ipinfo", {})
        city = ipinfo.get("city")
        if city:
            _print(f"city: {city}\n")
        
        country = ipinfo.get("country")
        if country:
            _print(f"country: {country}\n")

        asn_meta = item.get("asn_meta", {})
        asn = asn_meta.get("asn")
        name = asn_meta.get("name")
        if asn and name:
            _print(f"isp: AS{asn} {name}\n")
            _print(f"organization: AS{asn} {name}\n")

        coords = ipinfo.get("loc")
        if coords:
            _print(f"coordinates: {coords}\n")

        postal = ipinfo.get("postal")
        if postal:
            _print(f"postal_code: {postal}\n")

        vt_obj = item.get("virustotal", {})
        vt_stats = vt_obj.get("vt_last_analysis_stats", {})
        vt_mal = vt_stats.get("malicious", 0)
        vt_total = sum(vt_stats.values())
        _print(f"virustotal_detections: {vt_mal}/{vt_total}\n")

        vt_community_score = vt_obj.get("reputation", 0)
        _print(f"virustotal_community_score: {vt_community_score}\n")
        
        vt_link = vt_obj.get("vt_link")
        if vt_link:
            _print(f"virustotal_analysis_link: {vt_link}\n")

        abuse = item.get("abuseipdb", {})
        if abuse:
            reports = abuse.get("abuseipdb_reports", 0)
            confidence = abuse.get("abuseipdb_confidence_score", 0)
            _print(f"abuseipdb_reports: {reports}\n")
            _print(f"abuseipdb_confidence_score: {confidence}%\n")

        sh = item.get("shodan", {})
        open_ports = sh.get("ports", [])
        if open_ports:
            ports_sorted = sorted(open_ports)
            
            if str(ports_limit).lower() == 'all':
                max_show = len(ports_sorted)
            else:
                try:
                    limit = int(ports_limit)
                    max_show = limit if limit > 0 else 25
                except (ValueError, TypeError):
                    max_show = 25

            shown = ports_sorted[:max_show]
            more = len(ports_sorted) - len(shown)
            ports_str = ", ".join(str(p) for p in shown)
            if more > 0:
                ports_str += f" ... and {more} more"
            _print(f"open_ports: {ports_str}\n")

    return 0

 


def _default_output_dir() -> Path:
    # Standard output directory at project root: netintel/outputs
    here = Path(__file__).resolve()
    root = here.parent.parent  # netintel/
    out_dir = root / "outputs"
    return out_dir


async def _cmd_asn(
    asn: int,
    *,
    output: str = "console",
    neighbors: int = 8,
    enrich: bool = False,
    enrich_limit: int = 50,
    monochrome: bool = False,
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    res = await investigate_asn(asn, resolve_neighbors=neighbors, enrich=enrich, enrich_limit=enrich_limit)
    if not res.ok:
        log["error"]("ASN lookup failed", asn=asn, errors=res.errors)
        return 1
    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
    else:
        meta = res.data.get("meta", {})
        from netintel.reporting.console import render_asn_header, render_asn_bgp_panels
        # Print a boxed header matching the BGP panel style
        name = meta.get("name") or ""
        _print("╭───────────────────────────────────────────╮\n")
        _print((f"│ ASN lookup for AS{asn} ({name}) │\n") if name else (f"│ ASN lookup for AS{asn} │\n"))
        # Exactly one blank line after the boxed heading
        _print("╰───────────────────────────────────────────╯\n\n")
        # Then print details from renderer, skipping its internal header lines
        hdr = render_asn_header(asn, meta, use_color=(not monochrome))
        hdr_lines = hdr.splitlines()
        # Defensive: skip first two lines if they are the internal header; otherwise print all
        if len(hdr_lines) >= 3 and (hdr_lines[0].strip().startswith("ASN lookup") or ("AS Number" in (hdr_lines[2] if len(hdr_lines) > 2 else ""))):
            _print("\n".join(hdr_lines[2:]) + "\n")
        else:
            _print(hdr)
        # Ensure Peering @IXPs line is present
        if "Peering @IXPs" not in hdr:
            ixps = meta.get("ixps") or []
            ixp_names = []
            if isinstance(ixps, list):
                for i in ixps:
                    if isinstance(i, dict) and i.get("name"):
                        ixp_names.append(str(i.get("name")))
            if ixp_names:
                _print(f" Peering @IXPs ──> {' • '.join(ixp_names)}\n")
            else:
                _print(" Peering @IXPs ──> NONE\n")
        if not meta:
            _print("Note: Cloudflare Radar API token missing or request failed. Set CLOUDFLARE_API_TOKEN in .env for full ASN details.\n")
        bgp = res.data.get("bgp", {})
        if bgp:
            # Ensure a blank line before the BGP informations heading
            _print("\n")
            _print(render_asn_bgp_panels(asn, meta, bgp, use_color=(not monochrome)))
        # Optional: write full prefix lists to a text file
        if prefixes_out:
            v4_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v4") or []
            v6_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v6") or []
            name = meta.get("name") or ""
            out_lines: list[str] = []
            out_lines.append("╭──────────────────────────────────────────────────╮")
            title = f"│ Aggregated IP resources for AS{asn} ({name}) │" if name else f"│ Aggregated IP resources for AS{asn} │"
            out_lines.append(title)
            out_lines.append("╰──────────────────────────────────────────────────╯")
            out_lines.append("")
            if prefixes in ("v4", "both"):
                out_lines.append("───── IPv4 ─────")
                if v4_full:
                    out_lines.extend([str(p) for p in v4_full])
                else:
                    out_lines.append("NONE")
                if prefixes == "both":
                    out_lines.append("")
            if prefixes in ("v6", "both"):
                out_lines.append("───── IPv6 ─────")
                if v6_full:
                    out_lines.extend([str(p) for p in v6_full])
                else:
                    out_lines.append("NONE")

            # Resolve output path: if only a filename is provided, write to the standard outputs/ directory
            out_path = Path(prefixes_out)
            if not out_path.parent or str(out_path.parent) == ".":
                out_dir = _default_output_dir()
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / out_path.name
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
                log["info"]("Wrote prefix list", path=str(out_path))
            except Exception as e:
                log["error"]("Failed writing prefixes file", path=str(out_path), error=str(e))
    return 0


def main() -> None:
    # Load .env if present
    load_env()
    parser = argparse.ArgumentParser(prog="netintel", description="Unified OSINT IP/Domain/ASN investigations")
    parser.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("-V", "--version", action="version", version=f"netintel {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_ip = sub.add_parser("ip", help="Investigate an IP address")
    p_ip.add_argument("ip", type=str)
    p_ip.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
    p_ip.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)")

    p_domain = sub.add_parser("domain", help="Investigate a domain")
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
    p_domain.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown per IP in console (use 'all' to show all)")


    p_asn = sub.add_parser("asn", help="Lookup ASN details")
    p_asn.add_argument("asn", type=str)
    p_asn.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
    p_asn.add_argument("--neighbors", type=int, default=8, help="Resolve first N neighbors to names")
    p_asn.add_argument("--enrich", action="store_true", help="Enrich prefix info via whois/pWhois (slower)")
    p_asn.add_argument("--enrich-limit", type=int, default=50, help="Limit inetnum lines during enrichment")
    p_asn.add_argument("--monochrome", action="store_true", help="Disable ANSI colors in console output")
    p_asn.add_argument("--prefixes-out", type=str, default=None, help="Write full prefix list to a text file")
    p_asn.add_argument("--prefixes", choices=["v4", "v6", "both"], default="both", help="Which prefixes to include when writing --prefixes-out")

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        raise SystemExit(2)

    match args.cmd:
        case "ip":
            code = asyncio.run(_cmd_ip(args.ip, output=args.format, ports_limit=getattr(args, "ports_limit", "25")))
        case "domain":
            code = asyncio.run(_cmd_domain(args.domain, output=args.format, ports_limit=getattr(args, "ports_limit", "25")))
        case "asn":
            asn_str = str(args.asn).strip()
            if asn_str.lower().startswith("as"):
                asn_str = asn_str[2:]
            try:
                asn_int = int(asn_str)
            except Exception:
                log["error"]("Invalid ASN provided", asn=args.asn)
                code = 2
            else:
                code = asyncio.run(_cmd_asn(
                    asn_int,
                    output=args.format or "console",
                    neighbors=args.neighbors,
                    enrich=args.enrich,
                    enrich_limit=args.enrich_limit,
                    monochrome=args.monochrome,
                    prefixes_out=getattr(args, "prefixes_out", None),
                    prefixes=getattr(args, "prefixes", "both"),
                ))
        case _:
            code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
