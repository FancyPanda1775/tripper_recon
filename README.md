# Netintel

Unified, async OSINT toolkit for IP, domain, URL, and ASN investigations. It uses a functional design with RORO interfaces, typed models (Pydantic v2), structured JSON logs, and provider clients for Cloudflare Radar, VirusTotal, Shodan, AbuseIPDB, IPInfo, and OTX. It exposes both a CLI (see `netintel` in [`pyproject.toml`](./pyproject.toml)) and a REST API server (see `netintel-api`), with secure defaults, rate limiting, and jittered backoff.

- CLI entrypoint: [`netintel/cli.py`](./netintel/cli.py)
- API server: [`netintel/api/server.py`](./netintel/api/server.py)
- Orchestrators: [`netintel/orchestrators.py`](./netintel/orchestrators.py)

## Usage

```
# Help and version
netintel --help
netintel --version

# IP investigation
netintel ip 8.8.8.8
netintel ip 8.8.8.8 --format json

# Domain investigation
netintel domain www.google.com
netintel domain www.google.com --format json

# ASN lookup
netintel asn 15169
netintel asn 15169 --format json
```

Flags
- `-o, --format console|json` - Output format (default: `console`).
- `-V, --version` - Print version and exit.
- `-h, --help` - Show command help.

## Techniques

- HTTP/2 with connection pooling using `httpx.AsyncClient` for lower latency and better multiplexing. See MDN on HTTP/2: https://developer.mozilla.org/docs/Web/HTTP/Overview#http2
- Explicit HTTP headers for `User-Agent` and `Accept` to improve API compatibility. MDN docs: `User-Agent` https://developer.mozilla.org/docs/Web/HTTP/Headers/User-Agent and `Accept` https://developer.mozilla.org/docs/Web/HTTP/Headers/Accept
- Jittered exponential backoff for transient errors and rate limits; aligns with `429 Too Many Requests` and `Retry-After` guidance. MDN: 429 https://developer.mozilla.org/docs/Web/HTTP/Status/429 and `Retry-After` https://developer.mozilla.org/docs/Web/HTTP/Headers/Retry-After
- Structured JSON logging (flat key/value events) for SIEM ingestion and correlation, implemented in [`netintel/utils/logging.py`](./netintel/utils/logging.py).
- Async DNS resolution and reverse PTR lookups offloaded to threads to avoid blocking the event loop; see [`netintel/utils/dns.py`](./netintel/utils/dns.py). MDN DNS basics: https://developer.mozilla.org/docs/Glossary/DNS
- Dependency injection of a shared `httpx` client and env-driven API keys to keep functions pure and testable; RORO (Receive an Object, Return an Object) throughout the toolchain.
- Guard clauses and early returns to handle invalid inputs fast (e.g., malformed IPs/domains/ASNs) and keep the happy path last.
- Provider composition: results are normalized and merged by orchestrators to render consolidated reports; console formatting aligns with your example outputs in [`netintel/reporting/console.py`](./netintel/reporting/console.py).

## Notable Libraries

- httpx (async HTTP client with HTTP/2): https://www.python-httpx.org
- FastAPI (typed, async web framework): https://fastapi.tiangolo.com
- Pydantic v2 (data validation): https://docs.pydantic.dev
- Uvicorn (ASGI server): https://www.uvicorn.org
- python-dotenv (load `.env`): https://saurabh-kumar.com/python-dotenv
- Sublist3r (subdomain enumeration): https://github.com/aboul3la/Sublist3r
- iplyzer (IP enrichment tool): https://github.com/mxm0z/iplyzer

Provider APIs
- Cloudflare Radar (GraphQL used for ASN metadata): https://developers.cloudflare.com/api
- VirusTotal v3: https://docs.virustotal.com/reference/overview
- Shodan: https://developer.shodan.io/api
- AbuseIPDB: https://www.abuseipdb.com/api.html
- IPInfo: https://ipinfo.io/developers
- AlienVault OTX: https://otx.alienvault.com/api

Fonts
- No custom fonts are used.

## Project Structure

```
.
├─ README.md
├─ pyproject.toml
├─ .gitignore
├─ .env.example
├─ .env
└─ netintel/
   ├─ api/
   ├─ enumerators/
   ├─ providers/
   ├─ reporting/
   ├─ types/
   └─ utils/
```

- netintel/api: FastAPI app and launch function; see [`netintel/api/server.py`](./netintel/api/server.py).
- netintel/enumerators: Subdomain enumeration (Sublist3r wrapper).
- netintel/providers: Cloudflare Radar, VirusTotal, Shodan, AbuseIPDB, IPInfo, OTX, and iplyzer wrappers.
- netintel/reporting: Console renderers that match your target formats.
- netintel/types: Pydantic models for input/output and settings.
- netintel/utils: HTTP client factory, rate limiter, backoff, DNS helpers, `.env` loader, validation, and JSON logger.

## File Highlights

- CLI: [`netintel/cli.py`](./netintel/cli.py) - Commands for IP, domain, and ASN. Auto-loads `.env`.
- API Server: [`netintel/api/server.py`](./netintel/api/server.py) - Endpoints: `/ip/{ip}`, `/domain/{domain}`, `/asn/{asn}`.
- Orchestrators: [`netintel/orchestrators.py`](./netintel/orchestrators.py) - Async flows that combine providers per target type.
- Providers:
  - Cloudflare Radar GraphQL: [`netintel/providers/cloudflare_radar.py`](./netintel/providers/cloudflare_radar.py)
  - VirusTotal: [`netintel/providers/virustotal.py`](./netintel/providers/virustotal.py)
  - Shodan: [`netintel/providers/shodan_api.py`](./netintel/providers/shodan_api.py)
  - AbuseIPDB: [`netintel/providers/abuseipdb.py`](./netintel/providers/abuseipdb.py)
  - IPInfo: [`netintel/providers/ipinfo.py`](./netintel/providers/ipinfo.py)
  - AlienVault OTX: [`netintel/providers/otx.py`](./netintel/providers/otx.py)
  - iplyzer wrapper: [`netintel/providers/iplyzer_wrapper.py`](./netintel/providers/iplyzer_wrapper.py)
- Reporting: [`netintel/reporting/console.py`](./netintel/reporting/console.py) - Renders summaries aligned to your example outputs.
- Utilities:
  - JSON logging: [`netintel/utils/logging.py`](./netintel/utils/logging.py)
  - HTTP client + rate limiting: [`netintel/utils/http.py`](./netintel/utils/http.py)
  - Backoff: [`netintel/utils/backoff.py`](./netintel/utils/backoff.py)
  - DNS helpers: [`netintel/utils/dns.py`](./netintel/utils/dns.py)
  - Validation: [`netintel/utils/validation.py`](./netintel/utils/validation.py)
  - Env loader: [`netintel/utils/env.py`](./netintel/utils/env.py)

## Configuration

- The CLI and API auto-load a `.env` file when present; see [`netintel/utils/env.py`](./netintel/utils/env.py).
- Example configuration: [`.env.example`](./.env.example)
- Supported keys: `CLOUDFLARE_API_TOKEN`, `VT_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`, `OTX_API_KEY`, `NETINTEL_LOG_LEVEL`, `NETINTEL_UA`.

