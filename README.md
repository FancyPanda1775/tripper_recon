# tripper-recon

Unified, async OSINT toolkit for IP, domain, URL, and ASN investigations. It uses a functional design with RORO interfaces, typed models (Pydantic v2), structured JSON logs, and provider clients for Cloudflare Radar, VirusTotal, Shodan, AbuseIPDB, IPInfo, and OTX. It exposes both a CLI (see `tripper-recon` in [`pyproject.toml`](./pyproject.toml)) and a REST API server (see `tripper-recon-api`), with secure defaults, rate limiting, and jittered backoff.

- CLI entrypoint: [`tripper_recon/cli.py`](./tripper_recon/cli.py)
- API server: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py)
- Orchestrators: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py)

## Usage

```
# Help and version
tripper-recon --help
tripper-recon --version

# IP investigation
tripper-recon ip 8.8.8.8
tripper-recon ip 8.8.8.8 --format json

# Domain investigation
tripper-recon domain www.google.com
tripper-recon domain www.google.com --format json

# ASN lookup
tripper-recon asn 15169
tripper-recon asn 15169 --format json
```

Flags
- `-o, --format console|json` - Output format (default: `console`).
- `-V, --version` - Print version and exit.
- `-h, --help` - Show command help.

### CLI Commands

- `tripper-recon --help` — top-level usage and global flags.
- `tripper-recon ip <ip>` — investigate an IP address.
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon domain <domain>` — investigate a domain or URL.
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon asn <asn>` — investigate an Autonomous System Number.
  - `--format console|json`
  - `--neighbors <N>`
  - `--enrich`
  - `--enrich-limit <N>`
  - `--monochrome`
  - `--prefixes-out <path>`
  - `--prefixes v4|v6|both`
- `tripper-recon-api` — launch the FastAPI server (see `tripper_recon/api/server.py`).
- Python module alternative: `python -m tripper_recon.cli ...`

## Techniques

- HTTP/2 with connection pooling using `httpx.AsyncClient` for lower latency and better multiplexing. See MDN on HTTP/2: https://developer.mozilla.org/docs/Web/HTTP/Overview#http2
- Explicit HTTP headers for `User-Agent` and `Accept` to improve API compatibility. MDN docs: `User-Agent` https://developer.mozilla.org/docs/Web/HTTP/Headers/User-Agent and `Accept` https://developer.mozilla.org/docs/Web/HTTP/Headers/Accept
- Jittered exponential backoff for transient errors and rate limits; aligns with `429 Too Many Requests` and `Retry-After` guidance. MDN: 429 https://developer.mozilla.org/docs/Web/HTTP/Status/429 and `Retry-After` https://developer.mozilla.org/docs/Web/HTTP/Headers/Retry-After
- Structured JSON logging (flat key/value events) for SIEM ingestion and correlation, implemented in [`tripper_recon/utils/logging.py`](./tripper_recon/utils/logging.py).
- Async DNS resolution and reverse PTR lookups offloaded to threads to avoid blocking the event loop; see [`tripper_recon/utils/dns.py`](./tripper_recon/utils/dns.py). MDN DNS basics: https://developer.mozilla.org/docs/Glossary/DNS
- Dependency injection of a shared `httpx` client and env-driven API keys to keep functions pure and testable; RORO (Receive an Object, Return an Object) throughout the toolchain.
- Guard clauses and early returns to handle invalid inputs fast (e.g., malformed IPs/domains/ASNs) and keep the happy path last.
- Provider composition: results are normalized and merged by orchestrators to render consolidated reports; console formatting aligns with your example outputs in [`tripper_recon/reporting/console.py`](./tripper_recon/reporting/console.py).

## Notable Libraries

- httpx (async HTTP client with HTTP/2): https://www.python-httpx.org
- FastAPI (typed, async web framework): https://fastapi.tiangolo.com
- Pydantic v2 (data validation): https://docs.pydantic.dev
- Uvicorn (ASGI server): https://www.uvicorn.org
- python-dotenv (load `.env`): https://saurabh-kumar.com/python-dotenv

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

`
.
- README.md
- pyproject.toml
- .gitignore
- .env.example
- .env
- tripper_recon/
  - api/
  - providers/
  - reporting/
  - types/
  - utils/
`
## File Highlights

- CLI: [`tripper_recon/cli.py`](./tripper_recon/cli.py) - Commands for IP, domain, and ASN. Auto-loads `.env`.
- API Server: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py) - Endpoints: `/ip/{ip}`, `/domain/{domain}`, `/asn/{asn}`.
- Orchestrators: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py) - Async flows that combine providers per target type.
- Providers:
  - Cloudflare Radar GraphQL: [`tripper_recon/providers/cloudflare_radar.py`](./tripper_recon/providers/cloudflare_radar.py)
  - VirusTotal: [`tripper_recon/providers/virustotal.py`](./tripper_recon/providers/virustotal.py)
  - Shodan: [`tripper_recon/providers/shodan_api.py`](./tripper_recon/providers/shodan_api.py)
  - AbuseIPDB: [`tripper_recon/providers/abuseipdb.py`](./tripper_recon/providers/abuseipdb.py)
  - IPInfo: [`tripper_recon/providers/ipinfo.py`](./tripper_recon/providers/ipinfo.py)
  - AlienVault OTX: [`tripper_recon/providers/otx.py`](./tripper_recon/providers/otx.py)
- Reporting: [`tripper_recon/reporting/console.py`](./tripper_recon/reporting/console.py) - Renders summaries aligned to your example outputs.
- Utilities:
  - JSON logging: [`tripper_recon/utils/logging.py`](./tripper_recon/utils/logging.py)
  - HTTP client + rate limiting: [`tripper_recon/utils/http.py`](./tripper_recon/utils/http.py)
  - Backoff: [`tripper_recon/utils/backoff.py`](./tripper_recon/utils/backoff.py)
  - DNS helpers: [`tripper_recon/utils/dns.py`](./tripper_recon/utils/dns.py)
  - Validation: [`tripper_recon/utils/validation.py`](./tripper_recon/utils/validation.py)
  - Env loader: [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py)

## Configuration

- The CLI and API auto-load a `.env` file when present; see [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py).
- Example configuration: [`.env.example`](./.env.example)
- Supported keys: `CLOUDFLARE_API_TOKEN`, `VT_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`, `OTX_API_KEY`, `NETINTEL_LOG_LEVEL`, `NETINTEL_UA`.





