# Net Tools

A private, dark-themed, mobile-friendly suite for network discovery and diagnostics. Run it on an Ubuntu VM with Docker Compose and expose it through your existing Caddy server. **Subdomain Finder**, powered by [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder), is the first working tool.

The home page shows the tool directory and recent activity. Open Subdomain Finder to watch passive discovery results arrive with their IPv4 and IPv6 addresses, search them, and copy or download TXT, CSV, or JSON. Saved activity survives container recreation, and scans continue when your browser closes. You can cancel scans, restore options for another run, and delete old results. The interface works on phones without horizontal scrolling.

**Salesforce Detector** checks whether a site runs the Salesforce Aura/Lightning framework (Experience Cloud) and whether its guest user leaks data. Enter one target URL; the detector fingerprints the site, probes the unauthenticated Aura endpoint, and enumerates which standard and custom objects are readable by an anonymous guest, recording each object's total record count and a small sample of records (5–10 by default) as evidence. It is read-only — it counts and samples, never dumping full datasets — and classifies each target as *Not Salesforce*, *Salesforce* (guest access locked down), or *Leaking*. Only scan sites you own or are authorized to test. The checks combine the approach of Mandiant's [AuraInspector](https://github.com/google/aura-inspector) with related guest-access research. A built-in guard rejects private, loopback, link-local, and reserved addresses, so an internet-exposed instance cannot be aimed at internal services.

You can enter just a domain, such as `example.com`. The detector tries known Aura routes, reads relevant HTML links and literal bootstrap URLs, inspects up to three same-host scripts, and uses `robots.txt` and XML sitemaps (including sitemap indexes) to find community paths. Common community paths provide a fallback when no links are available. Explicitly linked subdomains and Salesforce-hosted communities under `*.my.site.com`, `*.force.com`, or `*.salesforce-sites.com` can be checked; unrelated external hosts are excluded. Canonical redirects such as `example.com` to `www.example.com` are followed within that scope, with public-address validation on every hop.

Discovery is bounded to 64 HTTP fetch calls (each with at most four redirect hops), 16 candidate pages, four hosts, and a 45-second discovery budget with at most three seconds per request hop. The job's existing time limit and object/sample limits still apply. It stops at the first confirmed Aura endpoint, then runs the existing object checks. The scan's JSON details include discovery counts, the selected candidate, its discovery source, and whether a discovery limit was reached. No additional executable or API key is required.

This is best-effort discovery: it does not execute JavaScript, enumerate DNS subdomains, guess tenant names, or find every unlinked community. A full community URL such as `https://example.com/partners/s/` is still accepted when known. A negative result means no endpoint was found in the locations checked, rather than proof that the organization has no Salesforce deployment.

The approach complements existing tools: [AuraInspector](https://github.com/google/aura-inspector) discovers Aura endpoints/context for an application URL; [Nuclei's Salesforce Aura template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/salesforce-aura.yaml) checks known route variants, including `/s/fact`; [Katana](https://docs.projectdiscovery.io/opensource/katana/usage) offers broader crawling, including JavaScript and known files. Salesforce documents `/s/sitemap.xml` for Aura sites in its [Experience Builder SEO guidance](https://help.salesforce.com/s/articleView?id=sf.networks_seo_best_practices.htm&language=en_US&type=5). The detector uses a small built-in discovery layer instead of adding one of these external tools as a runtime dependency.

| Page | Route | Status |
| --- | --- | --- |
| Home / tool directory | `/` | Available |
| Subdomain Finder | `/tools/subdomains` | Available |
| Salesforce Detector | `/tools/salesforce` | Available |
| Shared activity | `/activity` | Available |
| DNS Lookup | — | Planned |
| TLS Inspector | — | Planned |
| HTTP Inspector | — | Planned |

Planned tools are clearly marked and cannot be opened. All available pages share the same password login, navigation, and theme. Direct links, refreshes, and browser back/forward navigation are supported.

## Deploy on Ubuntu

Prerequisites: Docker Engine with the Compose plugin, Python 3 for the one-time setup, and Caddy on the host. Point your chosen domain's DNS A/AAAA records at the VM. Caddy needs public ports 80 and 443 to obtain and renew certificates. If you publish an AAAA record, the VM must also be reachable over IPv6.

Clone the repository on your VM, then run the setup:

```sh
git clone https://github.com/Darthcedeus/net-tools.git
cd net-tools
python3 scripts/setup.py
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8083/healthz
```

The setup prompts for the exact public origin, such as `https://net-tools.humza.xyz`, and a password of at least 12 characters. It creates a private `.env` containing a PBKDF2 password hash. Never send your password or provider keys to anyone. The origin is used for browser request checks and secure cookies; update it if you change the hostname. The app is served at the hostname root, not under a subpath.

Generate the Caddy site block from your existing `.env`:

```sh
python3 scripts/caddy_config.py
```

Copy that output into your host Caddyfile (usually `/etc/caddy/Caddyfile`), replacing only the existing Net Tools block and keeping your other sites. The generated block contains a **private proxy token**; do not commit or share it. It does not change `.env`, your password, or saved scans. Caddy overwrites the token and client-IP headers on every request so the app can safely apply separate login limits to separate clients. Ordinary `X-Forwarded-For` headers are ignored. This assumes Caddy receives public traffic directly; a CDN in front requires a separately reviewed client-identity setup. The header syntax follows the [Caddy reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

Validate and reload Caddy:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Open your public URL on your computer or phone and sign in. Compose publishes host port **8083 on all interfaces**, using `0.0.0.0:8083:8080`, and forwards it to port 8080 inside the container. Caddy can still use `127.0.0.1:8083` as its upstream. Browser access uses the configured public HTTPS origin; the VM's HTTP IP address will not match the login origin check.

### If Caddy also runs in Docker

Put Caddy and this service on a shared user-defined Docker network, remove the `ports` mapping from this service, and use `reverse_proxy subfinder:8080`. In a Caddy container, `127.0.0.1` refers to Caddy itself, not the Subfinder container. Keep Caddy's existing volumes for certificates. `APP_ORIGIN` stays the public HTTPS origin.

Keep both `header_up` directives from the generated block when changing the upstream address.

### Update an existing deployment

From the existing checkout on your VM:

```sh
git pull --ff-only
python3 scripts/caddy_config.py
# Replace only the Net Tools site block in /etc/caddy/Caddyfile with that output.
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
docker compose up -d --build
curl http://127.0.0.1:8083/healthz
```

Your existing `.env`, provider configuration, and saved scan volume are retained. You do not need to rerun setup if `APP_ORIGIN` already matches `https://net-tools.humza.xyz`. The service and volume keep their original `subfinder` / `subfinder-data` names to preserve deployed data.

**The Caddy block update is required when installing the client-specific login-limit fix.** With the old block, clients still share Caddy's socket IP. Once installed, the generated block stays valid across pulls; regenerate it only after changing the password or public hostname.

If Git refuses to pull because you previously edited `compose.yaml` to change the port, save that file and restore the tracked version before pulling. The updated version already includes `0.0.0.0:8083`:

```sh
cp compose.yaml compose.yaml.local-backup
git restore compose.yaml
git pull --ff-only
docker compose up -d --build
```

## Provider API keys (optional)

Subfinder works with public passive sources without keys. Additional sources require your own provider credentials; no provider credentials are entered or exposed in the web UI. Coverage depends on source availability, quotas, and the keys you configure. A successful scan with no results does not prove that a domain has no subdomains.

```sh
cp config/provider-config.example.yaml config/provider-config.yaml
# Edit provider-config.yaml on your VM to add your keys.
# The app runs as UID 10001; grant that UID read access without making keys public.
sudo chown 10001:10001 config/provider-config.yaml
sudo chmod 600 config/provider-config.yaml
docker compose -f compose.yaml -f compose.providers.yaml up -d --build
```

Example credential shape: `shodan: ["your-key"]`. Providers such as Censys have provider-specific formats; use the [official provider configuration instructions](https://docs.projectdiscovery.io/opensource/subfinder/install#post-install-configuration). The configuration is mounted read-only, excluded from Git and Docker build context, and never returned through the API. Continue using both `-f` arguments for later Compose commands when the overlay is enabled.

## Operation

- Password login is required for every scan, result, history, and export API. Sessions expire after 12 hours and are invalidated on app restart. Passwords use PBKDF2-SHA256 with a random salt and 600,000 iterations. Cookies are HttpOnly and SameSite=Strict; HTTPS origins add Secure. Mutations require an origin check and a session-specific CSRF token. Login is limited to 10 attempts per five minutes per client IP, with no shared five-minute lockout. Behind Caddy, the generated private token authenticates its client-IP header; direct requests use their socket IP. Devices sharing a public IP share the quota. At most two password verifications run concurrently; overload returns a temporary 503, without adding a login attempt. Tracking is bounded to 4,096 active client buckets.
- HTTP connections close after one response and have a hard 15-second lifetime, including incomplete headers, body trickles, and slow response reads. Limits allow 48 connections overall, eight per socket peer, and four active API/page requests per authenticated proxy client IP or direct socket IP. One watchdog enforces deadlines without creating a timer thread per connection. Large downloads must finish within the connection deadline; scans continue independently. These resource bounds do not replace upstream protection against distributed denial of service.
- One scan runs at a time; up to five more wait in the queue. Each scan has a configurable time limit (1–10 minutes), source timeout (5–60 seconds), and request rate (1–50/second). A hard wall-clock limit adds 30 seconds for cleanup. Results are capped at 10,000 per scan. Partial results survive cancellation, errors, timeouts, and restart.
- Discovery uses passive Subfinder sources. As each unique hostname arrives, up to eight DNS workers look up A and AAAA records through the container’s configured resolver, with a three-second lookup budget per hostname and the overall scan deadline. This adds DNS queries, but no HTTP requests, connections to discovered hosts, or port scans. Addresses are a snapshot taken during that scan; DNS resolution does not prove a service is live. No-record, timeout, partial, failed, and cancelled lookups are labeled separately. Existing saved scans retain their results and show “Not checked” for IPs; rerun them to resolve addresses. Use it for domains you own or have permission to assess.
- Scan records and results live in a SQLite database in the `subfinder-data` named volume. The latest 100 finished scans are retained, plus active jobs. Queued/running jobs become interrupted on restart and can be run again.
- Filtering matches subdomain names. Copy and export include **all matching results**, across every page. JSON includes scan metadata, source names, IP addresses, and DNS status. CSV includes `subdomain`, `sources`, `ip_addresses`, and `dns_status` columns. TXT and Copy remain one hostname per line.
- The container runs without root, with a read-only filesystem, dropped capabilities, bounded resources, and a writable temporary filesystem. No Docker socket is mounted. The frontend is plain HTML/CSS/JavaScript without npm, CDN, or font dependencies. The Python backend uses the standard library plus [dnspython](https://dnspython.readthedocs.io/en/stable/resolver-class.html) for DNS lookups with bounded timeouts; Docker installs the pinned dependency automatically.

Logs and health:

```sh
docker compose logs --tail=100 -f subfinder
docker compose ps
curl http://127.0.0.1:8083/healthz
```

Health checks report that the web service is responding; the UI separately checks that the engine is installed. Provider warnings can occur even when Subfinder exits successfully, and partial coverage is normal. Raw provider stderr is intentionally never returned to the browser because it can contain credentials. This wrapper does not persist those logs.

### Change the password or URL

```sh
python3 scripts/setup.py
python3 scripts/caddy_config.py
# Replace the Net Tools Caddy block, then validate and reload Caddy.
docker compose up -d --force-recreate
```

Recreating the container signs out existing sessions and retains saved results. The proxy token rotates with the password hash, so always regenerate the Caddy block after changing the password. Update DNS too if the hostname changes.

### Upgrade

Subfinder is pinned to `v2.17.0` in `compose.yaml` (the verified latest release on 10 October 2026). Update `SUBFINDER_VERSION` there to a reviewed release and rebuild. Python and Go images follow their specified minor-version tags.

```sh
docker compose build --pull
docker compose up -d
```

### Backup / restore

Stop the app for a consistent SQLite backup (including WAL files), copy the `/data` directory, then restart:

```sh
mkdir -p backup
docker compose stop subfinder
docker compose cp subfinder:/data/. ./backup/
docker compose start subfinder
```

To restore, stop the app and copy your backup back into `/data`, ensuring ownership is UID/GID `10001:10001`, then start it again. Store backups privately; discovered infrastructure can be sensitive. `docker compose down` retains the volume. **`docker compose down -v` deletes saved scans.**

## Local development and tests

Python 3.10+ is sufficient for the backend. The Docker image includes the pinned Subfinder binary; local development requires a separate Subfinder installation. To run without Docker, install the Python dependency, generate a temporary password hash and launch the app:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
export APP_ORIGIN=http://localhost:8080
export APP_PASSWORD_HASH="$(python3 -c 'from app.security import hash_password; import getpass; print(hash_password(getpass.getpass("Development password: ")))')"
export DATA_DIR="$PWD/data"
export HOST=127.0.0.1
python3 -m app.server
```

Open `http://localhost:8080` exactly (rather than `127.0.0.1`), so origin checks match. HTTP development cookies are not Secure; public deployments should always use HTTPS. The UI reports a missing engine instead of simulating results. The deterministic integration tests use an explicit fixture executable and do not contact real passive sources or public DNS:

```sh
python3 -m unittest discover -s tests -v
```

The app is a single-process, single-user utility. Run one replica per data volume. It has no account management, shared-user separation, distributed queue, or built-in DNS validation. The Docker Compose setup is the supported deployment.

## Extending the suite

`app/static/tools.js` is the frontend tool catalog, including display names, descriptions, availability, and routes. The shell handles navigation and shared activity; existing Subdomain Finder endpoints remain under `/api/scans`. New tools should add their own view and API handler, then register an available route in the catalog and the server page allowlist. Persist each new tool’s results in its own model and include its tool identity when adding records to shared activity. The current scan store identifies existing records as `subdomains` without changing the database schema.

