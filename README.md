# Subfinder GUI

A small, dark-themed, mobile-friendly, single-user web interface for [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder). Run it on an Ubuntu VM with Docker Compose and expose it through your existing Caddy server.

Enter a domain, watch passive discovery results arrive, search them, and copy or download TXT, CSV, or JSON. Scan history survives container recreation, and scans continue when your browser closes. You can cancel scans, restore options for another run, and delete old results. The interface works on phones without horizontal scrolling.

## Deploy on Ubuntu

Prerequisites: Docker Engine with the Compose plugin, Python 3 for the one-time setup, and Caddy on the host. Point your chosen domain's DNS A/AAAA records at the VM. Caddy needs public ports 80 and 443 to obtain and renew certificates. If you publish an AAAA record, the VM must also be reachable over IPv6.

Clone the repository on your VM, then run the setup:

```sh
git clone https://github.com/Darthcedeus/net-tools.git
cd net-tools
python3 scripts/setup.py
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8080/healthz
```

The setup prompts for the exact public origin, such as `https://subfinder.yourdomain.com`, and a password of at least 12 characters. It creates a private `.env` containing a PBKDF2 password hash. Never send your password or provider keys to anyone. The origin is used for browser request checks and secure cookies; update it if you change the hostname. The app is served at the hostname root, not under a subpath.

Add this block to your host Caddyfile (usually `/etc/caddy/Caddyfile`), replacing the domain with the same hostname you entered during setup:

```caddyfile
subfinder.yourdomain.com {
    encode zstd gzip
    header Strict-Transport-Security "max-age=31536000"
    reverse_proxy 127.0.0.1:8080
}
```

Validate and reload Caddy:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Open your public URL on your computer or phone and sign in. The Compose service binds port 8080 only to localhost. Do not change it to a public bind when using host Caddy. If port 8080 is already in use, change the host side of the port mapping and Caddy's upstream together, e.g. `127.0.0.1:8081:8080` and `reverse_proxy 127.0.0.1:8081`.

### If Caddy also runs in Docker

Put Caddy and this service on a shared user-defined Docker network, remove the `ports` mapping from this service, and use `reverse_proxy subfinder:8080`. In a Caddy container, `127.0.0.1` refers to Caddy itself, not the Subfinder container. Keep Caddy's existing volumes for certificates. `APP_ORIGIN` stays the public HTTPS origin.

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

- Password login is required for every scan, result, history, and export API. Sessions expire after 12 hours and are invalidated on app restart. Passwords use PBKDF2-SHA256 with a random salt and 600,000 iterations. Cookies are HttpOnly and SameSite=Strict; HTTPS origins add Secure. Mutations require an origin check and a session-specific CSRF token. Login is limited to 10 attempts per five minutes globally and per direct peer; forwarded headers cannot bypass this.
- One scan runs at a time; up to five more wait in the queue. Each scan has a configurable time limit (1–10 minutes), source timeout (5–60 seconds), and request rate (1–50/second). A hard wall-clock limit adds 30 seconds for cleanup. Results are capped at 10,000 per scan. Partial results survive cancellation, errors, timeouts, and restart.
- The tool runs passively; the UI does not expose active resolution, arbitrary CLI arguments, resolvers, proxy settings, or file paths. Discovered hostnames are not verified as live. Use it for domains you own or have permission to assess.
- Scan records and results live in a SQLite database in the `subfinder-data` named volume. The latest 100 finished scans are retained, plus active jobs. Queued/running jobs become interrupted on restart and can be run again.
- Filtering matches subdomain names. Copy and export include **all matching results**, across every page. JSON includes scan metadata and source names. TXT is one hostname per line; CSV has hostname and sources columns.
- The container runs without root, with a read-only filesystem, dropped capabilities, bounded resources, and a writable temporary filesystem. No Docker socket is mounted. The application has no pip, npm, CDN, or font dependencies. The frontend is plain HTML/CSS/JavaScript, and the backend uses Python's standard library.

Logs and health:

```sh
docker compose logs --tail=100 -f subfinder
docker compose ps
curl http://127.0.0.1:8080/healthz
```

Health checks report that the web service is responding; the UI separately checks that the engine is installed. Provider warnings can occur even when Subfinder exits successfully, and partial coverage is normal. Raw provider stderr is intentionally never returned to the browser because it can contain credentials. This wrapper does not persist those logs.

### Change the password or URL

```sh
python3 scripts/setup.py
docker compose up -d --force-recreate
```

Recreating the container signs out existing sessions and retains saved results. Update Caddy and DNS too if the hostname changes.

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

Python 3.10+ is sufficient for the backend. The Docker image includes the pinned Subfinder binary; local development requires a separate Subfinder installation. To run without Docker, generate a temporary password hash and launch the app:

```sh
export APP_ORIGIN=http://localhost:8080
export APP_PASSWORD_HASH="$(python3 -c 'from app.security import hash_password; import getpass; print(hash_password(getpass.getpass("Development password: ")))')"
export DATA_DIR="$PWD/data"
export HOST=127.0.0.1
python3 -m app.server
```

Open `http://localhost:8080` exactly (rather than `127.0.0.1`), so origin checks match. HTTP development cookies are not Secure; public deployments should always use HTTPS. The UI reports a missing engine instead of simulating results. The deterministic integration tests use an explicit fixture executable and do not contact real passive sources:

```sh
python3 -m unittest discover -s tests -v
```

The app is a single-process, single-user utility. Run one replica per data volume. It has no account management, shared-user separation, distributed queue, or built-in DNS validation. The Docker Compose setup is the supported deployment.
