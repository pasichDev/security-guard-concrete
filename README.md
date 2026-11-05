# Security Guard for Concrete CMS

**English** · [Українська](README.uk.md)

A web application firewall and security dashboard for **Concrete CMS 9.5**, shipped as
a single Concrete package. It inspects every request before Concrete dispatches it,
blocks attacks and password guessing, and shows what is happening on the site — both from
its own event log and from the hosting's access logs.

Built for real shared hosting (cPanel, CloudLinux resource limits, `exec()` disabled):
no database queries on a normal request, no external services, and it never takes the
site down — any internal error lets the request through.

> **Licence: source-available, all rights reserved.** The code is published for reading
> only. Installing or using it requires the author's written permission. See [LICENSE](LICENSE).

## Features

- 🛡️ **Firewall (WAF)** — signatures for SQL injection, XSS, path traversal, code
  execution, PHP object injection, XXE, SSRF, web shells, sensitive files (`.env`, `.git`,
  config backups), WordPress probing, Joomla exploit URLs, vulnerability scanners and AI
  crawlers.
- 🧱 **Concrete CMS exploits** — anonymous access to backend `/ccm/system/*` routes
  (the class behind the 2026 missing-permission disclosures), legacy `/tools/` routes,
  core internals, the install and upgrade routes, version fingerprinting. The allowlist of
  routes anonymous visitors legitimately use is taken from the 9.5.2 core.
- 🔐 **Login protection** — counts failed sign-ins per IP, bans with HTTP 429 after the
  threshold, e-mails the administrators, auto-trusts an administrator's IP after a
  successful sign-in.
- 🍯 **Honeypot** trap URLs, **PHP-probe burst** detection, **rate limiting**,
  **behaviour scoring**, **traffic-spike (DDoS) detection**.
- 🤖 **Search engines stay safe** — Googlebot, Bingbot, YandexBot, DuckDuckBot, Applebot
  and Baiduspider are verified by reverse + forward DNS; fakes are caught; verified
  crawlers can't be banned by a mis-click.
- ⏫ **Escalating bans** — 1 h → 24 h → 7 days → 30 days for repeat offenders; manual and
  permanent bans; whitelist with IPs, prefixes and CIDR ranges (IPv4/IPv6).
- 📊 **Dashboard** — overview with charts, event log with filters and CSV export, blocked
  IPs, whitelist, honeypot hits, behaviour scores, hosting-log traffic analytics, a
  server security check, settings, and a card for the dashboard welcome page.
- 📈 **Hosting-log analytics** — reads cPanel `access-logs/` and the monthly `.gz`
  archives (Apache combined format), aggregates per day idempotently (re-runs and log
  rotation never double-count), sees even the static files nginx serves without PHP.
- 🧰 **Server-side blocks in view** — 403 responses the server returns before PHP (hosting
  firewall such as ModSecurity/Imunify and `.htaccess` rules) are recognised in the access
  logs by their fixed block page and shown as a separate source.
- 🔄 **Bot range updates** — `security-guard:update-ranges` refreshes the official IP lists
  of Googlebot, Bingbot, Applebot and DuckDuckBot (strict validation, built-in fallback).
- 🌗 Dark and light dashboard themes, mobile layout.
- 🌍 Languages: English, Ukrainian, Polish, German, French, Spanish, Italian, Dutch,
  Portuguese (Brazil).

## Safety by design

- **Monitor mode by default.** After installation nothing is blocked — attacks are only
  logged. Review the event log, then switch to enforce mode on the Overview page.
- **Fail-open.** Any exception inside the firewall is logged and the request continues.
- **Administrators and editors are never blocked.** Signed-in users with dashboard access
  and whitelisted IPs bypass the checks; signed-in editors bypass content heuristics on
  `/ccm` and `/dashboard` (only while public registration is disabled).
- **Emergency bypass.** Set a bypass token in Settings and open
  `https://your-site/?sg_pass=<token>` to clear your own ban.

Details: [docs/security-model.md](docs/security-model.md).

## Requirements

- Concrete CMS **9.5.2** or newer 9.x
- PHP **8.2** (MySQL/MariaDB as used by Concrete)
- Optional: APCu (faster counters; file counters are used otherwise)

## Installation

**One step on a cPanel/SSH server** (fetches the public repository, swaps the package files,
runs install or update, clears the cache, checks the home page and rolls the files back if it
fails):

```bash
VERSION=v1.2.0
curl -fsSL "https://raw.githubusercontent.com/pasichDev/security-guard-concrete/${VERSION}/bin/server-update.sh" -o ~/sg-update.sh
bash ~/sg-update.sh "${VERSION}"                     # without an argument: the newest vX.Y.Z tag
EXPECTED_SHA=<commit sha> bash ~/sg-update.sh v1.2.0  # refuse if the tag doesn't point at this commit
```

Variables: `SITE_ROOT` (default `~/public_html`), `PHP`, `SITE_URL`, `EXPECTED_SHA`, `REQUIRE_SIGNED=1`.
Exit codes: 0 done, 1 error (files restored if they had been swapped), 2 another run in progress,
3 installed but the home-page check failed (files kept — the database is already updated). Back up the database
before updating — schema changes are not rolled back.

**Manually:**

1. Copy the package to `packages/security_guard` in your Concrete installation (the
   directory name must be `security_guard`). Don't copy `tests/` and `docs/` to a public
   web root.
2. Install it: **Dashboard → Extend Concrete → Add Functionality**, or from the CLI:

   ```bash
   php concrete/bin/concrete5 c5:package:install security_guard
   ```

3. Open **Dashboard → Security Guard**. The package starts in **monitor** mode.
4. In **Settings → Hosting logs** add your own IP to the excluded list *before* the first
   import, so your own traffic doesn't skew the statistics.
5. Add the cron jobs below.
6. After a few days with no false positives in the event log, switch to **enforce** mode.

## Cron (hosting-log import and cleanup)

```cron
15 * * * *    php /path/to/site/concrete/bin/concrete5 security-guard:ingest        >/dev/null 2>&1
*/15 * * * *  php /path/to/site/concrete/bin/concrete5 security-guard:cleanup       >/dev/null 2>&1
30 4 * * 1    php /path/to/site/concrete/bin/concrete5 security-guard:update-ranges >/dev/null 2>&1
```

On cPanel with CloudLinux use the full PHP path, e.g. `/opt/alt/php82/usr/bin/php`.

## Command line

| Command | What it does |
|---|---|
| `security-guard:ingest [--rebuild] [--days=N] [--time-budget=S] [--log-root=DIR] [--domain=D] [--exclude-ip=IP]` | Reads new lines of the hosting access logs and recomputes the affected days. Exit code 0 = done, 1 = errors, 2 = stopped by the time budget (run again to continue). |
| `security-guard:cleanup` | Deletes old events, expired bans, stale scores and expired counter files. |
| `security-guard:stats [--from=YYYY-MM-DD] [--to=YYYY-MM-DD] [--report-compat] [--json]` | Prints the daily statistics table. |
| `security-guard:update-ranges [--force] [--dry-run]` | Downloads the official crawler IP lists and stores them if they pass validation. |

Each command also answers to the `c5:security-guard:*` alias.

## Log sources

By default the package looks for `<home>/access-logs/<domain>` and
`<home>/access-logs/<domain>-ssl_log` plus the monthly archives in `<home>/logs/`, where
`<home>` is derived from the site directory and `<domain>` from the canonical URL. Set
**Settings → Hosting logs** (`log_root`, `log_sources`) if your host uses other paths.

## Adding a language

Add the locale and its plural rule to `SG_LOCALES` in `tests/ui/strings_lib.php`, run
`php tests/ui/sync_po.php xx_XX` to create `languages/xx_XX/LC_MESSAGES/messages.po` with every
string, translate it, and run the command again — it checks placeholders and compiles the `.mo`.

## Uninstalling

**Dashboard → Extend Concrete → Security Guard → Uninstall**. The package removes its
dashboard pages, database tables, settings and state files.

## What it does not do

- It doesn't modify your `.htaccess`. Core PHP files that Apache runs directly (for
  example under `concrete/vendor/`) never reach the firewall — deny them in the web server
  configuration.
- It doesn't call external services; the country shown for an IP is an offline estimate.
- Full-page-cached anonymous pages are served by Concrete before packages start, so the
  firewall doesn't see those requests.

## Author

Andrii Pasichnyk — [apasichnik9@gmail.com](mailto:apasichnik9@gmail.com).
For a licence or questions, write to the author.
