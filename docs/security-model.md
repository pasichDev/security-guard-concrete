# Security model

Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

How Security Guard decides what to do with a request, how it protects the sign-in form and
how it avoids locking out the people who run the site.

## Where it runs

The firewall is a Concrete HTTP middleware registered by the package's `on_start()`. It sees
the request before Concrete dispatches it and the response afterwards (that is how failed
sign-ins are detected — Concrete fires no event for them).

Requests that never reach Concrete's PHP front controller are not inspected:

- static files served by nginx or Apache directly;
- PHP files under the web root that Apache executes directly (deny those in the web server);
- pages served from Concrete's full-page cache to anonymous visitors.

## Hot path

On an ordinary request the firewall reads one state file and touches small counters. It does
not query the database.

- **State file** — a PHP-guarded file holding JSON (settings, active bans, whitelist). It is
  read with `file_get_contents`, not `include`, so a rebuild from cron or the CLI is seen by
  web processes at once, whatever the opcache settings. It is rebuilt atomically (temporary
  file + rename) after every change to bans, the whitelist or settings. It lives outside the
  web root when possible (`../.security_guard`), otherwise in `application/files/` behind an
  `.htaccess` deny. The emergency bypass token is stored only as a SHA-256 hash.
- **Counters** — APCu when available, otherwise small files with `flock` and HMAC-salted
  names; expired ones are removed by the cleanup.
- **Database writes** happen only on events (attack, ban, honeypot hit, failed sign-in) and
  are throttled per IP and rule.

Any exception inside the firewall is logged and the request continues (fail-open).

## Order of checks

1. Emergency bypass: `?sg_pass=<token>` clears the current IP's ban.
2. Whitelist (IPs, prefixes, CIDR; loopback always) and signed-in users with dashboard access.
3. Active ban → 403 (429 for sign-in bans). Manual bans apply in monitor mode too.
4. On `/dashboard`, `/ccm/` and the sign-in routes, signed-in users skip content heuristics —
   editors post HTML that legitimately contains `<script>`, `../` and similar. This applies to
   any signed-in user only while public registration is disabled; otherwise only to users with
   dashboard access. Anonymous requests to these paths get every check below.
5. Search engine bots: verified by reverse DNS + forward DNS (cached); a crawler user agent
   from an unverified IP is a fake bot.
6. Honeypot trap URLs.
7. User-agent rules (scanners, optionally HTTP libraries and AI crawlers).
8. Geo block (optional, offline country estimate).
9. PHP-probe burst counter.
10. Signatures on the path, query string, cookies (except Concrete's own) and the POST body of
    anonymous front-end requests (up to 64 KB). Sign-in POST bodies are never scanned.
11. Concrete rules: anonymous access to backend `/ccm/*` routes outside the allowlist — the
    first two requests in 10 minutes get 403 without a ban, the third bans (covers an editor's
    tab left open after the session expired); anonymous access to the upgrade route bans at once.
12. Rate limit (static files excluded) and, during a detected traffic spike, the busiest IPs.
13. Behaviour score (missing headers, POST without Referer, long query strings, probe paths)
    with a TTL; reaching the threshold bans.

In **monitor** mode steps 5–13 only log (`action = logged`); in **enforce** mode they ban and
deny. Bans escalate 1 h → 24 h → 7 days → 30 days when the previous ban is still active or
ended within 30 days.

## Sign-in protection

A POST to `/login/authenticate/concrete` with a non-empty user name and password that is
answered with the form again (not a redirect) counts as a failure for that IP. After
`bruteforce_threshold` failures within `bruteforce_window` the IP is banned and gets
**429 Too Many Requests** with `Retry-After`; administrators receive an alert e-mail.

This works alongside Concrete's own failed-login IP ban (Dashboard → System → Permissions),
whose state is shown on the Security Check page.

## Staying out of your own jail

- **Auto-trust:** after a successful administrator sign-in that IP is whitelisted for
  `trust_admin_days` days and any ban on it is lifted.
- **Emergency bypass token** (Settings → General).
- **"Unblock my IP"** on the Blocked IPs page, which also shows your current IP.
- The Security Check page signs its own requests to the site (HMAC header, 120 s), so probing
  `/.env` and similar never bans the server's IP.

## Client IP

The client IP comes from Concrete's request object, which honours the trusted proxies set in
Dashboard → System → Permissions. `X-Forwarded-For` from untrusted sources is ignored.
`CF-Connecting-IP` is used only when the Cloudflare option is on and the connection itself
comes from a published Cloudflare range.
