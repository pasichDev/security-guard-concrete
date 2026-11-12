# Security Policy

Security Guard for Concrete CMS is a firewall and monitoring package. Please report vulnerabilities in this package privately. Its source-available license remains unchanged; see [LICENSE](LICENSE).

## Supported versions

Security reports are reviewed against the latest maintained release of Security Guard for Concrete CMS, targeting Concrete CMS 9.5.2 and newer 9.x releases with PHP 8.2 as documented in the [README](README.md). Previous package versions may not receive separate fixes. This is **not** a claim of security support for Concrete CMS core or the underlying server.

## Reporting a vulnerability

**Preferred:** use GitHub's [Report a vulnerability](https://github.com/pasichDev/security-guard-concrete/security/advisories/new) form in the repository's Security / Advisories section, when private vulnerability reporting is enabled.

**Fallback:** send a brief initial report to [apasichnik9@gmail.com](mailto:apasichnik9@gmail.com). Do not include credentials, tokens, raw private logs or customer data in an unencrypted first message. We can agree on a confidential way to exchange additional evidence if needed.

Please do not disclose an unpatched issue, active exploitation instructions or sensitive details in public GitHub issues or pull requests.

For triage, include:

- The package version or commit, Concrete CMS/PHP versions and relevant hosting configuration
- Steps to reproduce on your own test site or another explicitly authorized environment
- Actual and expected behavior, security impact, and whether monitor/enforce mode affects the result
- Minimal redacted evidence and any relevant proxy, caching or web-server behavior

## What happens next

I will assess the report, seek a reproducible test case and coordinate remediation and disclosure if warranted. Response and release times are not guaranteed. Attribution can be agreed with the reporter.

This package cannot inspect requests that never reach Concrete's PHP middleware, as documented in [docs/security-model.md](docs/security-model.md). That architectural limit by itself is not necessarily a vulnerability in the package. Issues in Concrete core, PHP, the web server or third-party integrations should be reported to the responsible maintainers as well.

Only test systems you own or have permission to assess.
