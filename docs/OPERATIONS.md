# Operations and release criteria

## Architecture

Browser -> same-origin read-only API -> fixed CISA / FIRST HTTPS sources. Browser-side scoring and Markdown export; CLI uses the same engine. No database or paid services. Source content is untrusted. The dashboard uses textContent and fixed CVE links; Markdown text is escaped. The server has a static allowlist, method restrictions and restrictive browser security headers.

## Availability

Monitor API 503 rate, stale flag, catalogue release age, EPSS coverage and upstream latency externally. Alert on stale catalogue or failed scheduled report. Health endpoint is liveness only. Use a supervisor and TLS proxy, enforce rate limits at the edge, and retain reports in restricted storage under your retention policy. Instance-local cache is not durable across restarts. Docker runs as non-root; pin the verified base image digest and scan before a real release.

## Release gates

- Green Node 22/24 CI and Docker smoke test.
- Verify both live KEV sources and FIRST EPSS against a real snapshot.
- Browser acceptance: inventory, all-history matching, filter, export, demo labels, clear profile and stale/error paths.
- Review CSP and deployment routing over HTTPS; configure edge limits.
- Validate risk outcomes with a security analyst against actual installed versions; check false positives/negatives.
- Independent security review, documented ownership, incident process and recovery exercise before business-critical adoption.

## Known limitations

KEV-only coverage, product-name matching, newest-40 EPSS coverage, no multi-user access control, no persistent server cache, no LLM generation. A CISA due date is a US federal deadline; forensic-triage flags require review of applicability. No report confirms compromise or applicability.

## Local analyst data

Local workspace data includes case state, notes, evidence, watchlist, bounded activity and one catalogue baseline. Organisation name and industry identify local scopes; live and demo are isolated. It is not a durable audit trail or shared case database. Back up before browser storage clearing. CSV/JSON/Markdown may contain sensitive analyst input, so restrict report handling. Test status evidence enforcement, local persistence, scope switching, import validation, all filters, pagination and exports during browser acceptance. Catalogue baseline changes are full-catalogue CVE additions/removals, not changes in exposure.
