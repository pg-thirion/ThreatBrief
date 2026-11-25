# ThreatBrief

Organisation-specific vulnerability intelligence and executive briefings.

ThreatBrief consumes the CISA Known Exploited Vulnerabilities (KEV) catalogue, enriches its 40 newest records with FIRST EPSS when available, and correlates products against a browser-local organisation inventory. It produces a ranked analyst queue and a downloadable Markdown briefing. No paid API key, database, or package dependencies are required.

## Run

Requires Node.js 20+.

```sh
npm start
npm test
```

Open http://localhost:3000. The included Vercel configuration also supports importing this repository as a static site with a Node serverless API. No deployment is created automatically.

## Workflow

1. Enter an organisation name, industry and one product or technology per line. Use the actual product name, not a company-wide vendor name.
2. Mark internet-facing and business-critical assets using the optional pipe-separated flags, e.g. `Microsoft Exchange | internet | critical`.
3. Refresh intelligence. Select a date window and review ranked candidate matches.
4. Validate the installed version and configuration, confirm exposure, assign remediation, and export a briefing.

## Methodology

KEV confirms exploitation in the wild, not compromise of your organisation. Product token matching is a heuristic, not CPE/version matching. The 0–100 priority score is not CVSS or a probability. It combines a 45-point KEV baseline, internet exposure (+25), business criticality (+15), known ransomware use (+10), and recent addition within 30 days (+5). Unmatched records are excluded from the organisation queue. EPSS is shown separately (when available), not used to double-count exploitation evidence. CISA due dates are federal remediation deadlines, not universal obligations.

## Sources

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA official mirror: https://github.com/cisagov/kev-data
- FIRST EPSS: https://www.first.org/epss/

The server fetches fixed public URLs only, caches successful results for 15 minutes and marks stale responses explicitly. If both sources fail on cold start, the UI reports the error and offers an explicitly synthetic demo. Missing EPSS is not zero. Organisation profiles never leave the browser and are stored in localStorage; don't enter secrets or confidential hostnames. External feed text is rendered as text, never HTML. No automated exploitation or remediation is performed.

## Scope

This MVP is a deterministic, explainable intelligence engine, not an LLM service. It covers known exploited vulnerabilities, not comprehensive threat actor, phishing or malware intelligence. Refresh is user-triggered and runs at page load; unattended scheduled reports, team accounts, version-aware matching and integrations are future extensions. Treat all output as decision support subject to analyst verification.
