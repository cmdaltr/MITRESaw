# MITRESaw — Capabilities and Limitations

This document states plainly what MITRESaw does and does not do, so analysts can make informed decisions about how much to trust its output.

---

## What MITRESaw CAN do

### MITRE ATT&CK extraction (high confidence)
- Parse the official MITRE ATT&CK STIX bundle and extract every group, technique, sub-technique, tactic, platform, and procedure example.
- Filter by framework (Enterprise / ICS / Mobile), platform (Windows, Linux, macOS, etc.), threat group name, and keyword search terms.
- Extract indicators directly from MITRE's own procedure text — commands in backticks, registry keys, file paths, CVEs, ports, and known tool names. These are **MITRE-authored** and represent what MITRE's analysts specifically documented.
- Generate ATT&CK Navigator JSON layers per group.

### Evidence report generation (high confidence)
- Produce a styled multi-sheet XLSX with one row per atomic indicator, deduplication across sources, and per-indicator detection guidance (Sysmon EIDs, log sources, KEV references).
- Strip XML-illegal characters from all cell content to prevent Excel from rejecting the file.
- Produce a companion CSV suitable for SIEM ingestion as a lookup table.

### Citation enrichment (low-to-medium confidence — see limitations)
- Fetch the content of citation URLs referenced in MITRE procedure text using a multi-method fallback chain (direct HTTP → headless browser → Wayback Machine → Google Cache → PDF extraction → STIX metadata).
- Cache fetched content locally to avoid re-fetching on repeat runs.
- Extract additional indicators from fetched content and label them as `Citation` source type in the XLSX so they are distinguishable from MITRE-authored indicators.
- Rewrite known-dead domains (fireeye.com, mandiant.com) to their current locations (cloud.google.com).

---

## What MITRESaw CANNOT do

### Citation extraction is NOT technique-specific

**This is the most important limitation to understand.**

A citation in MITRE ATT&CK is a reference to a document (blog post, PDF, advisory) that MITRE's analysts used as a source. That document is typically about an entire campaign or malware family — not about a single technique. MITRESaw fetches that document and extracts indicators from it, but it has no way to know *which sentence in that document* MITRE was citing when they documented a specific technique.

**Consequence:** A citation listed under APT29's T1059.001 (PowerShell) may be a 20-page report covering APT29's entire intrusion. MITRESaw will extract indicators from relevant-looking paragraphs, but some of those indicators will belong to other techniques (T1003, T1021, T1105) that also happen to appear in the same paragraphs.

**What this means for you:** Citation-sourced indicators in the XLSX are *signals*, not definitive attributions. They expand coverage but require analyst review before use in detections. MITRE-procedure-sourced indicators (`Source Type = Procedure`) are reliable; citation-sourced indicators (`Source Type = Citation`) are suggestive.

### Relevance scoring is keyword-based, not semantic

The current paragraph scoring checks whether technique keywords appear in a paragraph. It does **not** understand meaning. A paragraph containing "the implant queries the current system time" will not be scored as relevant to "System Time Discovery" because that exact phrase does not appear. The scoring works well when documents use the same terminology as MITRE; it works poorly when documents use different phrasing.

### Citation fetch failure is common and silent

Many citation URLs cannot be fetched because:
- The page is behind a paywall or requires authentication
- The domain no longer exists (acquired, shut down, moved)
- The site uses JavaScript rendering that blocks automated access
- The PDF is scanned/image-only with no embedded text
- The server returns 403/429 rate limits

In all these cases, MITRESaw falls back to **STIX metadata only** — the bibliographic citation text (author, title, date) stored in the STIX bundle itself. This contains no technical indicators. The `citations_failed.yaml` file lists every URL that fell back to metadata.

### MITRESaw does not validate indicators

Extracted indicators are not checked for validity, safety, or current relevance:
- A command extracted from a 2017 threat report may no longer reflect current adversary behaviour.
- A registry path may be vendor-specific and irrelevant to your environment.
- A CVE may have been patched years ago.
- A domain or IP extracted from a citation may now be sinkholed or legitimately reused.

**MITRESaw extracts what is documented. It does not assess whether those indicators are still operationally relevant.**

### MITRESaw does not produce SIEM queries ready for production

The detection guidance column (Sysmon EIDs, log sources) tells you *where to look* — it does not produce tuned, tested, production-ready SIEM rules. The indicator values require contextualisation: an analyst must decide appropriate field names, exclusion lists, thresholds, and environment-specific adjustments before using them in detections.

### Platform and framework filtering reduces but does not eliminate noise

Filtering by `--platforms Windows` removes techniques that only apply to macOS or Linux, but many techniques span platforms. An indicator extracted for a Windows technique may not apply to your specific Windows environment (e.g., a command only relevant to domain-joined hosts running a specific service).

---

## Source type guide

Use the `Source Type` column in the Evidence Report to understand the confidence level of each row:

| Source Type | Origin | Confidence |
|-------------|--------|------------|
| `Procedure` | Directly from MITRE ATT&CK procedure text | **High** — MITRE-authored |
| `Technique` | From MITRE technique description text | **High** — MITRE-authored |
| `Citation` | Extracted from a fetched citation URL | **Low–medium** — may not be technique-specific |
| `MITRE ATT&CK` | Placeholder row — no indicators were extractable | **None** — technique is documented but has no extractable indicators |
| `Procedure \| Citation` | Indicator confirmed in both MITRE text and citation | **High** — corroborated across sources |

---

## Recommended workflow

1. **Filter aggressively** — use `--threatgroups`, `--platforms`, and `--searchterms` to narrow the output to your environment and threat model. Running against all groups and all platforms produces thousands of rows, most of which will not be relevant.

2. **Start with Procedure-sourced rows** — these are the most reliable. Review citation-sourced rows separately and with more scepticism.

3. **Use the Reference URL column** — click through to the original ATT&CK technique page or citation source to verify the context of any indicator before using it in a detection.

4. **Treat the output as a starting point, not a finished product** — MITRESaw accelerates the process of converting MITRE ATT&CK into detection candidates. It does not replace analyst judgement.
