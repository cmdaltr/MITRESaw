You are working inside the MITRESaw repository. Read MITRESaw.py and every file under
MITRESaw/toolbox/ fully before writing any code.

MITRESaw already extracts indicators from MITRE ATT&CK procedure examples and writes them to:
- ThreatActors_Techniques.csv — one row per (group, technique) with an `evidence` column
  containing a JSON dict of extracted indicators (keys: ports, cmd, reg, event_ids, cve,
  paths, software)
- ThreatActors_Techniques_Intersect.xlsx — group × technique matrix
- queries.conf — SIEM queries per technique
- Per-group ATT&CK Navigator JSON layers (when -n is passed)

The `evidence` column is a JSON string like:
  {"ports": ["445","139"], "cmd": ["net user /domain"], "reg": ["HKCU\\...\\Run"],
   "cve": ["CVE-2020-0688"], "paths": ["C:\\Windows\\Temp\\"], "software": ["Mimikatz"]}

The `procedure_example` field contains the raw MITRE ATT&CK procedure text verbatim, e.g.:
  "OilRig has run `net user`, `net user /domain`, `net group \"domain admins\" /domain`
   and `net group \"Exchange Trusted Subsystem\" /domain` to get account listings on a victim."

Your task is to add a native --evidence-report flag that generates a high-fidelity, styled
XLSX evidence report — one atomic indicator per row — directly from MITRESaw's own
extraction pipeline, for whatever -g / -t / -p / -f parameters were provided.

---

NEW FLAG

Add to the argparse block in MITRESaw.py:

  -E, --evidence-report
      Generate a styled XLSX evidence report (EvidenceReport_<timestamp>.xlsx)
      with one row per atomic indicator extracted from procedure examples.
      Applies the same group/platform/term filters as the main run.
      Compatible with all other flags; runs as a post-processing step after
      all existing outputs (CSV, XLSX matrix, queries.conf, nav layers) have
      been written. Does not affect or replace any existing output.

---

NEW MODULE — MITRESaw/toolbox/evidence_report.py

Create this module with two public functions:

  def extract_procedure_invocations(
      procedure_text: str,
      indicator_type: str,
      indicator_value: str
  ) -> list[str]

  def generate_evidence_report(
      rows: list[dict],
      output_path: str,
      framework: str = "Enterprise",
      platforms_arg: str = ".",
      searchterms_arg: str = ".",
      threatgroups_arg: str = "."
  ) -> None

---

FUNCTION 1 — extract_procedure_invocations()

This is the core of the update. It mines the raw MITRE procedure_example text for specific
invocation strings that MITRE has documented for this group using this indicator, and returns
them as a list of strings. It must be precise and evidence-grounded: return only what is
actually present in the procedure text, never synthesise or hallucinate invocations.

The function takes:
- procedure_text: the full raw procedure_example string for this (group, technique) row
- indicator_type: one of "cmd", "reg", "cve", "ports", "paths", "software", "event_ids"
- indicator_value: the specific atomic indicator being processed (e.g. "Mimikatz",
  "net user /domain", "CVE-2020-0688", "HKCU\\Software\\...\\Run")

Extraction logic — apply ALL of the following patterns to procedure_text and collect matches:

  PATTERN 1 — Backtick-quoted strings (MITRE's primary inline code convention):
    Regex: `([^`]+)`
    Extract every string wrapped in backtick characters. These are the highest-confidence
    invocations: MITRE explicitly formats command strings, registry paths, file paths, and
    tool invocations in backticks in their procedure text.
    Examples from real MITRE text:
      "has run `net user /domain`" → ["net user /domain"]
      "used `procdump.exe -ma lsass.exe lsass.dmp`" → ["procdump.exe -ma lsass.exe lsass.dmp"]
      "via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`" → ["HKCU\Software\..."]

  PATTERN 2 — Double-quoted strings containing executable-looking content:
    Regex: "([^"]{4,120})"
    Extract double-quoted strings that contain at least one of: a backslash, a forward slash,
    a dot followed by 2-4 letters (file extension), or whitespace preceded by - or /
    (flag pattern). This targets things like "mimikatz.exe" or "cmd /c whoami" while
    avoiding quoted prose phrases.

  PATTERN 3 — Executable invocations (unquoted):
    Regex: \b([A-Za-z0-9_\-]+\.(?:exe|ps1|bat|vbs|sh|py|pl|dll|cmd)(?:\s+[^\.\n]{0,80})?)\b
    Extract tool.exe invocations with any trailing arguments up to 80 chars or end of clause.
    Cap extraction at the first sentence boundary (full stop, semicolon, or newline) after
    the match to avoid pulling in unrelated prose.

  PATTERN 4 — Common command-line prefixes (Windows and Unix):
    Regex patterns for known CLI command roots, matched case-insensitively:
      net\s+(user|group|localgroup|use|view|share|session|start|stop)\s+\S[^\n]{0,100}
      reg\s+(add|delete|query|export|import)\s+\S[^\n]{0,100}
      schtasks\s+/[A-Za-z][^\n]{0,120}
      powershell(?:\.exe)?\s+[-/][^\n]{0,150}
      cmd(?:\.exe)?\s+/[cCkK]\s+[^\n]{0,120}
      wmic\s+\S[^\n]{0,100}
      certutil\s+[-/][^\n]{0,100}
      bitsadmin\s+/[^\n]{0,100}
      mshta(?:\.exe)?\s+\S[^\n]{0,100}
      wscript(?:\.exe)?\s+\S[^\n]{0,100}
      cscript(?:\.exe)?\s+\S[^\n]{0,100}
      rundll32(?:\.exe)?\s+\S[^\n]{0,100}
      regsvr32(?:\.exe)?\s+\S[^\n]{0,100}
      sc\s+(create|start|stop|delete|config|query)\s+\S[^\n]{0,100}
      vssadmin\s+\S[^\n]{0,80}
      nltest\s+/[^\n]{0,100}
      dsquery\s+\S[^\n]{0,100}
      ipconfig\s*[^\n]{0,60}
      whoami\s*[^\n]{0,60}
      ssh(?:\.exe)?\s+[-\w][^\n]{0,100}
      curl\s+[-\w][^\n]{0,150}
      wget\s+[-\w][^\n]{0,150}

  PATTERN 5 — CVE IDs in the procedure text (relevant when indicator_type is "cve"):
    Regex: CVE-\d{4}-\d{4,7}
    When the indicator_type is "cve", extract all CVE IDs mentioned in the procedure text
    and any adjacent text describing the exploitation method (up to 200 chars following the
    CVE ID, trimmed at the next full stop).

  PATTERN 6 — Windows Registry paths:
    Regex: HK(?:LM|CU|CR|U|CC)\\[^\s\n"'`]{6,200}
    When indicator_type is "reg", extract full registry paths as documented.

  PATTERN 7 — Windows and Unix file/directory paths:
    Windows: [A-Za-z]:\\[^\s\n"'`]{4,200}  or  \\\\[^\s\n"'`]{4,200}
    Unix: /(?:etc|var|tmp|usr|home|opt|bin|sbin|proc)/[^\s\n"'`]{2,150}
    When indicator_type is "paths", extract file paths.

Filtering and relevance scoring — after collecting all raw matches, apply:

  Step 1 — Relevance filter: retain only matches that are relevant to the specific
  indicator_value being processed. Relevance test: the match shares at least one
  significant token (word of length ≥ 4, or the full indicator_value as a substring)
  with the indicator_value, OR the match is a superset of the indicator_value (i.e. the
  indicator_value appears within the match as a substring). This ensures that when
  processing the "Mimikatz" software indicator, we return Mimikatz-specific invocations,
  not unrelated commands from the same procedure text.
  Exception: if indicator_type is "cmd" and the indicator_value IS the match (extracted
  verbatim by MITRESaw's own extractor), always include it regardless of the relevance
  filter — it is definitionally relevant.

  Step 2 — Deduplication: deduplicate the list case-insensitively, preserving the first
  occurrence.

  Step 3 — Length filter: discard matches shorter than 4 characters or longer than 300
  characters.

  Step 4 — Return order: return backtick-extracted strings first (highest confidence),
  then pattern 4 matches, then other patterns. Maximum 5 items returned.

Return [] (empty list) if no relevant invocations are found — do NOT fall back to
synthesised or invented strings. The calling code handles the empty case.

---

FUNCTION 2 — generate_evidence_report()

Where `rows` is the already-processed list of result dicts that mainsaw() has built (the
same data that gets written to ThreatActors_Techniques.csv). Do not assume field names —
read the existing code to determine exact field names used in the result dict.

ROW ATOMISATION LOGIC:

Each result dict contains a `procedure_example` text field and an `evidence` JSON string.
For each result dict, parse the `evidence` JSON. For every individual indicator value
across all evidence categories, emit one output row per indicator. The atomisation
categories are:

  evidence["cmd"]       → indicator_type = "cmd",       Source Type = "Website"
  evidence["reg"]       → indicator_type = "reg",        Source Type = "Website"
  evidence["cve"]       → indicator_type = "cve",        Source Type = "Website"
  evidence["ports"]     → indicator_type = "ports",      Source Type = "Website"
  evidence["paths"]     → indicator_type = "paths",      Source Type = "Website"
  evidence["software"]  → indicator_type = "software",   Source Type = "GitHub | Website"
  evidence["event_ids"] → indicator_type = "event_ids",  Source Type = "Website"

For ports, prefix with protocol where determinable: if the port is in
[80, 8080, 8443, 8888] → "TCP/<port>", [443] → "TCP/<port> (TLS)", [53] → "UDP/TCP/<port>",
[22] → "TCP/<port> (SSH)", [3389] → "TCP/<port> (RDP)", [445] → "TCP/<port> (SMB)",
[139] → "TCP/<port> (NetBIOS)", otherwise "TCP/<port>". Obtain protocol from the procedure
text if explicitly stated there.

If the evidence JSON is empty, all keys are empty lists, or the field is missing/null,
emit exactly one row with indicator_type = "none" and Evidential Element =
"(no extractable indicators)" to preserve the group/technique record.

Deduplicate on (group_sw_name, technique_id, evidential_element) — do not emit the same
atomic indicator twice for the same group+technique.

---

10-COLUMN OUTPUT SCHEMA — one row per atomic indicator:

Col 1 — Evidential Element:
  The atomic indicator string exactly as extracted from the evidence JSON.
  For ports: the prefixed string e.g. "TCP/3389 (RDP)".
  For event_ids: "Windows Event ID <value>".
  Font: Courier New 10, teal #2DD4BF, bold.

Col 2 — Threat Group:
  group_sw_name from the result dict. Single canonical name — no slashes, no MITRE IDs
  in parentheses. Just the name MITRESaw uses internally.
  Font: Calibri 10, group accent colour (see styling section), bold.

Col 3 — Procedure Example:
  The full procedure_example field verbatim. This is MITRE's documented procedure text
  for how this specific group uses this technique. Do not truncate.
  Font: Calibri 10, slate #CBD5E1.

Col 4 — Technique ID:
  technique_id from the result dict.
  Font: Courier New 10, green #22C55E, bold.

Col 5 — Technique Name:
  technique_name from the result dict.
  Font: Calibri 10, white #E0F2FE.

Col 6 — Tactic:
  tactic from the result dict.
  Font: Calibri 10, yellow #FACC15.

Col 7 — Contextual Evidence:
  This column must surface what MITRE has actually documented about HOW the group
  invokes this specific indicator — drawn directly from the procedure_example text —
  not a synthetic generic fallback.

  Construction logic (execute in this order):

  Step A — Call extract_procedure_invocations(procedure_example, indicator_type,
  indicator_value) to get the list of MITRE-documented invocation strings.

  Step B — If the list is non-empty, build the primary evidence string:
    "MITRE documented invocation(s):\n" + "\n".join(f"  • {inv}" for inv in invocations)
    This directly quotes what MITRE's procedure text contains for this group + indicator.

  Step C — Append detection context based on indicator_type (always append this regardless
  of whether Step B produced content):
    "cmd":       "\nDetection: Process Creation — Sysmon EID 1 / Windows Security EID 4688
                  (requires command-line auditing enabled)"
    "reg":       "\nDetection: Registry modification — Sysmon EID 12/13/14 / Windows
                  Security EID 4657 (requires object access auditing)"
    "cve":       "\nDetection: Exploit telemetry — check CISA KEV for active exploitation
                  status; review NVD for PoC availability; patch status is primary control"
    "ports":     "\nDetection: Network traffic — firewall/proxy logs, Zeek conn.log,
                  Sysmon EID 3 (network connection)"
    "paths":     "\nDetection: File creation/modification — Sysmon EID 11 (FileCreate),
                  EID 23 (FileDelete) / EDR file telemetry"
    "software":  "\nDetection: Process name / image load — Sysmon EID 1 (process),
                  EID 7 (image load); check GitHub for tool-specific CLI usage"
    "event_ids": "\nDetection: This IS a Windows event ID — ensure the corresponding log
                  channel is enabled and ingested into your SIEM"
    "none":      "(no extractable indicators — review procedure text manually)"

  Step D — If Step A returned an empty list (no invocations found in procedure text),
  prepend: "No specific invocation documented in MITRE procedure text for this indicator."
  followed by the Step C detection context.

  Step E — If the detectable_via field from the result dict is non-empty, append:
    "\nATT&CK Data Source(s): " + detectable_via

  The final Contextual Evidence string for a row with documented invocations looks like:
    "MITRE documented invocation(s):
       • net user /domain
       • net group "domain admins" /domain
     Detection: Process Creation — Sysmon EID 1 / Windows Security EID 4688
     ATT&CK Data Source(s): <detectable_via value>"

  Font: Courier New 10, slate #CBD5E1.

Col 8 — Reference URL:
  Extract the first URL found in procedure_example using regex https?://\S+{10,}.
  Strip trailing punctuation (.,;) from the matched URL.
  If no URL is found in the procedure text, construct the ATT&CK technique URL:
    https://attack.mitre.org/techniques/<technique_id>/
  where sub-techniques use a dot-to-slash conversion: T1059.001 → T1059/001.
  Font: Calibri 10, cyan #0EA5E9, with Excel hyperlink.

Col 9 — Navigation Layer URL:
  Construct from the group's MITRE ATT&CK group ID if available in the result dict.
  Check the result dict for a field containing the group ID (G-number) — read the code
  to determine the exact field name.
  If found: https://attack.mitre.org/groups/<group_id>/<group_id>-enterprise-layer.json
  If not found or not determinable: "N/A"
  Font: Calibri 10, purple #A78BFA, with Excel hyperlink if not "N/A".

Col 10 — Source Type:
  As mapped per indicator_type above.
  Font: Calibri 10, orange #F97316.

---

STYLING — match the scheme from iran_apt_evidence_v3.xlsx exactly:

Colours:
  Background navy (title, headers, sheet bg): #0D1B2A
  Default dark row BG:                        #0F1C2E
  Alternate even row tint:                    #0A1220
  Per-group row backgrounds (substring match on group_sw_name, case-insensitive):
    contains "OilRig" or "APT34"              → #0F2035
    contains "APT33" or "Peach Sandstorm"     → #0F250F
    contains "MuddyWater" or "Seedworm"       → #1F0A2A
    contains "Magic Hound" or "APT35"         → #2A150A
    contains "APT39" or "Chafer"              → #0A1535
    contains "Fox Kitten" or "Pioneer Kitten" → #1A0A2A
    all other groups                          → #0F1C2E
  Group accent colours (Col 2 font, substring match on group_sw_name):
    OilRig/APT34                              → #38BDF8
    APT33/Peach Sandstorm                     → #4ADE80
    MuddyWater/Seedworm                       → #C084FC
    Magic Hound/APT35                         → #FB923C
    APT39/Chafer                              → #60A5FA
    Fox Kitten/Pioneer Kitten                 → #E879F9
    all other groups                          → #E0F2FE

Font rules (apply exactly):
  Courier New 10 bold           → Col 1 (Evidential Element)
  Courier New 10 bold           → Col 4 (Technique ID)
  Courier New 10                → Col 7 (Contextual Evidence)
  Calibri 10 bold (group colour) → Col 2 (Threat Group)
  Calibri 10                    → Col 3, 5, 6, 8, 9, 10
  Calibri 12 bold               → all header cells (row 3)
  Calibri 16 bold               → title banner cell (row 1)
  Calibri 10 italic             → subtitle cell (row 2)

Alignment:
  All cells:         vertical = center
  All data cells:    horizontal = left,   wrap_text = True
  Header/title cells: horizontal = center, wrap_text = True

Borders: thin border on all cells, colour #1E3A5F
showGridLines = False on all sheets.

Row heights:
  Row 1 (title):    28
  Row 2 (subtitle): 16
  Row 3 (headers):  40
  Data rows:        70

Column widths:
  Col 1: 50  Col 2: 16  Col 3: 55  Col 4: 14  Col 5: 28
  Col 6: 18  Col 7: 72  Col 8: 45  Col 9: 38  Col 10: 16

Title banner — row 1, merged A1:J1:
  Text: "MITRESaw Evidence Report  |  {framework}  |  Groups: {N}  |
         Indicators: {M}  |  Generated: {YYYY-MM-DD HH:MM}"
  Fill: #0D1B2A, font: Calibri 16 bold, colour #0EA5E9, horizontal centre.

Subtitle — row 2, merged A2:J2:
  Text: "Platforms: {platforms_arg}  |  Search Terms: {searchterms_arg}  |
         Threat Groups: {threatgroups_arg}  |  Source: MITRE ATT&CK STIX via MITRESaw"
  Fill: #0D1B2A, font: Calibri 10 italic, colour #7FB3D3, horizontal centre.

Column headers — row 3:
  ["Evidential Element\n(Atomic Indicator / Command / Artefact)",
   "Threat Group",
   "Procedure Example\n(MITRE ATT&CK — verbatim)",
   "Technique ID",
   "Technique Name",
   "Tactic",
   "Contextual Evidence\n(MITRE Invocations + Detection Guidance)",
   "Reference URL",
   "Navigation Layer URL\n(ATT&CK Navigator JSON)",
   "Source Type"]
  Fill: #0D1B2A, font: Calibri 12 bold, colour #E0F2FE, horizontal centre.

Freeze panes at A4. Auto-filter on row 3 spanning A3:J{last_data_row}.

---

ADDITIONAL SHEETS:

Sheet 2 — "Group Summary":
  Columns (all Calibri 10, dark styling):
    Group Name | Technique Count | Indicator Count | Tactic Coverage | Top Tactic |
    Invocation Coverage (%)
  One row per unique group_sw_name in the atomised results.
  "Technique Count" = distinct technique IDs for the group.
  "Indicator Count" = total atomic indicator rows for the group.
  "Tactic Coverage" = comma-separated list of unique tactics for the group.
  "Top Tactic" = the tactic with the highest indicator count for the group.
  "Invocation Coverage (%)" = percentage of indicator rows for this group where
    extract_procedure_invocations() returned at least one result (non-empty list).
    Formula in Excel: =COUNTIF(range,"<>No specific*")/COUNT(range) — or calculate in
    Python and write as a value with % number format. This metric tells the analyst what
    proportion of indicators have MITRE-documented invocation evidence.
  Header: Calibri 12 bold.

Sheet 3 — "Tactic Pivot":
  Columns: Tactic | Indicator Count | % of Total | Invocations Found | Example Technique IDs
  One row per tactic, sorted descending by Indicator Count.
  "Invocations Found" = count of indicator rows for this tactic where Contextual Evidence
    starts with "MITRE documented invocation(s)" (i.e. extract_procedure_invocations
    returned results).
  "% of Total" column: Excel formula =B{row}/SUM($B$4:$B${last}), number format 0.0%.
  "Example Technique IDs": pipe-separated list of up to 5 unique technique IDs for the
    tactic, drawn from the atomised data.
  Header: Calibri 12 bold.

---

INTEGRATION INTO mainsaw():

After reading the full codebase, identify the point where result rows are fully assembled
and all existing output files have been written. After that point, if evidence_report is
True, call:

  from MITRESaw.toolbox.evidence_report import generate_evidence_report
  from datetime import datetime
  _er_path = f"EvidenceReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
  generate_evidence_report(
      rows=result_rows,           # use the actual variable name from the codebase
      output_path=_er_path,
      framework=",".join(attack_frameworks),
      platforms_arg=",".join(operating_platforms),
      searchterms_arg=",".join(search_terms),
      threatgroups_arg=",".join(provided_groups),
  )
  print(f"[+] Evidence report written to: {_er_path}")

Pass the evidence_report flag through from MITRESaw.py → mainsaw() using the exact same
pattern as navigationlayers, queries, and other boolean flags. Update the mainsaw()
function signature to accept evidence_report=False as a keyword argument with that default.

---

DEPENDENCIES:

Only openpyxl. Add to requirements.txt if not already present. Do not introduce any other
new dependencies. The module must import only from the Python standard library and openpyxl.

---

TESTS — tests/test_evidence_report.py:

test_extract_backtick_invocations:
  procedure = 'OilRig has run `net user /domain` and `net group "domain admins" /domain`.'
  result = extract_procedure_invocations(procedure, "cmd", "net user /domain")
  assert "net user /domain" in result

test_extract_exe_invocation:
  procedure = 'APT33 used procdump64.exe -ma lsass.exe to dump credentials.'
  result = extract_procedure_invocations(procedure, "software", "procdump64.exe")
  assert any("procdump64.exe" in r for r in result)

test_extract_reg_path:
  procedure = 'MuddyWater added HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemTextEncoding.'
  result = extract_procedure_invocations(procedure, "reg", "SystemTextEncoding")
  assert any("HKCU" in r for r in result)

test_extract_cve_with_context:
  procedure = 'MuddyWater exploited CVE-2020-0688, the Microsoft Exchange memory corruption vulnerability, to gain RCE.'
  result = extract_procedure_invocations(procedure, "cve", "CVE-2020-0688")
  assert any("CVE-2020-0688" in r for r in result)

test_no_invocation_returns_empty:
  procedure = 'The group used spearphishing emails to deliver malicious attachments.'
  result = extract_procedure_invocations(procedure, "software", "Mimikatz")
  assert result == []

test_relevance_filter:
  procedure = 'OilRig ran `net user /domain` and separately used `schtasks /create /tn WinUpdate`.'
  result = extract_procedure_invocations(procedure, "cmd", "schtasks")
  assert any("schtasks" in r for r in result)
  assert not any("net user" in r for r in result)  # irrelevant to schtasks indicator

test_atomise_cmd:
  Given a result dict with evidence={"cmd": ["net user /domain", "net group /domain"]},
  assert generate produces 2 data rows (one per cmd value).

test_atomise_empty_evidence:
  Given evidence={} or evidence field absent/null, assert exactly 1 row with
  Evidential Element == "(no extractable indicators)".

test_dedup:
  Given two result dicts for the same group+technique with identical cmd values,
  assert only 1 data row emitted for that indicator.

test_column_count:
  Assert every data row written to the XLSX has exactly 10 populated columns.

test_contextual_evidence_has_mitre_invocations:
  Given a procedure text containing backtick-wrapped commands and a matching cmd indicator,
  assert the generated Col 7 text starts with "MITRE documented invocation(s):".

test_contextual_evidence_fallback_when_no_invocations:
  Given a procedure text with no relevant invocations and a software indicator,
  assert Col 7 text starts with "No specific invocation documented in MITRE procedure text".

test_cve_detection_context:
  Given a CVE indicator, assert Col 7 contains "CISA KEV".

test_reg_detection_context:
  Given a registry key indicator, assert Col 7 contains "Sysmon EID 12".

test_technique_url_construction:
  For technique_id "T1059.001" with no URL in procedure text, assert Col 8 value is
  "https://attack.mitre.org/techniques/T1059/001/".

test_output_file_created:
  Assert the XLSX file exists on disk after generate_evidence_report() with a minimal
  1-row input.

test_invocation_coverage_in_group_summary:
  Assert Sheet 2 "Invocation Coverage (%)" column is present and numeric.

---

README UPDATE — add section "## Evidence Report (-E)":

  Explain the --evidence-report / -E flag, what it generates, and the 10-column schema.
  Note that Col 7 (Contextual Evidence) surfaces MITRE's own documented invocation strings
  extracted directly from procedure text — backtick-wrapped commands, specific CLI flags,
  registry paths and file paths as MITRE has documented them for that specific group.
  Where MITRE has not documented a specific invocation, the column states this explicitly.
  Clarify it is a post-processing step with zero impact on all existing outputs.

  Include example invocations:
    # All groups, default filter, evidence report
    ./MITRESaw.py -d -E

    # Iranian-linked groups on Windows with SIEM queries and evidence report
    ./MITRESaw.py -g OilRig,APT33,MuddyWater,APT39,Magic_Hound,Fox_Kitten -p Windows -Q -E

    # Industry-filtered with nav layers and evidence report
    ./MITRESaw.py -t financial,healthcare -p Windows,Linux -n -E

    # Force-refresh STIX data then generate evidence report
    ./MITRESaw.py -g APT29 -p Windows -F -E