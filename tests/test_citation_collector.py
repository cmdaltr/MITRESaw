"""Tests for the MITRESaw citation collector module."""

import os
import tempfile

from src.citation_collector import (
    resolve_citations,
    html_to_text,
    _extract_relevant_passages,
    _should_skip_url,
    _rewrite_url,
    _is_pdf_url,
    _is_plausible_indicator,
    _stix_description_fallback,
    import_citation_files,
)


def test_resolve_citations_basic():
    proc = "APT29 used tool X.(Citation: FireEye APT29 2020)(Citation: CISA Alert 2021)"
    ext_refs = [
        {"source_name": "FireEye APT29 2020", "url": "https://example.com/apt29",
         "description": "FireEye. (2020). APT29 Report."},
        {"source_name": "CISA Alert 2021", "url": "https://cisa.gov/alert",
         "description": "CISA. (2021). Alert."},
    ]
    result = resolve_citations(proc, ext_refs)
    assert len(result) == 2
    assert result[0]["citation_name"] == "FireEye APT29 2020"
    assert result[0]["url"] == "https://example.com/apt29"
    assert result[1]["citation_name"] == "CISA Alert 2021"


def test_resolve_citations_no_match():
    proc = "APT29 used spearphishing."
    ext_refs = [{"source_name": "Some Report", "url": "https://example.com"}]
    result = resolve_citations(proc, ext_refs)
    assert result == []


def test_resolve_citations_dedup():
    proc = "Used tool.(Citation: Report A) Again.(Citation: Report A)"
    ext_refs = [{"source_name": "Report A", "url": "https://example.com/a"}]
    result = resolve_citations(proc, ext_refs)
    assert len(result) == 1


def test_resolve_citations_empty_inputs():
    assert resolve_citations("", []) == []
    assert resolve_citations(None, []) == []
    assert resolve_citations("text", None) == []


def test_html_to_text_basic():
    html = "<html><body><p>Hello <b>world</b></p><script>var x=1;</script></body></html>"
    text = html_to_text(html)
    assert "Hello" in text
    assert "world" in text
    assert "var x" not in text


def test_html_to_text_strips_style():
    html = "<style>.foo{color:red}</style><p>Content here</p>"
    text = html_to_text(html)
    assert "Content here" in text
    assert "color" not in text


def test_extract_relevant_passages():
    text = (
        "This report covers APT29's activities in 2020.\n\n"
        "APT29 used PowerShell to execute commands on target systems. "
        "The group leveraged T1059.001 for initial access.\n\n"
        "Unrelated paragraph about weather and sports.\n\n"
        "APT29 also deployed Mimikatz for credential dumping."
    )
    result = _extract_relevant_passages(text, "APT29", "PowerShell", "T1059.001")
    assert "APT29" in result
    assert "PowerShell" in result
    assert "weather" not in result


def test_extract_relevant_no_matches():
    text = "This page is about cooking recipes and has nothing relevant."
    result = _extract_relevant_passages(text, "APT29", "PowerShell", "T1059")
    assert result == ""


def test_extract_relevant_technique_only_scoring():
    """Citations are scored on technique relevance only — group name is irrelevant
    since MITRE has already done the actor→citation linkage."""
    text = (
        "System Time Discovery via timedatectl is common on Linux systems.\n\n"
        "Adversaries query the system clock to synchronise implant activity.\n\n"
        "Unrelated paragraph about weather and sports."
    )
    result = _extract_relevant_passages(text, "ZIRCONIUM", "System Time Discovery", "T1124")
    assert "System Time Discovery" in result
    assert "weather" not in result


def test_extract_relevant_known_commands():
    """Single-word known commands in backticks should be classified as cmd."""
    from src.citation_collector import extract_indicators_from_text
    text = (
        "The adversary ran `hwclock` to read the hardware clock, "
        "then used `timedatectl` to check timezone settings. "
        "They also executed `date` to confirm the current time."
    )
    result = extract_indicators_from_text(text)
    assert "cmd" in result
    cmds_lower = [c.lower() for c in result["cmd"]]
    assert "hwclock" in cmds_lower
    assert "timedatectl" in cmds_lower
    assert "date" in cmds_lower


def test_extract_relevant_known_software():
    """Known offensive tool names in backticks should be classified as software."""
    from src.citation_collector import extract_indicators_from_text
    text = "The attacker deployed `mimikatz` to dump credentials and used `rubeus` for Kerberoasting."
    result = extract_indicators_from_text(text)
    assert "software" in result
    sw_lower = [s.lower() for s in result["software"]]
    assert "mimikatz" in sw_lower
    assert "rubeus" in sw_lower


def test_plausible_indicator_accepts_valid():
    """Real commands and paths must pass the plausibility filter."""
    assert _is_plausible_indicator("powershell -enc abc123") is True
    assert _is_plausible_indicator("net use \\\\server\\share") is True
    assert _is_plausible_indicator("del /f /q C:\\Windows\\Temp\\x.exe") is True
    assert _is_plausible_indicator("mimikatz") is True
    assert _is_plausible_indicator("hwclock") is True


def test_plausible_indicator_rejects_garbage():
    """Garbled PDF artifacts must be rejected by the plausibility filter."""
    # RTF control word sequence from bad PDF extraction
    assert _is_plausible_indicator("sxwx{pard3\\BM7") is False
    # High-density noise characters
    assert _is_plausible_indicator("ChY6]MHiWTDAms3@iJ%;") is False
    # Very low alphabetic ratio
    assert _is_plausible_indicator("o9\"2 9JX") is False
    # Embedded newline (PDF paragraph bleed)
    assert _is_plausible_indicator("cmd\n/c whoami") is False


def test_should_skip_url():
    assert _should_skip_url("") is True
    assert _should_skip_url("not-a-url") is True
    assert _should_skip_url("https://twitter.com/something") is True
    assert _should_skip_url("https://example.com/report.docx") is True  # Binary, not PDF
    assert _should_skip_url("https://example.com/report.pdf") is False  # PDFs handled by Method 4
    assert _should_skip_url("https://example.com/report.html") is False
    assert _should_skip_url("https://www.fireeye.com/blog/threat-research") is True  # Dead domain — pipeline rewrites to cloud.google.com before this check


def test_fireeye_rewrite_then_skip():
    """fireeye.com is rewritten to cloud.google.com by _rewrite_url; the rewritten URL is not skipped."""
    # fireeye.com no longer exists (acquired by Mandiant, then Google).
    # The pipeline calls _rewrite_url BEFORE _should_skip_url, so the
    # skip list never sees a fireeye.com URL during normal operation.
    rewritten = _rewrite_url("https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker.html")
    assert "cloud.google.com" in rewritten, "fireeye.com should be rewritten to cloud.google.com"
    assert _should_skip_url(rewritten) is False, "rewritten cloud.google.com URL should not be skipped"


# ---------------------------------------------------------------------------
# URL rewriting tests
# ---------------------------------------------------------------------------

def test_rewrite_mandiant_url():
    url = "https://www.mandiant.com/resources/blog/apt29-continues-targeting"
    result = _rewrite_url(url)
    assert "cloud.google.com/blog/topics/threat-intelligence" in result
    assert "apt29-continues-targeting" in result


def test_rewrite_fireeye_url():
    url = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker.html"
    result = _rewrite_url(url)
    assert "cloud.google.com/blog/topics/threat-intelligence" in result


def test_rewrite_leaves_normal_url():
    url = "https://www.cisa.gov/ncas/alerts/TA18-074A"
    assert _rewrite_url(url) == url


def test_rewrite_empty():
    assert _rewrite_url("") == ""
    assert _rewrite_url(None) is None


# ---------------------------------------------------------------------------
# Skip pattern tests
# ---------------------------------------------------------------------------

def test_skip_citation_homepage():
    """Homepage citations should be skipped by collect_reference_content."""
    # We test the pattern matching directly
    import re
    from src.citation_collector import _SKIP_CITATION_PATTERNS
    assert any(re.search(p, "7zip Homepage") for p in _SKIP_CITATION_PATTERNS)
    assert any(re.search(p, "WinRAR Homepage") for p in _SKIP_CITATION_PATTERNS)
    assert not any(re.search(p, "FireEye APT29 Report") for p in _SKIP_CITATION_PATTERNS)


def test_skip_citation_wikipedia():
    import re
    from src.citation_collector import _SKIP_CITATION_PATTERNS
    assert any(re.search(p, "Wikipedia PowerShell") for p in _SKIP_CITATION_PATTERNS)


def test_skip_cisco_docs_path():
    from src.citation_collector import _SKIP_URL_PATHS
    path = "/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref.html"
    assert any(p in path.lower() for p in _SKIP_URL_PATHS)


# ---------------------------------------------------------------------------
# PDF and fallback tests
# ---------------------------------------------------------------------------

def test_is_pdf_url():
    assert _is_pdf_url("https://example.com/report.pdf") is True
    assert _is_pdf_url("https://example.com/report.PDF") is True
    assert _is_pdf_url("https://example.com/report.html") is False
    assert _is_pdf_url("https://example.com/page") is False


def test_stix_description_fallback():
    text, method = _stix_description_fallback("Author. (2021). Report Title. Retrieved Oct 2022.")
    assert method == "stix_metadata"
    assert "Author" in text
    assert "Report Title" in text


def test_stix_description_fallback_empty():
    text, method = _stix_description_fallback("")
    assert method == "no_content"
    assert text == ""


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------

def test_import_html_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = os.path.join(tmpdir, "securelist.com_apt-report.html")
        with open(html_path, "w") as f:
            f.write("<html><body><p>APT29 used PowerShell to execute commands on target systems. "
                    "This is a detailed report about credential dumping techniques.</p></body></html>")
        count = import_citation_files(tmpdir)
        assert count == 1


def test_import_empty_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        count = import_citation_files(tmpdir)
        assert count == 0


def test_import_nonexistent_dir():
    count = import_citation_files("/nonexistent/path/that/does/not/exist")
    assert count == 0
