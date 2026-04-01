"""Tests for the MITRESaw reference collector module."""

from src.citation_collector import (
    resolve_citations,
    html_to_text,
    _extract_relevant_passages,
    _should_skip_url,
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


def test_should_skip_url():
    assert _should_skip_url("") is True
    assert _should_skip_url("not-a-url") is True
    assert _should_skip_url("https://twitter.com/something") is True
    assert _should_skip_url("https://example.com/report.docx") is True  # Binary, not PDF
    assert _should_skip_url("https://example.com/report.pdf") is False  # PDFs handled by Method 4
    assert _should_skip_url("https://example.com/report.html") is False
    assert _should_skip_url("https://www.fireeye.com/blog/threat-research") is False
