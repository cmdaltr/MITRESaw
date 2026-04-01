"""Tests for the MITRESaw evidence report module."""

import json
import os
import tempfile

import pytest
from openpyxl import load_workbook

from src.evidence_report import (
    extract_procedure_invocations,
    generate_evidence_report,
    _clean_procedure_text,
)


# ---------------------------------------------------------------------------
# extract_procedure_invocations() tests
# ---------------------------------------------------------------------------


def test_extract_backtick_invocations():
    procedure = 'OilRig has run `net user /domain` and `net group "domain admins" /domain`.'
    result = extract_procedure_invocations(procedure, "cmd", "net user /domain")
    assert "net user /domain" in result


def test_extract_exe_invocation():
    procedure = "APT33 used procdump64.exe -ma lsass.exe to dump credentials."
    result = extract_procedure_invocations(procedure, "software", "procdump64.exe")
    assert any("procdump64.exe" in r for r in result)


def test_extract_reg_path():
    procedure = (
        "MuddyWater added "
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemTextEncoding."
    )
    result = extract_procedure_invocations(procedure, "reg", "SystemTextEncoding")
    assert any("HKCU" in r for r in result)


def test_extract_cve_with_context():
    procedure = (
        "MuddyWater exploited CVE-2020-0688, the Microsoft Exchange memory "
        "corruption vulnerability, to gain RCE."
    )
    result = extract_procedure_invocations(procedure, "cve", "CVE-2020-0688")
    assert any("CVE-2020-0688" in r for r in result)


def test_no_invocation_returns_empty():
    procedure = "The group used spearphishing emails to deliver malicious attachments."
    result = extract_procedure_invocations(procedure, "software", "Mimikatz")
    assert result == []


def test_relevance_filter():
    procedure = (
        "OilRig ran `net user /domain` and separately used "
        "`schtasks /create /tn WinUpdate`."
    )
    result = extract_procedure_invocations(procedure, "cmd", "schtasks")
    assert any("schtasks" in r for r in result)
    assert not any("net user" in r for r in result)


# ---------------------------------------------------------------------------
# generate_evidence_report() tests
# ---------------------------------------------------------------------------


def _make_row(
    group_id="G0049",
    group_name="OilRig",
    technique_id="T1059.001",
    technique_name="PowerShell",
    tactic="Execution",
    platforms="Windows",
    framework="Enterprise",
    procedure="OilRig has run `net user /domain`.",
    evidence=None,
    detectable_via="Process Creation",
):
    if evidence is None:
        evidence = {"cmd": ["net user /domain"]}
    return {
        "group_sw_id": group_id,
        "group_sw_name": group_name,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "platforms": platforms,
        "framework": framework,
        "procedure_example": procedure,
        "evidence": json.dumps(evidence),
        "detectable_via": detectable_via,
    }


def test_atomise_cmd():
    row = _make_row(evidence={"cmd": ["net user /domain", "net group /domain"]})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        data_rows = [ws.cell(row=r, column=1).value for r in range(4, ws.max_row + 1)]
        assert len(data_rows) == 2
        assert "net user /domain" in data_rows
        assert "net group /domain" in data_rows
    finally:
        os.unlink(path)


def test_atomise_empty_evidence():
    row = _make_row(evidence={})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        val = ws.cell(row=4, column=1).value
        assert val == "(no extractable indicators)"
        # Exactly 1 data row
        assert ws.cell(row=5, column=1).value is None
    finally:
        os.unlink(path)


def test_dedup():
    row1 = _make_row(evidence={"cmd": ["net user /domain"]})
    row2 = _make_row(evidence={"cmd": ["net user /domain"]})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row1, row2], path)
        wb = load_workbook(path)
        ws = wb.active
        data_rows = [
            ws.cell(row=r, column=1).value
            for r in range(4, ws.max_row + 1)
            if ws.cell(row=r, column=1).value is not None
        ]
        assert len(data_rows) == 1
    finally:
        os.unlink(path)


def test_column_count():
    row = _make_row()
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        for r in range(4, ws.max_row + 1):
            if ws.cell(row=r, column=1).value is None:
                break
            populated = sum(
                1 for c in range(1, 15) if ws.cell(row=r, column=c).value is not None
            )
            assert populated == 14, f"Row {r} has {populated} populated columns, expected 14"
    finally:
        os.unlink(path)


def test_invocations_column_has_extracted_commands():
    procedure = 'OilRig has run `net user /domain` on target systems.'
    row = _make_row(procedure=procedure, evidence={"cmd": ["net user /domain"]})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        inv = ws.cell(row=4, column=9).value
        assert "net user /domain" in inv
    finally:
        os.unlink(path)


def test_invocations_fallback_when_no_invocations():
    procedure = "The group used spearphishing emails to deliver malicious attachments."
    row = _make_row(
        procedure=procedure,
        evidence={"software": ["Mimikatz"]},
    )
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        inv = ws.cell(row=4, column=9).value
        assert inv.startswith("No specific invocation documented in MITRE procedure text")
    finally:
        os.unlink(path)


def test_cve_detection_context():
    row = _make_row(
        evidence={"cve": [{"CVE-2020-0688": "Exchange vuln"}]},
        procedure="Exploited CVE-2020-0688.",
    )
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        det = ws.cell(row=4, column=10).value
        assert "CISA KEV" in det
    finally:
        os.unlink(path)


def test_reg_detection_context():
    row = _make_row(
        evidence={"reg": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]},
        procedure="Added HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key.",
    )
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        det = ws.cell(row=4, column=10).value
        assert "Sysmon EID 12" in det
    finally:
        os.unlink(path)


def test_technique_url_construction():
    row = _make_row(
        technique_id="T1059.001",
        procedure="The group used PowerShell scripts.",
        evidence={"cmd": ["powershell"]},
    )
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        url = ws.cell(row=4, column=12).value
        assert url == "https://attack.mitre.org/techniques/T1059/001/"
    finally:
        os.unlink(path)


def test_output_file_created():
    row = _make_row()
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0
    finally:
        os.unlink(path)


def test_invocation_coverage_in_group_summary():
    row = _make_row()
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws2 = wb["Group Summary"]
        # Check header row 3, column 6
        assert "Invocation Coverage" in ws2.cell(row=3, column=6).value
        # Check the data value is numeric
        val = ws2.cell(row=4, column=6).value
        assert isinstance(val, (int, float))
    finally:
        os.unlink(path)


def test_technique_matrix_with_multiple_groups():
    row1 = _make_row(group_name="OilRig", technique_id="T1059.001")
    row2 = _make_row(group_name="APT33", technique_id="T1059.001",
                     evidence={"cmd": ["powershell -enc"]})
    row3 = _make_row(group_name="APT33", technique_id="T1078",
                     technique_name="Valid Accounts",
                     evidence={"cmd": ["net user"]})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row1, row2, row3], path)
        wb = load_workbook(path)
        assert "Technique Matrix" in wb.sheetnames
        ws = wb["Technique Matrix"]
        # T1059.001 used by 2 groups should be first (row 3)
        assert ws.cell(row=3, column=1).value == "T1059.001"
        assert ws.cell(row=3, column=4).value == 2
        # T1078 used by 1 group should be second (row 4)
        assert ws.cell(row=4, column=1).value == "T1078"
        assert ws.cell(row=4, column=4).value == 1
    finally:
        os.unlink(path)


def test_technique_matrix_not_created_single_group():
    row = _make_row()
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        assert "Technique Matrix" not in wb.sheetnames
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Platforms and framework columns
# ---------------------------------------------------------------------------

def test_platforms_column():
    row = _make_row(platforms="Windows, Linux")
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        val = ws.cell(row=4, column=7).value  # Platforms is col 7
        assert "Windows" in val
    finally:
        os.unlink(path)


def test_framework_column():
    row = _make_row(framework="Enterprise")
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        val = ws.cell(row=4, column=8).value  # Framework is col 8
        assert val == "Enterprise"
    finally:
        os.unlink(path)


def test_log_sources_column():
    row = _make_row(detectable_via="Sysmon: 1; Security EventLog: 4688")
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        generate_evidence_report([row], path)
        wb = load_workbook(path)
        ws = wb.active
        val = ws.cell(row=4, column=11).value  # Log Sources is col 11
        assert "Sysmon" in val
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Procedure text cleaning
# ---------------------------------------------------------------------------

def test_clean_procedure_markdown_links():
    text = "[Axiom](https://attack.mitre.org/groups/G0001) used [Mimikatz](https://attack.mitre.org/software/S0002)."
    result = _clean_procedure_text(text)
    assert "Axiom (G0001)" in result
    assert "Mimikatz (S0002)" in result
    assert "[" not in result
    assert "](" not in result


def test_clean_procedure_citations_removed():
    text = "APT29 used PowerShell.(Citation: FireEye APT29 2020)(Citation: CISA Alert)"
    result = _clean_procedure_text(text)
    assert "APT29 used PowerShell" in result
    assert "Citation" not in result
    assert "FireEye" not in result


def test_clean_procedure_empty():
    assert _clean_procedure_text("") == ""
    assert _clean_procedure_text(None) is None
