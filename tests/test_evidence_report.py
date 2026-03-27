"""Tests for the MITRESaw evidence report module."""

import json
import os
import tempfile

import pytest
from openpyxl import load_workbook

from toolbox.evidence_report import extract_procedure_invocations, generate_evidence_report


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
                1 for c in range(1, 12) if ws.cell(row=r, column=c).value is not None
            )
            assert populated == 11, f"Row {r} has {populated} populated columns, expected 11"
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
        inv = ws.cell(row=4, column=7).value
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
        inv = ws.cell(row=4, column=7).value
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
        det = ws.cell(row=4, column=8).value
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
        det = ws.cell(row=4, column=8).value
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
        url = ws.cell(row=4, column=9).value
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
