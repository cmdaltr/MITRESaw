#!/usr/bin/env python3 -tt
import json
import re
import requests
import time
import urllib3
import warnings

from src.extract import (
    extract_port_indicators,
    extract_cmd_indicators,
    extract_filepath_indicators,
    extract_reg_indicators,
)

# In-memory cache: CVE ID -> enriched result string (or None for failed fetches)
_cve_cache = {}
# Separate cache for evidence dict values (pipe-delimited format)
_cve_evidence_cache = {}
# Collect CVEs with no actionable intelligence for end-of-run reporting
_cves_no_evidence = []
# Collect CVE fetch failures for end-of-run reporting
_cve_fetch_failures = []


def report_cve_summary():
    """Print CVE enrichment summary. Call at end of run."""
    unique_no_evidence = sorted(set(_cves_no_evidence))
    unique_failures = sorted(set(_cve_fetch_failures))
    if unique_failures:
        print(f"\n   CVE enrichment failed for: {', '.join(unique_failures)}")
    if unique_no_evidence:
        print(f"   No evidence/PoC found for: {', '.join(unique_no_evidence)}")
    if _ssl_fallback_used:
        print("   Note: SSL verification was bypassed for some requests (corporate VPN/proxy detected)")
    if unique_failures or unique_no_evidence or _ssl_fallback_used:
        print()


# Known PoC/exploit hosting domains
_POC_DOMAINS = [
    "github.com/",
    "packetstormsecurity.com",
    "exploit-db.com",
    "vuldb.com",
    "sploitus.com",
]

# NVD rate-limit: max 1 request per 6 seconds (without API key)
_last_nvd_request = 0.0
# PoC search cache and rate limiting
_poc_search_cache = {}
_last_github_search = 0.0
_last_gitlab_search = 0.0


_ssl_fallback_used = False


def _fetch(url, **kwargs):
    """GET with automatic SSL-verify fallback for corporate VPN/proxy environments."""
    global _ssl_fallback_used
    try:
        return requests.get(url, timeout=15, **kwargs)
    except requests.exceptions.SSLError:
        _ssl_fallback_used = True
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return requests.get(url, verify=False, timeout=15, **kwargs)


def _build_cvelistv5_url(cve_id):
    """Build correct CVEProject/cvelistV5 raw URL for a CVE ID.

    CVE-2021-26855  -> cves/2021/26xxx/CVE-2021-26855.json
    CVE-2017-1000486 -> cves/2017/1000xxx/CVE-2017-1000486.json
    """
    parts = cve_id.split("-")
    year = parts[1]
    seq = parts[2]
    seq_range = (seq[:-3] or "0") + "xxx"
    return (
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
        f"cves/{year}/{seq_range}/{cve_id}.json"
    )


def _extract_indicators_from_text(text):
    """Run extraction functions against CVE description text to find actionable indicators.

    Note: port extraction is skipped for CVE descriptions because version numbers
    (e.g. Office 2005, 2007, 2010) are falsely detected as port numbers.
    """
    indicators = {}
    cmds = extract_cmd_indicators(text)
    if cmds:
        indicators["cmds"] = cmds
    filepaths = extract_filepath_indicators(text)
    if filepaths:
        indicators["filepaths"] = filepaths
    regs = extract_reg_indicators(text)
    if regs:
        indicators["registry"] = regs
    return indicators


def _find_poc_references(cve_data):
    """Search CVE JSON for PoC/exploit references."""
    poc_refs = []
    # Check CNA references
    cna = cve_data.get("containers", {}).get("cna", {})
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        tags = [t.lower() for t in ref.get("tags", [])]
        # Tagged as exploit
        if any("exploit" in t for t in tags):
            poc_refs.append(url)
            continue
        # Known PoC domains with exploit/poc keywords in URL
        url_lower = url.lower()
        if any(domain in url_lower for domain in _POC_DOMAINS):
            if any(kw in url_lower for kw in ["exploit", "poc", "proof-of-concept", "advisory"]):
                poc_refs.append(url)
    # Check ADP references
    for adp in cve_data.get("containers", {}).get("adp", []):
        for ref in adp.get("references", []):
            url = ref.get("url", "")
            tags = [t.lower() for t in ref.get("tags", [])]
            if any("exploit" in t for t in tags):
                poc_refs.append(url)
    return list(set(poc_refs))


def _search_github_pocs(cve_id, product_name=""):
    """Search nomi-sec/PoC-in-GitHub for curated PoCs, fall back to GitHub search API."""
    if cve_id in _poc_search_cache:
        return _poc_search_cache[cve_id]
    refs = []
    # 1. nomi-sec curated lookup (no rate limit)
    parts = cve_id.split("-")
    year = parts[1]
    url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
    try:
        resp = _fetch(url)
        if resp.status_code == 200:
            pocs = resp.json()
            pocs.sort(key=lambda x: x.get("stargazers_count", 0), reverse=True)
            refs = [p["html_url"] for p in pocs[:5] if "html_url" in p]
    except Exception:
        pass
    # 2. GitHub search fallback by product name (rate-limited)
    if not refs and product_name:
        global _last_github_search
        elapsed = time.time() - _last_github_search
        if elapsed < 6.0:
            time.sleep(6.0 - elapsed)
        _last_github_search = time.time()
        try:
            query = requests.utils.quote(f"{cve_id} {product_name} exploit OR poc")
            resp = _fetch(
                f"https://api.github.com/search/repositories?q={query}&sort=stars&per_page=5"
            )
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                refs = [item["html_url"] for item in items[:5]]
        except Exception:
            pass
    _poc_search_cache[cve_id] = refs
    return refs


def _search_exploitdb(cve_id):
    """Search ExploitDB via GitLab API for exploits matching the CVE."""
    global _last_gitlab_search
    elapsed = time.time() - _last_gitlab_search
    if elapsed < 6.0:
        time.sleep(6.0 - elapsed)
    _last_gitlab_search = time.time()
    refs = []
    try:
        search_url = (
            f"https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb"
            f"/search?scope=blobs&search={cve_id}"
        )
        resp = _fetch(search_url)
        if resp.status_code == 200:
            results = resp.json()
            for result in results[:5]:
                filename = result.get("filename", "")
                match = re.search(r"(\d+)\.\w+$", filename)
                if match:
                    refs.append(
                        f"https://www.exploit-db.com/exploits/{match.group(1)}"
                    )
    except Exception:
        pass
    return refs


def _extract_cvss_score(cve_data):
    """Extract highest CVSS score from CNA or ADP metrics."""
    scores = []
    for container_key in ["cna", "adp"]:
        containers = cve_data.get("containers", {})
        if container_key == "cna":
            container_list = [containers.get("cna", {})]
        else:
            container_list = containers.get("adp", [])
        for container in container_list:
            for metric in container.get("metrics", []):
                for cvss_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    cvss = metric.get(cvss_key, {})
                    score = cvss.get("baseScore")
                    if score is not None:
                        scores.append(float(score))
    return max(scores) if scores else None


def _check_cisa_kev(cve_data):
    """Check ADP containers for CISA KEV (Known Exploited Vulnerabilities) status."""
    for adp in cve_data.get("containers", {}).get("adp", []):
        title = adp.get("title", "").lower()
        if "cisa" in title and ("kev" in title or "known exploited" in title):
            return True
        # Check providerMetadata for CISA
        provider = adp.get("providerMetadata", {}).get("orgId", "")
        if provider and "cisa" in adp.get("title", "").lower():
            return True
    return False


def _collect_descriptions(cve_data):
    """Collect all description text from CNA and ADP containers."""
    texts = []
    cna = cve_data.get("containers", {}).get("cna", {})
    for desc in cna.get("descriptions", []):
        texts.append(desc.get("value", ""))
    for adp in cve_data.get("containers", {}).get("adp", []):
        for desc in adp.get("descriptions", []):
            texts.append(desc.get("value", ""))
    return " ".join(texts)


def _fetch_nvd_enrichment(cve_id):
    """Fetch richer description from NVD API (rate-limited)."""
    global _last_nvd_request
    elapsed = time.time() - _last_nvd_request
    if elapsed < 6.0:
        time.sleep(6.0 - elapsed)
    _last_nvd_request = time.time()
    try:
        resp = _fetch(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        )
        if resp.status_code == 200:
            nvd_data = resp.json()
            vulns = nvd_data.get("vulnerabilities", [])
            if vulns:
                cve_item = vulns[0].get("cve", {})
                for desc in cve_item.get("descriptions", []):
                    if desc.get("lang") == "en":
                        return desc.get("value", "")
    except Exception:
        pass
    return ""


def obtain_cve_details(evidence):
    """Fetch CVE data, extract actionable intelligence, and return enriched results.

    Returns a list of strings in format: "{cve_id},{vendor},{versions},{enriched_description}"
    where enriched_description includes CVSS, indicators, PoC count, and CISA KEV status.
    """
    cves = []
    for cve in evidence:
        if not cve or "-" not in cve:
            continue

        # Check cache first
        if cve in _cve_cache:
            cached = _cve_cache[cve]
            if cached is not None:
                cves.append(cached)
            continue

        url = _build_cvelistv5_url(cve)
        try:
            response = _fetch(url)
        except Exception as e:
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            continue

        if not (200 <= response.status_code < 300):
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            time.sleep(1)
            continue

        try:
            cve_data = response.json()
        except json.JSONDecodeError:
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            continue

        # Extract basic metadata with safe access
        cna = cve_data.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [{}])
        vendor = affected[0].get("vendor", "Unknown") if affected else "Unknown"
        versions_list = affected[0].get("versions", []) if affected else []
        versions = ";".join(
            v.get("version", "")
            for v in versions_list
            if v.get("status") == "affected" and v.get("version")
        )
        if not versions:
            versions = str(
                re.findall(
                    r"'affected', 'version': '([^']+)",
                    str(versions_list),
                )
            )[2:-2].replace("', '", ";")

        # Collect all description text
        full_text = _collect_descriptions(cve_data)
        description = (
            full_text.strip()
            .replace(",", "")
            .replace("\n", " ")
            .replace("'", "`")
            .strip()
        )

        # NVD fallback for terse descriptions
        if len(full_text.strip()) < 100:
            nvd_text = _fetch_nvd_enrichment(cve)
            if nvd_text and len(nvd_text) > len(full_text):
                full_text = nvd_text
                description = (
                    full_text.strip()
                    .replace(",", "")
                    .replace("\n", " ")
                    .replace("'", "`")
                    .strip()
                )

        # Extract actionable indicators from description text
        indicators = _extract_indicators_from_text(full_text)

        # Find PoC/exploit references (CVE JSON + GitHub + ExploitDB)
        poc_refs = _find_poc_references(cve_data)
        product_name = affected[0].get("product", "") if affected else ""
        github_pocs = _search_github_pocs(cve, product_name)
        exploitdb_pocs = _search_exploitdb(cve)
        poc_refs = list(set(poc_refs + github_pocs + exploitdb_pocs))

        # Extract CVSS score
        cvss_score = _extract_cvss_score(cve_data)

        # Check CISA KEV status
        cisa_kev = _check_cisa_kev(cve_data)

        # Build enrichment suffix
        enrichment_parts = []
        if cvss_score is not None:
            enrichment_parts.append(f"CVSS:{cvss_score}")
        if indicators:
            indicator_strs = []
            for itype, ivals in sorted(indicators.items()):
                indicator_strs.append(f"{itype}={';'.join(ivals[:5])}")
            enrichment_parts.append("Indicators: " + " | ".join(indicator_strs))
        if poc_refs:
            enrichment_parts.append(f"PoC:{len(poc_refs)} refs")
        if cisa_kev:
            enrichment_parts.append("CISA-KEV:Yes")

        if enrichment_parts:
            enriched_desc = description + " | " + " | ".join(enrichment_parts)
        else:
            enriched_desc = description

        # Report if no actionable intelligence found
        has_actionable = bool(indicators) or bool(poc_refs) or cisa_kev
        if not has_actionable:
            _cves_no_evidence.append(cve)

        cve_result = f"{cve},{vendor},{versions},{enriched_desc}"
        _cve_cache[cve] = cve_result
        cves.append(cve_result)

    return cves


def enrich_cves_for_evidence(cve_ids):
    """Enrich CVE IDs with actionable intelligence for the evidence dict.

    Returns list of dicts like:
        [{"CVE-2021-26855": "Exchange Server 2013-2019|description|indicators|poc_url1; poc_url2|CISA-KEV:Yes"}]

    Fields are pipe-delimited. Multiple values within a field use semi-colons.
    Commas are stripped from all text fields.
    """
    enriched = []
    for cve in cve_ids:
        if not cve or "-" not in cve:
            continue

        # Check evidence cache first
        if cve in _cve_evidence_cache:
            cached = _cve_evidence_cache[cve]
            enriched.append({cve: cached if cached is not None else ""})
            continue

        url = _build_cvelistv5_url(cve)
        try:
            response = _fetch(url)
        except Exception as e:
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            _cve_evidence_cache[cve] = None
            enriched.append({cve: ""})
            continue

        if not (200 <= response.status_code < 300):
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            _cve_evidence_cache[cve] = None
            enriched.append({cve: ""})
            time.sleep(1)
            continue

        try:
            cve_data = response.json()
        except json.JSONDecodeError:
            _cve_fetch_failures.append(cve)
            _cve_cache[cve] = None
            _cve_evidence_cache[cve] = None
            enriched.append({cve: ""})
            continue

        # Extract metadata
        cna = cve_data.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [{}])
        vendor = affected[0].get("vendor", "Unknown") if affected else "Unknown"
        versions_list = affected[0].get("versions", []) if affected else []
        versions = ";".join(
            v.get("version", "")
            for v in versions_list
            if v.get("status") == "affected" and v.get("version")
        )
        if not versions:
            versions = str(
                re.findall(
                    r"'affected', 'version': '([^']+)",
                    str(versions_list),
                )
            )[2:-2].replace("', '", ";")

        product = f"{vendor} {versions}".strip().replace(",", "")

        # Collect description text
        full_text = _collect_descriptions(cve_data)
        description = (
            full_text.strip()
            .replace(",", "")
            .replace("\n", " ")
            .replace("'", "`")
            .strip()
        )

        # NVD fallback for terse descriptions
        if len(full_text.strip()) < 100:
            nvd_text = _fetch_nvd_enrichment(cve)
            if nvd_text and len(nvd_text) > len(full_text):
                full_text = nvd_text
                description = (
                    full_text.strip()
                    .replace(",", "")
                    .replace("\n", " ")
                    .replace("'", "`")
                    .strip()
                )

        # Extract actionable indicators
        indicators = _extract_indicators_from_text(full_text)

        # Find PoC/exploit references (CVE JSON + GitHub + ExploitDB)
        poc_refs = _find_poc_references(cve_data)
        product_name = affected[0].get("product", "") if affected else ""
        github_pocs = _search_github_pocs(cve, product_name)
        exploitdb_pocs = _search_exploitdb(cve)
        poc_refs = list(set(poc_refs + github_pocs + exploitdb_pocs))

        # Extract CVSS score
        cvss_score = _extract_cvss_score(cve_data)

        # Check CISA KEV status
        cisa_kev = _check_cisa_kev(cve_data)

        # Build indicator string (semi-colon separated)
        indicator_parts = []
        if indicators:
            for itype, ivals in sorted(indicators.items()):
                cleaned = [v.replace(",", "") for v in ivals[:5]]
                indicator_parts.extend(cleaned)
        indicators_str = "; ".join(indicator_parts)

        # PoC refs (semi-colon separated)
        poc_str = "; ".join(poc_refs) if poc_refs else ""

        # CISA KEV status
        kev_str = "CISA-KEV:Yes" if cisa_kev else ""

        # Build pipe-delimited value: product|description|indicators|poc_refs|kev
        value = f"{product}|{description}|{indicators_str}|{poc_str}|{kev_str}"

        # Report if no actionable intelligence found
        has_actionable = bool(indicators) or bool(poc_refs) or cisa_kev
        if not has_actionable:
            _cves_no_evidence.append(cve)

        # Cache the original format for bespoke_mapping compatibility
        enrichment_parts = []
        if cvss_score is not None:
            enrichment_parts.append(f"CVSS:{cvss_score}")
        if indicators:
            ind_strs = []
            for itype, ivals in sorted(indicators.items()):
                ind_strs.append(f"{itype}={';'.join(ivals[:5])}")
            enrichment_parts.append("Indicators: " + " | ".join(ind_strs))
        if poc_refs:
            enrichment_parts.append(f"PoC:{len(poc_refs)} refs")
        if cisa_kev:
            enrichment_parts.append("CISA-KEV:Yes")
        if enrichment_parts:
            enriched_desc = description + " | " + " | ".join(enrichment_parts)
        else:
            enriched_desc = description
        _cve_cache[cve] = f"{cve},{vendor},{versions},{enriched_desc}"
        _cve_evidence_cache[cve] = value

        enriched.append({cve: value})

    return enriched


def remove_logsource(logsource, data):
    for each in data:
        logsource = [x for x in logsource if x != each]
    return logsource


def bespoke_mapping(technique_id, platform, logsource, evidence_type, evidence):
    # provide logsource.append() for applicable splunk indexes, Sentinel tables etc.
    """logsource.append("")"""

    # removing (and replacing) ATT&CK log sources
    if "File: File " in str(logsource):
        remove_logsource(
            logsource,
            ["File: File Access", "File: File Creation", "File: File Modification"],
        )
        logsource.append("EDR (file logging)")
    if "Process: Process Creation" in str(logsource):
        remove_logsource(logsource, ["Process: Process Creation"])
        logsource.append("EDR (process logging)")

    # removing generic/unspecified log sources
    if "Process monitoring" in str(logsource):
        remove_logsource(logsource, ["Process monitoring"])

    # removing data sources not applicable to our environment
    """if "Zeek conn.log" in str(logsource):
        remove_logsource(logsource, ["Zeek conn.log"])"""

    # assigning data sources based on platform
    if "Azure" in platform or "IaaS" in platform:
        logsource.append("Azure logs")
        logsource.append("Azure Defender")
    if "IaaS" in platform:
        logsource.append("AWS CloudTrail logs")
        logsource.append("AWS GuardDuty")

    # assigning data sources based on evidence-type uncovered and environment-relevant data sources
    if evidence_type == "reg":
        logsource.append("EDR (registry logging)")
    elif evidence_type == "cmd" or evidence_type == "software":
        if "Windows" in platform:
            logsource.append("EDR (command logging)")
        else:  # Linux and macOS
            logsource.append("EDR (command logging)")
    elif (
        evidence_type == "ports"
    ):  # consider location of appliances and technology stack inc. logical architecture (internal/external)
        if (
            technique_id == "T1090.002" or technique_id == "T1105"
        ):  # external data sources only
            logsource.append("EDR (network logging)")
        elif (
            technique_id == "T1047"
            or technique_id == "T1082"
            or technique_id == "T1112"
        ):  # internal data sources only
            logsource.append("EDR (network logging)")
        elif (
            technique_id == "T1090.003" or "T1110" in technique_id
        ):  # both internal and external data sources
            logsource.append("EDR (network logging)")
    elif evidence_type == "evt":
        logsource.append("Event logs")
    elif evidence_type == "cve":
        # Evidence is now a list of enriched dicts; extract CVE IDs for log source lookup
        cve_items = re.findall(r"(CVE-\d+-\d+)", str(evidence))
        if cve_items:
            logsource = obtain_cve_details(cve_items)
    logsource = re.sub(
        r"('[^']+)\\?(', )\"([^']+)(', ')", r"\1\2'\3\4", str(logsource)
    )[2:-2].split("', '")

    # assigning data sources based on technique id and environment-relevant data sources
    if technique_id == "T1566.001" or technique_id == "T1566.002":
        logsource.append("Email logs")
    if (
        technique_id == "T1098.005"
        or technique_id == "T1111"
        or technique_id == "T1556.006"
        or technique_id == "T1621"
    ):
        logsource.append("MFA logs")

    # DNS-related techniques
    if technique_id in ("T1071.004", "T1568", "T1572", "T1090.004"):
        logsource.append("DNS logs")

    # RDP lateral movement
    if technique_id == "T1021.001":
        logsource.append("RDP logs")

    # Proxy/web-based techniques
    if "T1090" in technique_id or technique_id in ("T1102", "T1071.001"):
        logsource.append("Proxy logs")

    # Network scanning / intrusion detection
    if technique_id in ("T1046", "T1595.001", "T1595.002", "T1040"):
        logsource.append("IDS/IPS logs")

    # VPN / remote access
    if technique_id in ("T1133", "T1021.006"):
        logsource.append("VPN logs")

    # Web Application Firewall
    if technique_id in (
        "T1190", "T1189", "T1505.003",
        "T1071.001", "T1102",
        "T1046", "T1595.001", "T1595.002",
    ) or "T1110" in technique_id:
        logsource.append("WAF logs")

    # merging duplicate data sources
    counter = 0
    while counter < 20:
        logsource = re.sub(
            r"', '([^:]+)([^']+)', '\1: ([^']+)", r"', '\1\2;\3", str(logsource)
        )
        logsource = re.sub(r"', '([^:]+)', '\1", r"', '\1", str(logsource))
        counter += 1
    logsource = sorted(list(filter(None, logsource[2:-2].split("', '"))))
    return sorted(list(set(logsource)))
