"""
MITRESaw Reference Collector

Fetches and extracts pertinent content from MITRE ATT&CK citation sources
(blog posts, reports, advisories, vendor documentation).

Uses only stdlib + requests (already a MITRESaw dependency).
"""

import hashlib
import json
import os
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_DIR = Path(".reference_cache")
REQUEST_TIMEOUT = 15       # seconds
RATE_LIMIT_DELAY = 0.3     # seconds between fetches
MAX_CONTENT_CHARS = 80000  # max chars to keep from a page
MAX_RELEVANT_CHARS = 4000  # max chars per reference in output
USER_AGENT = "MITRESaw-ReferenceCollector/1.0 (security research)"

# Domains that block automated requests or require auth
_SKIP_DOMAINS = frozenset([
    "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "youtube.com", "vimeo.com",
])

# File extensions we can't meaningfully parse as text
_BINARY_EXTENSIONS = frozenset([
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".gz", ".tar", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".mp3",
    ".exe", ".dll", ".bin",
])


# ---------------------------------------------------------------------------
# HTML → plain text
# ---------------------------------------------------------------------------

class _HTMLTextExtractor(HTMLParser):
    """Strip HTML tags and extract visible text."""

    _SKIP_TAGS = frozenset([
        "script", "style", "noscript", "svg", "head", "meta", "link",
    ])

    def __init__(self):
        super().__init__()
        self._parts = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._SKIP_TAGS:
            self._skip_depth += 1
        if tag.lower() in ("br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"):
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in self._SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        if tag.lower() in ("p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"):
            self._parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        raw = " ".join(self._parts)
        # Collapse whitespace
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def html_to_text(html: str) -> str:
    """Convert HTML to plain text."""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
    except Exception:
        return ""
    return parser.get_text()


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_key(url: str) -> str:
    """Generate a filesystem-safe cache key from URL."""
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    domain = urlparse(url).netloc.replace(".", "_")
    return f"{domain}_{h}"


def _read_cache(url: str) -> str | None:
    """Read cached content for a URL, or None if not cached."""
    path = CACHE_DIR / f"{_cache_key(url)}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text())
            return data.get("text", "")
        except Exception:
            return None
    return None


def _write_cache(url: str, text: str):
    """Cache extracted text for a URL."""
    CACHE_DIR.mkdir(exist_ok=True)
    path = CACHE_DIR / f"{_cache_key(url)}.json"
    try:
        path.write_text(json.dumps({
            "url": url,
            "text": text[:MAX_CONTENT_CHARS],
            "fetched": time.strftime("%Y-%m-%d %H:%M:%S"),
        }))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# URL fetching
# ---------------------------------------------------------------------------

def _should_skip_url(url: str) -> bool:
    """Check if a URL should be skipped."""
    if not url or not url.startswith("http"):
        return True
    parsed = urlparse(url)
    if parsed.netloc.lower().lstrip("www.") in _SKIP_DOMAINS:
        return True
    ext = os.path.splitext(parsed.path)[1].lower()
    if ext in _BINARY_EXTENSIONS:
        return True
    return False


def _fetch_url(url: str) -> str:
    """Fetch a URL and return extracted text. Returns empty string on failure."""
    import requests

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return ""

        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" in content_type or "text" in content_type:
            return html_to_text(resp.text[:MAX_CONTENT_CHARS])
        else:
            return ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Relevance extraction
# ---------------------------------------------------------------------------

_RE_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def _extract_relevant_passages(
    full_text: str,
    group_name: str,
    technique_name: str,
    technique_id: str,
    indicators: list | None = None,
) -> str:
    """Extract paragraphs/sentences relevant to the group+technique from page text."""
    if not full_text:
        return ""

    # Build search terms
    search_terms = set()
    if group_name:
        search_terms.add(group_name.lower())
        # Add common aliases (first word if multi-word)
        parts = group_name.split()
        if len(parts) > 1:
            for p in parts:
                if len(p) >= 4:
                    search_terms.add(p.lower())
    if technique_name and len(technique_name) >= 4:
        search_terms.add(technique_name.lower())
    if technique_id:
        search_terms.add(technique_id.lower())
        # Also try without sub-technique: T1059.001 → T1059
        if "." in technique_id:
            search_terms.add(technique_id.split(".")[0].lower())
    if indicators:
        for ind in indicators[:5]:  # limit to top 5
            if isinstance(ind, str) and len(ind) >= 4:
                search_terms.add(ind.lower())

    # Discard empty/short terms
    search_terms = {t for t in search_terms if len(t) >= 3}
    if not search_terms:
        return ""

    # Split into paragraphs
    paragraphs = re.split(r"\n\s*\n", full_text)

    relevant = []
    total_len = 0

    for para in paragraphs:
        para = para.strip()
        if len(para) < 30:
            continue

        para_lower = para.lower()

        # Count how many search terms appear in this paragraph
        hits = sum(1 for t in search_terms if t in para_lower)
        if hits >= 1:
            relevant.append((hits, para))
            total_len += len(para)
            if total_len >= MAX_RELEVANT_CHARS:
                break

    if not relevant:
        return ""

    # Sort by relevance (most hits first), take top passages
    relevant.sort(key=lambda x: -x[0])
    passages = []
    chars = 0
    for _, para in relevant:
        passages.append(para)
        chars += len(para)
        if chars >= MAX_RELEVANT_CHARS:
            break

    return "\n\n".join(passages)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_citations(procedure_text: str, external_references: list) -> list:
    """Map (Citation: X) in procedure text to reference metadata.

    Returns list of dicts:
        {"citation_name": str, "url": str, "description": str}
    """
    if not procedure_text or not external_references:
        return []

    # Extract citation names from procedure text
    citation_names = re.findall(r"\(Citation:\s*([^)]+)\)", procedure_text)
    if not citation_names:
        return []

    # Build lookup from external_references
    ref_lookup = {}
    for ref in external_references:
        sn = ref.get("source_name", "")
        if sn:
            ref_lookup[sn] = ref

    results = []
    seen = set()
    for cname in citation_names:
        cname = cname.strip()
        if cname in seen:
            continue
        seen.add(cname)

        ref = ref_lookup.get(cname, {})
        results.append({
            "citation_name": cname,
            "url": ref.get("url", ""),
            "description": ref.get("description", ""),
        })

    return results


def collect_reference_content(
    citations: list,
    group_name: str,
    technique_name: str,
    technique_id: str,
    indicators: list | None = None,
    verbose: bool = False,
) -> list:
    """Fetch and extract relevant content from citation URLs.

    Parameters
    ----------
    citations : list[dict]
        Output from resolve_citations().
    group_name, technique_name, technique_id : str
        Context for relevance extraction.
    indicators : list[str] | None
        Additional indicator strings to search for in page content.
    verbose : bool
        Print progress to stdout.

    Returns
    -------
    list[dict]
        Each dict has: citation_name, url, description, extracted_content, status
    """
    results = []

    for cit in citations:
        url = cit.get("url", "")
        entry = {
            "citation_name": cit["citation_name"],
            "url": url,
            "description": cit.get("description", ""),
            "extracted_content": "",
            "status": "",
        }

        if not url:
            entry["status"] = "no_url"
            results.append(entry)
            continue

        if _should_skip_url(url):
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            if ext in _BINARY_EXTENSIONS:
                entry["status"] = f"binary ({ext})"
            else:
                entry["status"] = "skipped_domain"
            results.append(entry)
            continue

        # Check cache first
        cached = _read_cache(url)
        if cached is not None:
            text = cached
            entry["status"] = "cached"
        else:
            if verbose:
                domain = urlparse(url).netloc
                print(f"      Fetching: {domain}...", end="", flush=True)
            text = _fetch_url(url)
            _write_cache(url, text)
            entry["status"] = "fetched" if text else "fetch_failed"
            if verbose:
                print(f" {'OK' if text else 'FAIL'} ({len(text)} chars)")
            time.sleep(RATE_LIMIT_DELAY)

        if text:
            relevant = _extract_relevant_passages(
                text, group_name, technique_name, technique_id, indicators
            )
            entry["extracted_content"] = relevant

        results.append(entry)

    return results


def collect_all_references(
    atomised_rows: list,
    stix_ref_map: dict,
    verbose: bool = True,
) -> list:
    """Collect references for all atomised rows.

    Parameters
    ----------
    atomised_rows : list[dict]
        Atomised evidence rows (must include group, technique_id, technique_name,
        procedure_example, evidential_element).
    stix_ref_map : dict
        Mapping of (group_name, technique_id, procedure_hash) → list of external_references
        from the STIX relationship objects.
    verbose : bool
        Print progress.

    Returns
    -------
    list[dict]
        One entry per unique citation, with fields:
        group, technique_id, technique_name, citation_name, url,
        description, extracted_content, status
    """
    # Deduplicate: collect unique (group, technique_id, procedure) combos
    seen_procs = set()
    unique_procs = []

    for row in atomised_rows:
        key = (row.get("group", ""), row.get("technique_id", ""),
               hash(row.get("procedure_example", "")))
        if key in seen_procs:
            continue
        seen_procs.add(key)
        unique_procs.append(row)

    if verbose:
        total_procs = len(unique_procs)
        print(f"\n[+] Collecting references for {total_procs} unique procedure examples...")

    all_refs = []
    seen_urls = {}  # url → extracted content (avoid re-fetching same URL)
    fetch_count = 0

    for i, row in enumerate(unique_procs):
        group_name = row.get("group", "")
        tech_id = row.get("technique_id", "")
        tech_name = row.get("technique_name", "")
        proc = row.get("procedure_example", "")
        indicator = row.get("evidential_element", "")

        # Get STIX external_references for this procedure
        proc_key = (group_name, tech_id, hash(proc))
        ext_refs = stix_ref_map.get(proc_key, [])

        if not ext_refs:
            continue

        # Resolve citations
        # Use the raw (uncleaned) procedure text for citation matching
        raw_proc = row.get("_raw_procedure", proc)
        citations = resolve_citations(raw_proc, ext_refs)

        if not citations:
            continue

        indicators = [indicator] if indicator and indicator != "(no extractable indicators)" else []

        for cit in citations:
            url = cit.get("url", "")

            # Re-use already-fetched content for same URL
            if url and url in seen_urls:
                content = seen_urls[url]
                relevant = _extract_relevant_passages(
                    content, group_name, tech_name, tech_id, indicators
                )
                all_refs.append({
                    "group": group_name,
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "citation_name": cit["citation_name"],
                    "url": url,
                    "description": cit.get("description", ""),
                    "extracted_content": relevant,
                    "status": "cached_session",
                })
                continue

            # Fetch
            ref_results = collect_reference_content(
                [cit], group_name, tech_name, tech_id, indicators,
                verbose=verbose,
            )
            for r in ref_results:
                r["group"] = group_name
                r["technique_id"] = tech_id
                r["technique_name"] = tech_name
                all_refs.append(r)

                # Cache in session
                if url and r.get("extracted_content"):
                    # Store the full text for re-use with different search terms
                    cached_text = _read_cache(url)
                    if cached_text:
                        seen_urls[url] = cached_text

            fetch_count += 1

        if verbose and (i + 1) % 25 == 0:
            print(f"    [{i+1}/{len(unique_procs)}] {fetch_count} URLs fetched, "
                  f"{len(all_refs)} references collected")

    if verbose:
        with_content = sum(1 for r in all_refs if r.get("extracted_content"))
        print(f"\n[+] Reference collection complete: {len(all_refs)} citations, "
              f"{with_content} with extracted content")

    return all_refs
