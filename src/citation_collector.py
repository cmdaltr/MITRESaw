"""
MITRESaw Reference Collector

Fetches and extracts pertinent content from MITRE ATT&CK citation sources
using a multi-method fallback chain:

  Method 1 — Direct fetch (browser-like headers, SSL fallback)
  Method 2 — Wayback Machine (web.archive.org snapshot)
  Method 3 — Google Cache (webcache.googleusercontent.com)
  Method 4 — PDF extraction (for .pdf URLs, requires PyPDF2 or pdfplumber)
  Fallback  — STIX description metadata (author, title, date — always available)
"""

import hashlib
import json
import os
import re
import sys
import time
import warnings
import yaml

# Suppress urllib3 InsecureRequestWarning from verify=False fallbacks
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, urlparse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_DIR = Path("data/.citation_cache")
REQUEST_TIMEOUT = 8
WAYBACK_TIMEOUT = 5
RATE_LIMIT_DELAY = 0.5   # seconds between requests to same domain
RATE_LIMIT_GLOBAL = 0.0  # disabled — per-domain delay is sufficient for politeness
SSL_VERIFY = True        # Set to False by main.py if STIX loading hit SSL errors
MAX_CONTENT_CHARS = 80000
MAX_RELEVANT_CHARS = 4000

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
]

# Track last request time per domain to enforce per-domain rate limiting
_domain_last_request = {}

_SKIP_DOMAINS = {
    "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "youtube.com", "vimeo.com",
}

# Citation names that are tool homepages, vendor sites, or generic docs — no threat intel value
_SKIP_CITATION_PATTERNS = [
    r"(?i)homepage$",
    r"(?i)^wikipedia ",
    r"(?i)^microsoft docs",
    r"(?i)^microsoft technet",
    r"(?i)^microsoft windows ",
    r"(?i)^apple developer",
]

_SKIP_CITATION_URLS = {
    "www.7-zip.org", "www.rarlab.com", "www.winzip.com",
    "www.gnu.org", "www.perl.org", "www.python.org", "www.ruby-lang.org",
    "docs.microsoft.com", "learn.microsoft.com", "support.microsoft.com",
    "docs.cloud.google.com",
    "developer.apple.com", "man7.org", "linux.die.net",
    "en.wikipedia.org", "wikipedia.org",
    "attack.mitre.org",  # Already have this data from STIX
    "technet.microsoft.com", "msdn.microsoft.com",
    "docs.docker.com", "kubernetes.io",
    "www.openssl.org", "curl.se", "nmap.org", "www.wireshark.org",
    "github.com/PowerShellMafia", "github.com/gentilkiwi",
}

# URL path patterns that indicate documentation, not threat intel
_SKIP_URL_PATHS = [
    "/vpc/docs/", "/compute/docs/", "/iam/docs/", "/storage/docs/",
    "/sdk/docs/", "/kubernetes/docs/", "/docs/reference/",
    "/c/en/us/td/docs/",  # Cisco product documentation
]

_PDF_EXTENSIONS = frozenset([".pdf"])


# ---------------------------------------------------------------------------
# Known single-word commands / tools — loaded from data/known_commands.yaml
# ---------------------------------------------------------------------------

_KNOWN_CMD_NAMES: frozenset = frozenset()
_KNOWN_SOFTWARE_NAMES: frozenset = frozenset()
_known_commands_loaded = False


def _load_known_commands():
    """Lazily load data/known_commands.yaml and build lookup sets."""
    global _KNOWN_CMD_NAMES, _KNOWN_SOFTWARE_NAMES, _known_commands_loaded
    if _known_commands_loaded:
        return
    _known_commands_loaded = True
    _yaml_path = Path("data/known_commands.yaml")
    if not _yaml_path.exists():
        return
    try:
        with open(_yaml_path) as f:
            data = yaml.safe_load(f)
        cmd_set: set = set()
        sw_set: set = set()
        for _platform, _types in (data or {}).items():
            if not isinstance(_types, dict):
                continue
            for _token in (_types.get("cmd") or []):
                cmd_set.add(str(_token).lower())
            for _token in (_types.get("software") or []):
                sw_set.add(str(_token).lower())
        _KNOWN_CMD_NAMES = frozenset(cmd_set)
        _KNOWN_SOFTWARE_NAMES = frozenset(sw_set)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# User-configurable blocked domain list
# ---------------------------------------------------------------------------

def _load_blocked_domains_file():
    """Load data/blocked_domains.yaml and return (domains, prefixes, paths).

    Returns three collections that extend the hardcoded skip lists above.
    Fails silently so a missing or malformed file never breaks a run.
    """
    _file = Path(__file__).parent.parent / "data" / "blocked_domains.yaml"
    if not _file.exists():
        return frozenset(), frozenset(), []
    try:
        with open(_file, encoding="utf-8") as _f:
            _data = yaml.safe_load(_f) or {}

        def _norm(entry):
            if isinstance(entry, dict):
                return str(entry.get("domain") or entry.get("prefix") or entry.get("path") or "")
            return str(entry)

        _domains = frozenset(
            _norm(e).lower().lstrip("www.")
            for e in _data.get("blocked_domains", [])
            if _norm(e)
        )
        _prefixes = frozenset(
            _norm(e).lower()
            for e in _data.get("blocked_url_prefixes", [])
            if _norm(e)
        )
        _paths = [
            _norm(e)
            for e in _data.get("blocked_url_paths", [])
            if _norm(e)
        ]
        return _domains, _prefixes, _paths
    except Exception:
        return frozenset(), frozenset(), []


_file_domains, _file_prefixes, _file_paths = _load_blocked_domains_file()
_SKIP_DOMAINS = _SKIP_DOMAINS | _file_domains
_SKIP_CITATION_URLS = _SKIP_CITATION_URLS | _file_prefixes
_SKIP_URL_PATHS = _SKIP_URL_PATHS + [p for p in _file_paths if p not in _SKIP_URL_PATHS]

_BINARY_EXTENSIONS = frozenset([
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".gz", ".tar", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".mp3",
    ".exe", ".dll", ".bin",
])


# ---------------------------------------------------------------------------
# HTML → plain text
# ---------------------------------------------------------------------------

class _HTMLTextExtractor(HTMLParser):
    _SKIP_TAGS = frozenset(["script", "style", "noscript", "svg", "head", "meta", "link"])

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
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def html_to_text(html: str) -> str:
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
    except Exception:
        return ""
    return parser.get_text()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(url: str) -> str:
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    domain = urlparse(url).netloc.replace(".", "_")
    return f"{domain}_{h}"


def _read_cache(url: str) -> str | None:
    path = CACHE_DIR / f"{_cache_key(url)}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text())
            text = data.get("text", "")
            # Sanitize non-printable/binary chars from old cache entries
            if text:
                text = re.sub(r"[^\x20-\x7E\n\r\t]", "", text)
            return text
        except Exception:
            return None
    return None


def _write_cache(url: str, text: str, method: str = ""):
    CACHE_DIR.mkdir(exist_ok=True)
    path = CACHE_DIR / f"{_cache_key(url)}.json"
    try:
        path.write_text(json.dumps({
            "url": url,
            "text": text[:MAX_CONTENT_CHARS],
            "method": method,
            "fetched": time.strftime("%Y-%m-%d %H:%M:%S"),
        }))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _rate_limit(url: str):
    """Enforce per-domain and global rate limiting."""
    domain = urlparse(url).netloc.lower()
    now = time.time()
    # Per-domain delay
    last = _domain_last_request.get(domain, 0)
    wait = RATE_LIMIT_DELAY - (now - last)
    if wait > 0:
        time.sleep(wait)
    # Global delay
    global_last = _domain_last_request.get("__global__", 0)
    wait = RATE_LIMIT_GLOBAL - (time.time() - global_last)
    if wait > 0:
        time.sleep(wait)
    _domain_last_request[domain] = time.time()
    _domain_last_request["__global__"] = time.time()


def _make_session():
    import random
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    ua = random.choice(_USER_AGENTS)
    session.headers.update({
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Cache-Control": "max-age=0",
    })
    return session


# ---------------------------------------------------------------------------
# Method 1 — Direct fetch
# ---------------------------------------------------------------------------

def _fetch_direct(url: str, session=None) -> tuple:
    """Returns (text, status_detail). Empty text on failure."""
    import requests
    if session is None:
        session = _make_session()

    _verify_options = (SSL_VERIFY,) if not SSL_VERIFY else (True, False)
    for verify_ssl in _verify_options:
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=verify_ssl)
            if resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "").lower()
                if "html" in ct or "text" in ct:
                    text = html_to_text(resp.text[:MAX_CONTENT_CHARS])
                    if len(text) > 200:  # JS-rendered pages return near-empty shells
                        return text, "direct"
                    return "", "direct:js_rendered_page"
                return "", f"direct:unsupported_content_type({ct[:30]})"
            if resp.status_code in (403, 401) and verify_ssl:
                continue
            return "", f"direct:http_{resp.status_code}"
        except requests.exceptions.SSLError:
            if verify_ssl:
                continue
            return "", "direct:ssl_error"
        except requests.exceptions.Timeout:
            return "", "direct:timeout"
        except Exception as e:
            return "", f"direct:{type(e).__name__}"

    return "", "direct:all_attempts_failed"


# ---------------------------------------------------------------------------
# Method 2 — Wayback Machine
# ---------------------------------------------------------------------------

def _fetch_wayback(url: str, session=None) -> tuple:
    """Try the most recent Wayback Machine snapshot."""
    import requests
    if session is None:
        session = _make_session()

    wb_api = f"https://archive.org/wayback/available?url={quote(url, safe='')}"
    try:
        api_resp = session.get(wb_api, timeout=WAYBACK_TIMEOUT, verify=SSL_VERIFY)
        if api_resp.status_code != 200:
            return "", "wayback:api_failed"
        data = api_resp.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        if not snapshot or not snapshot.get("available"):
            return "", "wayback:no_snapshot"

        snap_url = snapshot["url"]
        resp = session.get(snap_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=SSL_VERIFY)
        if resp.status_code == 200:
            ct = resp.headers.get("Content-Type", "").lower()
            if "html" in ct or "text" in ct:
                text = html_to_text(resp.text[:MAX_CONTENT_CHARS])
                if len(text) > 200:
                    return text, "wayback"
                return "", "wayback:insufficient_content"
        return "", f"wayback:http_{resp.status_code}"
    except requests.exceptions.Timeout:
        return "", "wayback:timeout"
    except Exception as e:
        return "", f"wayback:{type(e).__name__}"


# ---------------------------------------------------------------------------
# Method 3 — Google Cache
# ---------------------------------------------------------------------------

def _fetch_google_cache(url: str, session=None) -> tuple:
    """Try Google's cached version of the page."""
    import requests
    if session is None:
        session = _make_session()

    cache_url = f"https://webcache.googleusercontent.com/search?q=cache:{quote(url, safe='')}"
    try:
        resp = session.get(cache_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=SSL_VERIFY)
        if resp.status_code == 200:
            text = html_to_text(resp.text[:MAX_CONTENT_CHARS])
            if text and len(text) > 100:
                return text, "google_cache"
        return "", f"google_cache:http_{resp.status_code}"
    except requests.exceptions.Timeout:
        return "", "google_cache:timeout"
    except Exception as e:
        return "", f"google_cache:{type(e).__name__}"


# ---------------------------------------------------------------------------
# Method 4 — PDF extraction
# ---------------------------------------------------------------------------

def _fetch_pdf(url: str, session=None) -> tuple:
    """Download PDF and extract text using PyPDF2 or pdfplumber."""
    import requests
    if session is None:
        session = _make_session()

    try:
        resp = session.get(url, timeout=30, allow_redirects=True, verify=False)
        if resp.status_code != 200:
            return "", f"pdf:http_{resp.status_code}"
        ct = resp.headers.get("Content-Type", "").lower()
        if "pdf" not in ct and not url.lower().endswith(".pdf"):
            return "", "pdf:not_a_pdf"
    except Exception as e:
        return "", f"pdf:download_{type(e).__name__}"

    pdf_bytes = resp.content

    # Try PyPDF2 first
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(BytesIO(pdf_bytes))
        pages = []
        for page in reader.pages[:30]:  # Cap at 30 pages
            text = page.extract_text()
            if text:
                pages.append(text)
        if pages:
            raw = "\n\n".join(pages)[:MAX_CONTENT_CHARS]
            clean = re.sub(r"[^\x20-\x7E\n\r\t]", "", raw)
            if len(clean) > 100:
                return clean, "pdf:PyPDF2"
    except ImportError:
        pass
    except Exception:
        pass

    # Try pdfplumber
    try:
        import pdfplumber
        with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
            pages = []
            for page in pdf.pages[:30]:
                text = page.extract_text()
                if text:
                    pages.append(text)
            if pages:
                raw = "\n\n".join(pages)[:MAX_CONTENT_CHARS]
                clean = re.sub(r"[^\x20-\x7E\n\r\t]", "", raw)
                if len(clean) > 100:
                    return clean, "pdf:pdfplumber"
    except ImportError:
        pass
    except Exception:
        pass

    # OCR fallback for image-only / scanned PDFs
    return _fetch_pdf_ocr(pdf_bytes)


def _fetch_pdf_ocr(pdf_bytes: bytes) -> tuple:
    """OCR fallback for image-only or scanned PDFs.

    Requires: pdf2image (wraps poppler) + pytesseract (wraps Tesseract).
    Both are optional — if absent the function returns empty string.
    Caps at 10 pages to avoid excessive processing time.
    """
    try:
        from pdf2image import convert_from_bytes
        import pytesseract
    except ImportError:
        return "", "pdf:ocr_unavailable"

    try:
        images = convert_from_bytes(pdf_bytes, dpi=200, first_page=1, last_page=10)
    except Exception as e:
        return "", f"pdf:ocr_convert_{type(e).__name__}"

    pages = []
    for img in images:
        try:
            text = pytesseract.image_to_string(img)
            if text and text.strip():
                pages.append(text)
        except Exception:
            continue

    if pages:
        raw = "\n\n".join(pages)[:MAX_CONTENT_CHARS]
        clean = re.sub(r"[^\x20-\x7E\n\r\t]", "", raw)
        if len(clean) > 100:
            return clean, "pdf:ocr"

    return "", "pdf:ocr_no_text"


# ---------------------------------------------------------------------------
# Method 5 — Headless browser (for Cloudflare/JS-protected sites)
# ---------------------------------------------------------------------------

def _ensure_playwright_browsers():
    """Check if Playwright Chromium is installed, install if missing."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # Try to get the executable path — fails if not installed
            p.chromium.executable_path
    except Exception:
        import subprocess
        try:
            subprocess.run(
                ["playwright", "install", "chromium"],
                check=True, capture_output=True, timeout=120,
            )
        except Exception:
            # Try via python -m
            try:
                subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    check=True, capture_output=True, timeout=120,
                )
            except Exception:
                return False
    return True

_playwright_checked = False


def _fetch_headless(url: str) -> tuple:
    """Use Playwright headless browser with stealth measures to bypass JS challenges.

    Stealth measures:
    - Runs in headed-like mode (headless=new) to avoid detection
    - Spoofs webdriver/navigator properties via init script
    - Sets realistic viewport, locale, timezone, color scheme
    - Longer wait with scroll to trigger lazy-loaded content
    - Retries with increased wait if first attempt has insufficient content
    """
    global _playwright_checked

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "", "headless:playwright_not_installed"

    if not _playwright_checked:
        _playwright_checked = True
        if not _ensure_playwright_browsers():
            return "", "headless:chromium_install_failed"

    # JavaScript to mask headless browser fingerprint
    _STEALTH_JS = """
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
    Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
    window.chrome = {runtime: {}};
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) =>
        parameters.name === 'notifications'
            ? Promise.resolve({state: Notification.permission})
            : originalQuery(parameters);
    """

    import random

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                user_agent=random.choice(_USER_AGENTS),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
                color_scheme="light",
                java_script_enabled=True,
            )
            context.add_init_script(_STEALTH_JS)
            page = context.new_page()

            # Navigate with short timeout
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                browser.close()
                return "", "headless:navigation_failed"

            # Brief wait for JS rendering
            page.wait_for_timeout(3000)

            # Quick scroll to trigger lazy content
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1000)

            content = page.content()
            browser.close()

            if content and len(content) > 500:
                text = html_to_text(content[:MAX_CONTENT_CHARS])
                if text and len(text) > 200:
                    return text, "headless"
            return "", "headless:no_content"
    except Exception as e:
        return "", f"headless:{type(e).__name__}"


# ---------------------------------------------------------------------------
# Fallback — STIX description metadata
# ---------------------------------------------------------------------------

def _stix_description_fallback(description: str) -> tuple:
    """Use the STIX external_reference description as content.
    Always available — contains author, title, date, publication."""
    if description and len(description.strip()) > 10:
        return description.strip(), "stix_metadata"
    return "", "no_content"


# ---------------------------------------------------------------------------
# Relevance extraction
# ---------------------------------------------------------------------------

def _extract_relevant_passages(
    full_text: str,
    group_name: str,
    technique_name: str,
    technique_id: str,
    indicators: list | None = None,
) -> str:
    """Return the most relevant paragraphs from full_text for this technique.

    MITRE has already done the actor→citation linkage, so searching for the
    group name is redundant: citations are either specifically about that
    actor (linkage guaranteed) or describe a generic tool/technique (where
    the actor name won't appear anyway).  We score purely on technique
    relevance.

    Scoring: count of distinct technique search terms found in the paragraph.
    Paragraphs with zero hits are excluded.  Ties are broken by original
    document order (stable sort).  Returns up to MAX_RELEVANT_CHARS.
    """
    if not full_text:
        return ""

    search_terms: set = set()

    # Technique name as a full phrase (avoids false positives on common words)
    if technique_name and len(technique_name) >= 4:
        search_terms.add(technique_name.lower())

    # Technique ID — also add parent ID for sub-techniques (e.g. T1059 from T1059.001)
    if technique_id:
        search_terms.add(technique_id.lower())
        if "." in technique_id:
            search_terms.add(technique_id.split(".")[0].lower())

    # Extracted indicators as supplementary signals (e.g. "net time", "hwclock")
    if indicators:
        for ind in indicators[:5]:
            if isinstance(ind, str) and len(ind) >= 4:
                search_terms.add(ind.lower())

    search_terms = {t for t in search_terms if len(t) >= 3}

    if not search_terms:
        return full_text[:MAX_RELEVANT_CHARS]

    paragraphs = re.split(r"\n\s*\n", full_text)
    scored = []
    total_len = 0

    for para in paragraphs:
        para = para.strip()
        if len(para) < 30:
            continue
        para_lower = para.lower()
        hits = sum(1 for t in search_terms if t in para_lower)
        if hits:
            scored.append((hits, para))
            total_len += len(para)
            if total_len >= MAX_RELEVANT_CHARS * 3:
                break

    if not scored:
        return ""

    scored.sort(key=lambda x: -x[0])
    passages = []
    chars = 0
    for _, para in scored:
        passages.append(para)
        chars += len(para)
        if chars >= MAX_RELEVANT_CHARS:
            break

    return "\n\n".join(passages)


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------

def _rewrite_url(url: str) -> str:
    """Rewrite known redirected/migrated URLs to their current location."""
    if not url:
        return url
    # Mandiant blogs migrated to Google Cloud
    if "www.mandiant.com/resources" in url:
        slug = url.rsplit("/", 1)[-1]
        return f"https://cloud.google.com/blog/topics/threat-intelligence/{slug}/"
    # FireEye blogs also migrated to Mandiant/Google
    if "www.fireeye.com/blog/" in url:
        slug = url.rsplit("/", 1)[-1]
        return f"https://cloud.google.com/blog/topics/threat-intelligence/{slug}/"
    return url


def _should_skip_url(url: str) -> bool:
    if not url or not url.startswith("http"):
        return True
    parsed = urlparse(url)
    if parsed.netloc.lower().lstrip("www.") in _SKIP_DOMAINS:
        return True
    ext = os.path.splitext(parsed.path)[1].lower()
    if ext in _BINARY_EXTENSIONS:
        return True
    return False


def _is_pdf_url(url: str) -> bool:
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    return ext in _PDF_EXTENSIONS


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_citations(procedure_text: str, external_references: list) -> list:
    """Map (Citation: X) in procedure text to reference metadata."""
    if not procedure_text or not external_references:
        return []

    citation_names = re.findall(r"\(Citation:\s*([^)]+)\)", procedure_text)
    if not citation_names:
        return []

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
    """Fetch content from citation URLs using a multi-method fallback chain.

    For each citation, tries methods in order until content is obtained:
      1. Direct fetch (browser headers, SSL fallback)
      2. Wayback Machine snapshot
      3. Google Cache
      4. PDF extraction (for .pdf URLs)
      Fallback: STIX description metadata

    Returns list of dicts with: citation_name, url, description,
    extracted_content, method, attempts
    """
    results = []
    session = _make_session()

    for cit in citations:
        url = _rewrite_url(cit.get("url", ""))
        stix_desc = cit.get("description", "")
        entry = {
            "citation_name": cit["citation_name"],
            "url": url,
            "description": stix_desc,
            "extracted_content": "",
            "method": "",
            "attempts": [],
        }

        # Skip useless citations (homepages, docs, tool sites)
        _cname = cit["citation_name"]
        if any(re.search(p, _cname) for p in _SKIP_CITATION_PATTERNS):
            continue
        if url:
            _parsed = urlparse(url)
            _url_domain = _parsed.netloc.lower().lstrip("www.")
            _url_path = _parsed.path.lower()
            if any(_url_domain.startswith(d.lstrip("www.")) for d in _SKIP_CITATION_URLS):
                continue
            if any(p in _url_path for p in _SKIP_URL_PATHS):
                continue

        if not url:
            # No URL — use STIX metadata directly
            text, method = _stix_description_fallback(stix_desc)
            entry["extracted_content"] = text
            entry["method"] = method
            entry["attempts"].append("no_url → stix_metadata")
            results.append(entry)
            continue

        if _should_skip_url(url):
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            entry["method"] = f"skipped ({ext})" if ext in _BINARY_EXTENSIONS else "skipped_domain"
            entry["attempts"].append(entry["method"])
            # Still use STIX metadata
            text, _ = _stix_description_fallback(stix_desc)
            entry["extracted_content"] = text
            results.append(entry)
            continue

        # Check cache first
        cached = _read_cache(url)
        if cached is not None:
            if cached:
                relevant = _extract_relevant_passages(
                    cached, group_name, technique_name, technique_id, indicators
                )
                entry["extracted_content"] = relevant or cached[:MAX_RELEVANT_CHARS]
                entry["method"] = "cached"
                entry["attempts"].append("cache_hit")
            else:
                # Cached failure — don't re-attempt the full method chain
                fb_text, fb_method = _stix_description_fallback(stix_desc)
                entry["extracted_content"] = fb_text
                entry["method"] = "no_content"
                entry["attempts"].append("cache_hit_empty")
            results.append(entry)
            continue

        # --- Method chain (tries each method until content is obtained) ---
        text = ""
        is_pdf = _is_pdf_url(url)
        _got_403 = False

        # Method 4 first for PDFs
        if is_pdf:
            _rate_limit(url)
            text, detail = _fetch_pdf(url, session)
            entry["attempts"].append(f"pdf → {detail}")
            if text:
                _write_cache(url, text, "pdf")
                entry["method"] = detail

        # Method 1 — Direct fetch
        if not text and not is_pdf:
            _rate_limit(url)
            text, detail = _fetch_direct(url, session)
            entry["attempts"].append(f"direct → {detail}")
            if text:
                _write_cache(url, text, "direct")
                entry["method"] = "direct"
            elif "403" in detail or "401" in detail:
                _got_403 = True
            elif "js_rendered" in detail:
                _got_403 = True  # also try headless for JS-rendered pages

        # Method 5 — Headless browser (if direct got 403/Cloudflare or JS-rendered)
        if not text and _got_403:
            text, detail = _fetch_headless(url)
            entry["attempts"].append(f"headless → {detail}")
            if text:
                _write_cache(url, text, "headless")
                entry["method"] = "headless"

        # Method 2 — Wayback Machine
        if not text:
            _rate_limit("https://archive.org")
            text, detail = _fetch_wayback(url, session)
            entry["attempts"].append(f"wayback → {detail}")
            if text:
                _write_cache(url, text, "wayback")
                entry["method"] = "wayback"

        # Method 3 — Google Cache
        if not text:
            _rate_limit("https://webcache.googleusercontent.com")
            text, detail = _fetch_google_cache(url, session)
            entry["attempts"].append(f"google_cache → {detail}")
            if text:
                _write_cache(url, text, "google_cache")
                entry["method"] = "google_cache"

        # Extract relevant passages if we got content
        if text:
            relevant = _extract_relevant_passages(
                text, group_name, technique_name, technique_id, indicators
            )
            entry["extracted_content"] = relevant or text[:MAX_RELEVANT_CHARS]
        else:
            # Fallback — STIX description metadata (always available)
            fb_text, fb_method = _stix_description_fallback(stix_desc)
            entry["extracted_content"] = fb_text
            entry["method"] = fb_method
            entry["attempts"].append(f"fallback → {fb_method}")
            # Cache failure to skip on subsequent procedures in same run
            # --clear-cache removes these for fresh retry next time
            _write_cache(url, "", "failed")

        results.append(entry)

    return results


def extract_indicators_from_text(text: str) -> dict:
    """Extract indicators from fetched citation text using MITRESaw's patterns.

    Returns dict: {type: [values]} matching MITRESaw's evidence format.
    Types: cmd, reg, cve, paths, software, ports
    """
    if not text or len(text) < 50:
        return {}

    # Strip non-printable/binary characters (bad PDF extraction)
    text = re.sub(r"[^\x20-\x7E\n\r\t]", "", text)
    if len(text) < 50:
        return {}

    # Reject garbled/encoded text (base64, mangled PDF extraction)
    # Real prose has mostly alphanumeric + spaces; gibberish has high special-char density
    _sample = text[:2000]
    _alnum_spaces = sum(1 for c in _sample if c.isalnum() or c == ' ')
    if len(_sample) > 0 and _alnum_spaces / len(_sample) < 0.65:
        return {}

    # Ensure known-commands YAML is loaded
    _load_known_commands()

    indicators = {}

    # Backtick-quoted strings (highest confidence)
    backtick_re = re.compile(r"`([^`]{3,120})`")
    backticks = backtick_re.findall(text)
    if backticks:
        # Classify backtick content
        for bt in backticks[:30]:
            bt = bt.strip()
            if len(bt) < 3 or len(bt) > 200:
                continue
            bt_lower = bt.lower()
            if re.match(r"HK(?:LM|CU|CR|U|CC)\\", bt, re.IGNORECASE):
                indicators.setdefault("reg", []).append(bt)
            elif re.match(r"[A-Za-z]:\\", bt) or bt.startswith("\\\\") or re.match(r"/(?:etc|var|tmp|usr|home|opt|bin|proc)/", bt):
                indicators.setdefault("paths", []).append(bt)
            elif bt_lower.split() and bt_lower.split()[0] in _KNOWN_CMD_NAMES:
                # First word is a known command — always cmd regardless of extensions
                # in the arguments (e.g. `del /f /q payload.exe`, `powershell -File x.ps1`)
                indicators.setdefault("cmd", []).append(bt)
            elif re.search(r"\.(?:exe|dll|ps1|bat|vbs|sh|py|cmd)\b", bt_lower):
                indicators.setdefault("software", []).append(bt)
            elif bt_lower in _KNOWN_SOFTWARE_NAMES:
                # Known offensive tool / malware name — no extension but still software
                indicators.setdefault("software", []).append(bt)
            elif len(bt.split()) >= 2 or re.search(r"[-/]", bt):
                # Multi-word or has flags/path separators — definitely a command
                indicators.setdefault("cmd", []).append(bt)
            elif bt_lower in _KNOWN_CMD_NAMES:
                # Single-word known command (e.g. date, hwclock, timedatectl, net, sc)
                indicators.setdefault("cmd", []).append(bt)

    # Filter prose fragments from cmd/software backtick captures.
    # These are the same patterns used by extract.py but applied here to
    # citation text which has no MITRE markdown formatting to constrain scope.
    _PROSE_PHRASES = frozenset([
        "where the", "such as", "can be used", "can additionally",
        "information about", "information such", "the type of",
        "for example", "is used to", "are used to", "may use",
        "can also", "can list", "will be", "used by",
        "providers also", "cloud providers", "infrastructure as",
        "as well as", "in order to", "refers to", "known as",
        "which is", "that is", "there is", "there are",
    ])
    _PROSE_STARTS = (
        "in ", "on ", "the ", "that ", "which ", "a ", "an ", "and ",
        "or ", "for ", "to ", "from ", "with ", "this ", "these ",
        "can ", "may ", "is ", "are ", "it ", "its ", "also ",
        "when ", "if ", "as ", "by ", "at ", "of ",
    )
    for _prose_type in ("cmd", "software"):
        if _prose_type in indicators:
            indicators[_prose_type] = [
                v for v in indicators[_prose_type]
                if not any(phrase in v.lower() for phrase in _PROSE_PHRASES)
                and not any(v.lower().startswith(prefix) for prefix in _PROSE_STARTS)
                and len(v) <= 150
            ]

    # CVE IDs
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
    cves = list(set(cve_re.findall(text)))
    if cves:
        indicators["cve"] = cves[:10]

    # Registry paths (outside backticks)
    reg_re = re.compile(r"HK(?:LM|CU|CR|U|CC)\\[^\s\n\"'`]{6,200}")
    regs = list(set(reg_re.findall(text)))
    if regs:
        indicators.setdefault("reg", []).extend(regs)

    # Windows file paths (outside backticks)
    win_path_re = re.compile(r"[A-Za-z]:\\[^\s\n\"'`]{4,200}")
    unix_path_re = re.compile(r"/(?:etc|var|tmp|usr|home|opt|bin|sbin|proc)/[^\s\n\"'`]{2,150}")
    paths = list(set(win_path_re.findall(text) + unix_path_re.findall(text)))
    if paths:
        indicators.setdefault("paths", []).extend(paths)

    # Port numbers — context-aware extraction
    # High-confidence: explicit protocol prefix or "port" keyword
    _hi_port_re = re.compile(
        r"(?:TCP/|UDP/|port\s+)(\d{1,5})\b", re.IGNORECASE
    )
    # Medium-confidence: IP:port format (e.g. 192.168.1.1:4444)
    _ip_port_re = re.compile(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d{1,5})\b"
    )
    # Context-dependent: bare numbers near network keywords (not IP octets)
    _ctx_port_re = re.compile(
        r"(?:(?:inbound|outbound|ingress|egress)\s+(?:on\s+|over\s+|via\s+|port\s+|connections?\s+(?:on\s+|to\s+)?)?"
        r"|listen(?:ing|s)?\s+(?:on\s+|port\s+)?"
        r"|connect(?:s|ing)?\s+(?:on|to|via)\s+(?:port\s+)?"
        r"|beacon(?:ing)?\s+(?:on|to|over)\s+(?:port\s+)?"
        r"|communicat\w+\s+(?:on|over|via)\s+(?:port\s+)?"
        r"|traffic\s+(?:on|over)\s+(?:port\s+)?"
        r"|tunnel(?:ing)?\s+(?:on|over|via)\s+(?:port\s+)?"
        r"|c2\s+(?:on|over|port)\s+(?:port\s+)?"
        r"|c&c\s+(?:on|over|port)\s+(?:port\s+)?)"
        r"(\d{1,5})\b", re.IGNORECASE
    )
    # Collect all IP addresses to exclude their octets
    _ip_octets = set()
    for _ip_match in re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text):
        _ip_octets.update(_ip_match.split("."))

    _all_ports = set()
    _all_ports.update(_hi_port_re.findall(text))
    _all_ports.update(_ip_port_re.findall(text))
    _all_ports.update(_ctx_port_re.findall(text))
    ports = [p for p in _all_ports if 1 <= int(p) <= 65535 and p not in _ip_octets]
    if ports:
        indicators["ports"] = ports[:10]

    # Deduplicate and filter gibberish from each type
    for k in indicators:
        seen = set()
        deduped = []
        for v in indicators[k]:
            vl = v.lower()
            if vl in seen:
                continue
            # Reject individual values that look like encoded/garbled text
            if k != "cve":  # CVEs have a strict format, always clean
                _val_clean = sum(1 for c in v if c.isalnum() or c in ' \\/:.-_')
                if len(v) > 5 and _val_clean / len(v) < 0.75:
                    continue
                # Reject if too many "junk" special chars typical of encoding
                _junk = sum(1 for c in v if c in '$@#}{)(+*=;|^~`<>[]!?')
                if len(v) > 5 and _junk / len(v) > 0.08:
                    continue
            seen.add(vl)
            deduped.append(v)
        indicators[k] = deduped[:15]  # cap at 15 per type

    return indicators


# Emoji mapping matching MITRESaw's extract.py
_INDICATOR_EMOJI = {
    "cmd": "💻",
    "reg": "🔑",
    "cve": "🔒",
    "paths": "📁",
    "software": "📦",
    "ports": "🌐",
}


def clear_cache_stix_metadata() -> int:
    """Remove cache entries where method is stix_metadata or failed.
    These had a URL but all fetch methods failed, falling back to STIX description only.
    """
    return _clear_cache_by(lambda d: d.get("method") in ("stix_metadata", "failed", ""))


def clear_cache_no_content() -> int:
    """Remove cache entries with empty text (no content at all).
    These are URLs where every method failed and even STIX had nothing.
    """
    return _clear_cache_by(lambda d: not d.get("text", ""))


def clear_cache_all_failed() -> int:
    """Remove all failed cache entries (stix_metadata + no_content + failed).
    Preserves only successfully fetched pages with real content.
    """
    return _clear_cache_by(lambda d: not d.get("text", "") or d.get("method") in ("stix_metadata", "failed", ""))


def _clear_cache_by(predicate) -> int:
    """Remove cache entries matching a predicate function."""
    if not CACHE_DIR.exists():
        return 0
    removed = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if predicate(data):
                f.unlink()
                removed += 1
        except Exception:
            f.unlink()
            removed += 1
    return removed


def import_citation_files(import_dir: str) -> int:
    """Import manually saved PDF/HTML files into the citation cache.

    File naming convention — use any of these formats:
      securelist.com_apt-luminousmoth.pdf
      https___securelist.com_apt-luminousmoth_103332.html
      unit42.paloaltonetworks.com_medusa-ransomware.pdf
      any-descriptive-name.pdf  (matched by content, not URL)

    For URL-named files, the filename is decoded back to a URL for cache keying.
    For other files, they're cached by filename and matched during collection
    by searching the extracted text for citation names.

    Args:
        import_dir: Path to directory containing PDF/HTML files.

    Returns:
        Number of files successfully imported.
    """
    import_path = Path(import_dir)
    if not import_path.exists():
        print(f"    Import directory not found: {import_dir}")
        return 0

    imported = 0
    for f in sorted(import_path.iterdir()):
        if f.name.startswith("."):
            continue
        ext = f.suffix.lower()
        if ext not in (".pdf", ".html", ".htm", ".txt"):
            continue

        text = ""

        # Extract text based on file type
        if ext == ".pdf":
            try:
                from PyPDF2 import PdfReader
                reader = PdfReader(str(f))
                pages = []
                for page in reader.pages[:50]:
                    t = page.extract_text()
                    if t:
                        pages.append(t)
                text = "\n\n".join(pages)[:MAX_CONTENT_CHARS]
            except ImportError:
                try:
                    import pdfplumber
                    with pdfplumber.open(str(f)) as pdf:
                        pages = [p.extract_text() for p in pdf.pages[:50] if p.extract_text()]
                    text = "\n\n".join(pages)[:MAX_CONTENT_CHARS]
                except ImportError:
                    print(f"    Skipping {f.name}: no PDF parser (pip install PyPDF2)")
                    continue
            except Exception as e:
                print(f"    Skipping {f.name}: {e}")
                continue
        else:
            # HTML or text file
            try:
                raw = f.read_text(errors="ignore")
                if ext in (".html", ".htm"):
                    text = html_to_text(raw[:MAX_CONTENT_CHARS])
                else:
                    text = raw[:MAX_CONTENT_CHARS]
            except Exception as e:
                print(f"    Skipping {f.name}: {e}")
                continue

        if not text or len(text) < 50:
            print(f"    Skipping {f.name}: insufficient content")
            continue

        # Derive URL from filename
        # Try to decode: https___securelist.com_apt-luminousmoth_103332.html → URL
        stem = f.stem
        url = ""
        if stem.startswith("http"):
            url = stem.replace("___", "://").replace("__", "/").replace("_", "/")
            # Fix common issues
            if not url.startswith("http"):
                url = "https://" + url
        else:
            # Use filename as-is for cache key
            url = f"file://{f.name}"

        _write_cache(url, text, "imported")
        imported += 1
        print(f"    Imported: {f.name} ({len(text)} chars) → cached as [{url[:60]}]")

    return imported


def collect_references_parallel(
    citations: list,
    group_name: str,
    technique_name: str,
    technique_id: str,
    indicators: list | None = None,
    max_workers: int = 10,
) -> list:
    """Fetch multiple citations concurrently using a thread pool.

    Each citation is fetched independently. Per-domain rate limiting
    still applies within each thread.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not citations:
        return []

    # Single citation — no need for threading overhead
    if len(citations) == 1:
        return collect_reference_content(
            citations, group_name, technique_name, technique_id, indicators
        )

    results = []

    def _fetch_one(cit):
        return collect_reference_content(
            [cit], group_name, technique_name, technique_id, indicators
        )

    with ThreadPoolExecutor(max_workers=min(max_workers, len(citations))) as pool:
        futures = {pool.submit(_fetch_one, cit): cit for cit in citations}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.extend(result)
            except Exception:
                pass

    return results
