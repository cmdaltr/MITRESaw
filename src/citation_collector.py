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
# Optional scoring dependencies
# Tier 1 — BM25 + NLTK stemming/synonyms (pip install rank-bm25 nltk)
# Tier 2 — Semantic embeddings        (pip install sentence-transformers)
# All three tiers degrade gracefully: Tier 2 → Tier 1 → keyword fallback.
# ---------------------------------------------------------------------------

# Tier 1a: BM25
try:
    from rank_bm25 import BM25Okapi as _BM25Okapi  # type: ignore
    _HAS_BM25 = True
except ImportError:
    _BM25Okapi = None
    _HAS_BM25 = False

# Tier 1b: NLTK stemming + WordNet synonyms
_stemmer = None
_wordnet_corpus = None
_HAS_NLTK = False
_HAS_WORDNET = False
try:
    import nltk as _nltk_mod
    from nltk.stem import PorterStemmer as _PorterStemmer  # type: ignore
    _stemmer = _PorterStemmer()
    _HAS_NLTK = True
    # WordNet — attempt to load; download quietly on first use if missing
    try:
        from nltk.corpus import wordnet as _wordnet_corpus  # type: ignore
        _wordnet_corpus.synsets("test")  # trigger LookupError if data absent
        _HAS_WORDNET = True
    except Exception:
        try:
            _nltk_mod.download("wordnet", quiet=True)
            _nltk_mod.download("omw-1.4", quiet=True)
            from nltk.corpus import wordnet as _wordnet_corpus  # type: ignore
            _HAS_WORDNET = True
        except Exception:
            _wordnet_corpus = None
            _HAS_WORDNET = False
except ImportError:
    _nltk_mod = None

# Tier 2: Semantic model — loaded once on first use
_SEMANTIC_MODEL = None
_SEMANTIC_MODEL_CHECKED = False


def _get_semantic_model():
    """Lazy-load all-MiniLM-L6-v2 once; return None if not installed."""
    global _SEMANTIC_MODEL, _SEMANTIC_MODEL_CHECKED
    if _SEMANTIC_MODEL_CHECKED:
        return _SEMANTIC_MODEL
    _SEMANTIC_MODEL_CHECKED = True
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        _SEMANTIC_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:
        _SEMANTIC_MODEL = None
    return _SEMANTIC_MODEL


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

# ---------------------------------------------------------------------------
# Cross-technique indicator catalogue (Fix 1)
# Keyed by URL; populated the FIRST time a document is fetched so that
# subsequent techniques citing the same URL get the same complete indicator
# set without re-fetching.  See redistribute_citation_indicators().
# ---------------------------------------------------------------------------
_URL_FULL_INDICATORS: dict = {}

# ---------------------------------------------------------------------------
# Relevance scoring — stop words for technique-name tokenisation
# These are filtered OUT before building BM25/semantic queries because on
# their own they are too generic to distinguish technique relevance.
# ---------------------------------------------------------------------------
_TECHNIQUE_STOP_WORDS = frozenset({
    "and", "or", "the", "via", "a", "an", "of", "in", "on", "at",
    "by", "to", "its", "their", "use", "used", "using", "with",
    "from", "for", "through", "into", "over", "between",
})

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

# Set to False to disable platform-based filtering of extracted cmd indicators.
# Revert: flip this to False if platform filtering causes false negatives.
PLATFORM_FILTER_ENABLED: bool = True

_KNOWN_CMD_NAMES: frozenset = frozenset()
_KNOWN_SOFTWARE_NAMES: frozenset = frozenset()
# Per-platform cmd sets — used by filter_indicators_by_platform()
_KNOWN_WIN_CMDS: frozenset = frozenset()
_KNOWN_LINUX_CMDS: frozenset = frozenset()
_KNOWN_MACOS_CMDS: frozenset = frozenset()
_KNOWN_CROSS_CMDS: frozenset = frozenset()
_known_commands_loaded = False


def _load_known_commands():
    """Lazily load data/known_commands.yaml and build lookup sets."""
    global _KNOWN_CMD_NAMES, _KNOWN_SOFTWARE_NAMES, _known_commands_loaded
    global _KNOWN_WIN_CMDS, _KNOWN_LINUX_CMDS, _KNOWN_MACOS_CMDS, _KNOWN_CROSS_CMDS
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
        win_set: set = set()
        linux_set: set = set()
        macos_set: set = set()
        cross_set: set = set()
        _platform_map = {
            "windows": win_set,
            "linux": linux_set,
            "macos": macos_set,
            "cross_platform": cross_set,
        }
        for _platform, _types in (data or {}).items():
            if not isinstance(_types, dict):
                continue
            _plat_set = _platform_map.get(_platform)
            for _token in (_types.get("cmd") or []):
                _tok = str(_token).lower()
                cmd_set.add(_tok)
                if _plat_set is not None:
                    _plat_set.add(_tok)
            for _token in (_types.get("software") or []):
                sw_set.add(str(_token).lower())
        _KNOWN_CMD_NAMES = frozenset(cmd_set)
        _KNOWN_SOFTWARE_NAMES = frozenset(sw_set)
        _KNOWN_WIN_CMDS = frozenset(win_set)
        _KNOWN_LINUX_CMDS = frozenset(linux_set)
        _KNOWN_MACOS_CMDS = frozenset(macos_set)
        _KNOWN_CROSS_CMDS = frozenset(cross_set)
    except Exception:
        pass


def filter_indicators_by_platform(
    indicators: dict,
    technique_platforms: list,
) -> dict:
    """Drop cmd indicators that are known commands for a *different* platform.

    Rules:
    - Only runs when PLATFORM_FILTER_ENABLED is True.
    - Only filters when the technique targets a strict subset of platforms
      (e.g. Windows-only). If the technique runs on all major platforms,
      no filtering happens.
    - Unknown tool names (not in any known-cmd set) are ALWAYS kept —
      novel tools are the highest-value extraction output.
    - software, cve, paths, reg, ports are never filtered (platform-agnostic).
    - Cross-platform commands (curl, ssh, python, etc.) are always kept.

    To revert: set PLATFORM_FILTER_ENABLED = False at the top of this file.
    """
    if not PLATFORM_FILTER_ENABLED:
        return indicators

    _load_known_commands()

    # Normalise platform strings from MITRE ("Windows", "Linux", "macOS", ...)
    _plats = {p.lower().strip() for p in (technique_platforms or [])}
    # "mac os x" and "macos" both appear in STIX data
    if "mac os x" in _plats:
        _plats.add("macos")

    # No platforms listed, or all three major platforms present → nothing to filter
    _major = {"windows", "linux", "macos"}
    if not _plats or _major.issubset(_plats):
        return indicators

    # Build the set of platform-appropriate known commands
    _allowed: set = set(_KNOWN_CROSS_CMDS)  # cross-platform always ok
    if "windows" in _plats:
        _allowed |= _KNOWN_WIN_CMDS
    if "linux" in _plats:
        _allowed |= _KNOWN_LINUX_CMDS
    if "macos" in _plats:
        _allowed |= _KNOWN_MACOS_CMDS

    # Build the set of commands that exist but NOT for this technique's platforms
    _wrong_platform: set = _KNOWN_CMD_NAMES - _allowed

    if not _wrong_platform or "cmd" not in indicators:
        return indicators

    filtered_cmds = []
    for cmd in indicators["cmd"]:
        root = cmd.split()[0].lower().rstrip(".exe")
        if root in _wrong_platform:
            # Known command, wrong platform — drop it
            continue
        filtered_cmds.append(cmd)

    result = dict(indicators)
    if filtered_cmds:
        result["cmd"] = filtered_cmds
    else:
        result.pop("cmd", None)
    return result


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
            # (e.g. a direct fetch that grabbed a PDF binary blob)
            if text:
                text = re.sub(r"[^\x20-\x7E\n\r\t]", "", text)
            # If the surviving text is too sparse to be useful prose
            # (binary/garbled PDF), treat the cache as empty so the entry
            # shows as no_content and can be retried with -rN.
            if text:
                _sample = text[:2000]
                _alnum_sp = sum(1 for c in _sample if c.isalnum() or c == " ")
                if len(_sample) > 0 and _alnum_sp / len(_sample) < 0.65:
                    return ""
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
        import logging as _logging
        _logging.getLogger("PyPDF2").setLevel(_logging.ERROR)
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

    def _run_browser(headless: bool) -> tuple:
        """Launch browser, navigate, return (inner_text, error_str)."""
        try:
            with sync_playwright() as p:
                launch_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ]
                browser = p.chromium.launch(headless=headless, args=launch_args)
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
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception as e:
                    browser.close()
                    return "", str(e).splitlines()[0]
                page.wait_for_timeout(3000)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(1000)
                try:
                    text = page.inner_text("body")
                except Exception as e:
                    text = ""
                browser.close()
                return text[:MAX_CONTENT_CHARS] if text else "", ""
        except Exception as e:
            return "", str(e).splitlines()[0]

    try:
        # Pass 1 — headless (fast, no display required)
        text, err = _run_browser(headless=True)
        if text and len(text) > 200:
            return text, "headless"

        # Pass 2 — headed (bypasses Cloudflare fingerprinting; requires display)
        # Only attempt when a display is available (macOS always has one;
        # Linux servers need DISPLAY set).
        import sys as _sys
        _has_display = (
            _sys.platform == "darwin"                    # macOS always has a display
            or _sys.platform.startswith("win")           # Windows always has a display
            or bool(os.environ.get("DISPLAY"))           # Linux X11
            or bool(os.environ.get("WAYLAND_DISPLAY"))  # Linux Wayland
        )
        if _has_display:
            text, err = _run_browser(headless=False)
            if text and len(text) > 200:
                return text, "headless_headed"

        detail = f"headless:no_content  {err}" if err else "headless:no_content"
        return "", detail
    except Exception as e:
        return "", f"headless:{type(e).__name__}: {str(e).splitlines()[0]}"


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

# ---------------------------------------------------------------------------
# Relevance scoring helpers
# ---------------------------------------------------------------------------

def _stem_tokenize(text: str) -> list:
    """Lowercase, split on non-alpha, filter stop words, optionally stem."""
    tokens = re.findall(r"[a-z]{2,}", text.lower())
    tokens = [t for t in tokens if t not in _TECHNIQUE_STOP_WORDS]
    if _HAS_NLTK and _stemmer:
        tokens = [_stemmer.stem(t) for t in tokens]
    return [t for t in tokens if len(t) >= 2]


def _build_bm25_query(technique_name: str, indicator_strings: list) -> list:
    """Build a weighted BM25 token list from technique name + MITRE indicators.

    Indicators carry 3× weight (ground-truth signal).
    Technique name tokens carry 1× weight, plus WordNet synonyms where available.
    Technique ID is intentionally excluded — it never appears in threat reports.
    """
    query: list = []

    # Indicators — triple weight: these are what MITRE documented for this technique
    for ind in indicator_strings:
        query.extend(_stem_tokenize(ind) * 3)

    # Technique name — tokenised (not exact phrase)
    name_raw = [t for t in re.findall(r"[a-z]{2,}", (technique_name or "").lower())
                if t not in _TECHNIQUE_STOP_WORDS]
    if _HAS_NLTK and _stemmer:
        query.extend(_stemmer.stem(t) for t in name_raw)
    else:
        query.extend(name_raw)

    # WordNet synonyms for technique name tokens (unstemmed lookup → stem result)
    if _HAS_WORDNET and _wordnet_corpus and _stemmer:
        for raw_tok in name_raw:
            try:
                for syn in _wordnet_corpus.synsets(raw_tok)[:2]:
                    for lemma in syn.lemmas()[:2]:
                        word = lemma.name().replace("_", " ").split()[0]
                        if len(word) >= 3 and word.lower() not in _TECHNIQUE_STOP_WORDS:
                            query.append(_stemmer.stem(word))
            except Exception:
                pass

    return [t for t in query if len(t) >= 2]


def _score_bm25(paragraphs: list, query_tokens: list) -> list:
    """Score paragraphs with BM25Okapi. Returns [(score, paragraph)] with score > 0."""
    if not _HAS_BM25 or not query_tokens or not paragraphs:
        return []
    tokenized = [_stem_tokenize(p) for p in paragraphs]
    valid = [(tc, p) for tc, p in zip(tokenized, paragraphs) if tc]
    if not valid:
        return []
    bm25 = _BM25Okapi([v[0] for v in valid])
    scores = bm25.get_scores(query_tokens)
    return [(float(s), v[1]) for s, v in zip(scores, valid) if s > 0.0]


def _score_semantic(paragraphs: list, query: str) -> list:
    """Score paragraphs by cosine similarity to query via sentence-transformers.
    Returns [(score, paragraph)] with similarity > 0.20."""
    model = _get_semantic_model()
    if model is None or not query or not paragraphs:
        return []
    try:
        import numpy as np  # type: ignore
        q_emb = model.encode(query, convert_to_numpy=True)
        p_embs = model.encode(paragraphs, convert_to_numpy=True,
                               batch_size=32, show_progress_bar=False)
        q_norm = q_emb / (np.linalg.norm(q_emb) + 1e-10)
        p_norms = p_embs / (np.linalg.norm(p_embs, axis=1, keepdims=True) + 1e-10)
        sims = p_norms @ q_norm
        return [(float(s), p) for s, p in zip(sims, paragraphs) if s > 0.40]
    except Exception:
        return []


def _assemble_passages(scored: list) -> str:
    """Sort by score descending, concatenate up to MAX_RELEVANT_CHARS."""
    scored.sort(key=lambda x: -x[0])
    passages, chars = [], 0
    for _, para in scored:
        passages.append(para)
        chars += len(para)
        if chars >= MAX_RELEVANT_CHARS:
            break
    return "\n\n".join(passages)


def _extract_relevant_passages(
    full_text: str,
    technique_name: str,
    technique_id: str,
    indicators: list | None = None,
) -> str:
    """Return the most relevant paragraphs from full_text for this technique.

    Uses a tiered scoring approach — each tier falls back to the next if
    the dependency is not installed or returns no results:

      Tier 2 (best)  — Semantic cosine similarity via sentence-transformers
                        all-MiniLM-L6-v2.  Handles terminology mismatches
                        (e.g. "queries the system clock" ≈ "System Time Discovery").
      Tier 1         — BM25Okapi + Porter stemming + WordNet synonyms.
                        rank-bm25 and nltk packages required.
      Tier 0 (fallback) — Keyword token presence counting (always available).

    Key design decisions vs. original approach:
    • MITRE indicators are the primary signal (triple-weighted in BM25,
      included in semantic query) — they are ground truth for the technique.
    • Technique name is TOKENISED, not matched as an exact phrase.  Threat
      reports rarely use MITRE's exact phrasing.
    • Technique ID (T1059.001) is NOT used — it never appears in prose.
    • Group name is not a parameter — MITRE already linked citations to groups.
    """
    if not full_text:
        return ""

    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", full_text)]
    paragraphs = [p for p in paragraphs if len(p) >= 30]
    if not paragraphs:
        return ""

    # Flatten indicators to plain strings
    indicator_strings: list = []
    if indicators:
        for ind in indicators[:10]:
            if isinstance(ind, str) and len(ind) >= 3:
                indicator_strings.append(ind)
            elif isinstance(ind, dict):
                indicator_strings.extend(
                    str(k) for k in ind.keys() if len(str(k)) >= 3
                )

    # ── Tier 2: Semantic scoring ──────────────────────────────────────────────
    model = _get_semantic_model()
    if model is not None:
        query_parts = ([technique_name] if technique_name else []) + indicator_strings[:5]
        query = " ".join(query_parts)
        if query:
            scored = _score_semantic(paragraphs, query)
            if scored:
                return _assemble_passages(scored)

    # ── Tier 1: BM25 + stemming ───────────────────────────────────────────────
    if _HAS_BM25:
        query_tokens = _build_bm25_query(technique_name or "", indicator_strings)
        if query_tokens:
            scored = _score_bm25(paragraphs, query_tokens)
            if scored:
                return _assemble_passages(scored)

    # ── Tier 0: Keyword token fallback ───────────────────────────────────────
    search_terms: set = set()
    for token in re.findall(r"[a-z]{3,}", (technique_name or "").lower()):
        if token not in _TECHNIQUE_STOP_WORDS:
            search_terms.add(token)
    for ind in indicator_strings:
        search_terms.add(ind.lower())

    if not search_terms:
        return full_text[:MAX_RELEVANT_CHARS]

    min_hits = min(2, len(search_terms))  # require ≥2 terms when available
    scored = []
    for para in paragraphs:
        para_lower = para.lower()
        hits = sum(1 for t in search_terms if t in para_lower)
        if hits >= min_hits:
            scored.append((float(hits), para))
    return _assemble_passages(scored) if scored else ""


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------

def _rewrite_url(url: str) -> str:
    """Rewrite known redirected/migrated URLs to their current location."""
    if not url:
        return url
    # FireEye / Mandiant → Google Cloud (all content migrated)
    # Covers: www.fireeye.com, www2.fireeye.com, fireeye.com,
    #         www.mandiant.com, mandiant.com — any path.
    _fe_m = re.match(
        r"https?://(?:www2?\.)?(?:fireeye|mandiant)\.com(/.*)?$", url, re.IGNORECASE
    )
    if _fe_m:
        # Extract the last non-empty path segment as the slug
        _path = (_fe_m.group(1) or "").rstrip("/")
        _slug = _path.rsplit("/", 1)[-1] if _path else ""
        if _slug:
            return f"https://cloud.google.com/blog/topics/threat-intelligence/{_slug}/"
        # No recognisable slug — send to the index page
        return "https://cloud.google.com/blog/topics/threat-intelligence/"
    # LOLBAS project site is a Vue.js SPA — individual binary pages return a JS
    # shell with no meaningful content.  Rewrite to the raw YAML source in the
    # GitHub repo, which contains full command descriptions, use cases, and
    # detection guidance as plain text.
    # Pattern: https://lolbas-project.github.io/lolbas/{Type}/{Name}/
    #       → https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/yml/OS{Type}s/{Name}.yml
    _lolbas_m = re.match(
        r"https?://lolbas-project\.github\.io/lolbas/(\w+)/([^/]+)/?$",
        url, re.IGNORECASE,
    )
    if _lolbas_m:
        _ltype, _lname = _lolbas_m.group(1), _lolbas_m.group(2)
        # Map URL type segment → YAML subdirectory
        _type_map = {
            "binaries": "OSBinaries",
            "scripts":  "OSScripts",
            "libraries": "OSLibraries",
        }
        _subdir = _type_map.get(_ltype.lower(), f"OS{_ltype.title()}s")
        return (
            f"https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS"
            f"/master/yml/{_subdir}/{_lname}.yml"
        )
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
                # Populate full-indicator cache on first encounter (Fix 1)
                if url not in _URL_FULL_INDICATORS:
                    _URL_FULL_INDICATORS[url] = extract_indicators_from_text(cached)
                relevant = _extract_relevant_passages(
                    cached, technique_name, technique_id, indicators
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
            entry["full_indicators"] = _URL_FULL_INDICATORS.get(url, {})
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
                # Reject binary/garbled responses that decoded as text but are
                # not meaningful prose (e.g. gzip returned as text/html, JS blob)
                _qsample = text[:2000]
                _qalnum = sum(1 for c in _qsample if c.isalnum() or c == " ")
                if len(_qsample) > 0 and _qalnum / len(_qsample) < 0.65:
                    text = ""
                    _got_403 = True  # try headless for quality failures too
                    entry["attempts"].append("direct → quality_check_failed→headless")
                else:
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
                _write_cache(url, text, detail)   # preserves headless vs headless_headed
                entry["method"] = detail

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

        # Populate full-indicator cache on first successful fetch (Fix 1)
        if text and url not in _URL_FULL_INDICATORS:
            _URL_FULL_INDICATORS[url] = extract_indicators_from_text(text)

        # Extract relevant passages if we got content
        if text:
            relevant = _extract_relevant_passages(
                text, technique_name, technique_id, indicators
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

        entry["full_indicators"] = _URL_FULL_INDICATORS.get(url, {})
        results.append(entry)

    return results


_INDICATOR_NOISE_CHARS = frozenset("@%[]{}^!;~<>=|#$&,?")


def _is_plausible_indicator(bt: str) -> bool:
    """Return False if a candidate string is clearly garbled text, not a real indicator.

    Garbled strings arise from badly-extracted PDFs (ASCII garbage, RTF markup,
    base64 fragments, etc.).  Real commands/paths/tools are mostly alphabetic with
    a small set of punctuation characters.
    """
    # Embedded newlines / form-feeds — PDF paragraph boundaries bleeding in
    if any(c in bt for c in "\n\r\x0b\x0c"):
        return False
    # RTF control word sequences like \pard \ql \BM7 from PDF-to-text artifacts.
    # Windows paths (C:\Windows\...) and UNC paths (\\server\share) are exempt —
    # backslashes in those are path separators, not RTF escapes.
    _has_win_path = bool(
        re.search(r"[A-Za-z]:\\", bt) or   # drive path: C:\...
        re.search(r"\\\\[A-Za-z]", bt)      # UNC path: \\server (anywhere in string)
    )
    if not _has_win_path and re.search(r"\\[A-Za-z]{2,}", bt):
        return False
    # High density of characters that almost never appear in real commands/paths
    noise = sum(1 for c in bt if c in _INDICATOR_NOISE_CHARS)
    if noise >= 1 and len(bt) > 0 and noise / len(bt) > 0.07:
        return False
    # Very low alphabetic ratio — real indicators are mostly letters
    alpha = sum(1 for c in bt if c.isalpha())
    if len(bt) > 5 and alpha / len(bt) < 0.40:
        return False
    digits = sum(1 for c in bt if c.isdigit())
    # A single digit in a short word that is NOT at the end almost always
    # indicates a leetspeak letter substitution (t0r, s3cur1ty).
    # Legitimate tool names either put digits at the end (cmd2) or use
    # consecutive digit runs as part of the name (w32tm, b64decode).
    if len(bt) <= 5 and digits == 1 and not bt[-1].isdigit():
        return False
    # High digit density in longer strings = encoded/garbled fragment
    if len(bt) > 6 and digits / len(bt) > 0.40:
        return False
    # URL-encoded content (e.g. %3aKus...) — never a real command or tool name
    if re.search(r'%[0-9A-Fa-f]{2}', bt):
        return False
    # Short pure-alpha strings must have consistent case — mixed case in short words
    # (e.g. rEN, EnV, lC) almost always indicates garbled PDF text, not a real command.
    # Accepted patterns: all-lowercase, ALL-UPPERCASE, or PascalCase (e.g. Lua, Ren).
    _words = bt.split()
    if len(_words) == 1 and len(bt) <= 5 and bt.isalpha():
        if not (bt == bt.lower() or bt == bt.upper() or
                (bt[0].isupper() and bt[1:] == bt[1:].lower())):
            return False
    return True


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

    # ── Collect candidate strings from multiple sources ───────────────────
    # Citations vary widely in formatting — backticks, single/double quotes,
    # or no quoting at all.  Scan all styles plus known-name bare-prose matches.
    _cands: list = []

    # Backtick-quoted  (e.g. `net time /set`)
    for _m in re.finditer(r'`([^`\n]{3,120})`', text):
        _cands.append(_m.group(1).strip())

    # Single-quoted code-like content  (e.g. 'whoami /all', 'C:\Windows\...')
    # Require ≥ 6 chars to avoid English contractions (it's, don't, …).
    for _m in re.finditer(r"(?<!\w)'([A-Za-z][\w /\\:.@,\-]{5,100})'(?!\w)", text):
        _cands.append(_m.group(1).strip())

    # Double-quoted strings  (e.g. "cmd.exe /c whoami")
    for _m in re.finditer(r'"([A-Za-z][\w /\\:.@,\-]{5,100})"', text):
        _cands.append(_m.group(1).strip())

    # Known commands/software in plain prose (no quoting required).
    # Matches the tool name with optional flags/args following it.
    if _KNOWN_CMD_NAMES or _KNOWN_SOFTWARE_NAMES:
        _all_known = sorted(_KNOWN_CMD_NAMES | _KNOWN_SOFTWARE_NAMES, key=len, reverse=True)
        _known_re = re.compile(
            r'\b(' + '|'.join(re.escape(n) for n in _all_known) + r')'
            r'(?:\.exe)?'
            r'(?!\w)'  # must end at a word boundary (no partial match in e.g. APT29)
            r'(?:\s+[/\-]{1,2}[\w:]{1,20}){0,4}',
            re.IGNORECASE,
        )
        for _m in _known_re.finditer(text):
            _cands.append(_m.group(0).strip())

    # ── Classify each candidate ───────────────────────────────────────────
    for bt in _cands[:80]:
        bt = bt.strip()
        if len(bt) < 3 or len(bt) > 200:
            continue
        if not _is_plausible_indicator(bt):
            continue
        bt_lower = bt.lower()
        if re.match(r"HK(?:LM|CU|CR|U|CC)\\", bt, re.IGNORECASE):
            indicators.setdefault("reg", []).append(bt)
        elif re.match(r"[A-Za-z]:\\", bt) or bt.startswith("\\\\") or re.match(r"/(?:etc|var|tmp|usr|home|opt|bin|proc)/", bt):
            indicators.setdefault("paths", []).append(bt)
        elif bt_lower.split() and bt_lower.split()[0] in _KNOWN_CMD_NAMES:
            # First word is a known command — always cmd regardless of extensions
            # in the arguments (e.g. del /f /q payload.exe, powershell -File x.ps1)
            indicators.setdefault("cmd", []).append(bt)
        elif re.search(r"\.(?:exe|dll|ps1|bat|vbs|sh|py|cmd)\b", bt_lower):
            indicators.setdefault("software", []).append(bt)
        elif bt_lower in _KNOWN_SOFTWARE_NAMES:
            # Known offensive tool / malware name — no extension but still software
            indicators.setdefault("software", []).append(bt)
        elif re.search(r"[-/]", bt):
            # Has flags or path separators — require ≥2 chars before the first
            # flag/separator so standalone flags like -Vz8 or i/m are excluded.
            # Pre-flag must also be a known command, all-lowercase, or ≥4 chars;
            # short all-uppercase prefixes (e.g. PL in PL/ygP) are garbled text.
            _pre_flag = re.split(r"[\s\-/]", bt)[0]
            if (len(_pre_flag) >= 2
                    and not any(c in _INDICATOR_NOISE_CHARS for c in _pre_flag)
                    and (_pre_flag.lower() in _KNOWN_CMD_NAMES
                         or _pre_flag == _pre_flag.lower()
                         or len(_pre_flag) >= 4)):
                indicators.setdefault("cmd", []).append(bt)
        elif bt_lower in _KNOWN_CMD_NAMES:
            # Single-word known command (e.g. date, hwclock, timedatectl, net, sc)
            indicators.setdefault("cmd", []).append(bt)

    # Filter prose fragments from cmd/software captures.
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

    # Windows file paths — allow spaces within paths (e.g. "Program Files")
    # Stop at > (command-prompt chars), whitespace, and quotes.
    win_path_re = re.compile(
        r"[A-Za-z]:\\(?:[^\s\n\"'`>]+(?:\s(?=[A-Z(\\])[^\s\n\"'`>]+)*)"
    )
    unix_path_re = re.compile(r"/(?:etc|var|tmp|usr|home|opt|bin|sbin|proc)/[^\s\n\"'`]{2,150}")
    _raw_paths = list(set(win_path_re.findall(text) + unix_path_re.findall(text)))

    # Generic top-level directories that carry no threat-intel signal on their own
    _GENERIC_WIN_PATHS = frozenset({
        r"c:\windows", r"c:\windows\system32", r"c:\windows\syswow64",
        r"c:\program files", r"c:\program files (x86)",
        r"c:\users", r"c:\temp", r"c:\tmp",
    })
    # Registry-only path segments — reclassify as reg rather than paths
    _REGISTRY_IN_PATH = (
        r"\system\currentcontrolset", r"\software\microsoft",
        r"\controlset001", r"\controlset002",
    )
    paths = []
    for _p in _raw_paths:
        _p_low = _p.lower().rstrip("\\")
        # Skip generic system directories
        if _p_low in _GENERIC_WIN_PATHS:
            continue
        # Reclassify registry-like paths (e.g. m:\system\currentcontrolset\services)
        if any(kw in _p_low for kw in _REGISTRY_IN_PATH):
            indicators.setdefault("reg", []).append(_p)
            continue
        # Validate first path component — reject garbled short segments (e.g. D:\w2Mj)
        _after_drive = re.sub(r"^[A-Za-z]:\\", "", _p)
        _first_seg = _after_drive.split("\\")[0] if _after_drive else ""
        _seg_alpha = sum(1 for c in _first_seg if c.isalpha())
        _seg_digits = sum(1 for c in _first_seg if c.isdigit())
        # Must have at least 2 alphabetic chars in first segment (rejects g:\+, g:\*)
        if _first_seg and _seg_alpha < 2:
            continue
        if (_first_seg and len(_first_seg) <= 6 and _seg_digits == 1
                and not _first_seg[-1].isdigit()):
            continue  # single non-terminal digit = garbled (w2Mj, D:\w2Mj)
        paths.append(_p)

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

    _hi_ports = set(_hi_port_re.findall(text))
    _ip_ports = set(_ip_port_re.findall(text))
    _ctx_ports = set(_ctx_port_re.findall(text))
    _all_ports = _hi_ports | _ip_ports | _ctx_ports
    # Year-like numbers (1990–2030) are excluded unless they appear in an
    # unambiguous IP:port context (e.g. 192.168.1.1:2017).
    # "port 2017", "TCP/2017", "UDP/2017" in prose are too easily matched by
    # publication years, conference years, or CVE years — not admitted.
    ports = [
        p for p in _all_ports
        if 20 <= int(p) <= 65535        # ports < 20 are unassigned/noise in threat reports
        and p not in _ip_octets
        and not (1990 <= int(p) <= 2030 and p not in _ip_ports)
    ]
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
    import sys as _sys
    import time as _time
    if not CACHE_DIR.exists():
        return 0
    files = list(CACHE_DIR.glob("*.json"))
    total = len(files)
    removed = 0
    _start = _time.time()
    for i, f in enumerate(files, 1):
        try:
            data = json.loads(f.read_text())
            if predicate(data):
                f.unlink()
                removed += 1
        except Exception:
            f.unlink()
            removed += 1
        if i % 200 == 0 or i == total:
            _elapsed = _time.time() - _start
            _rate = i / _elapsed if _elapsed > 0 else i
            _eta = (total - i) / _rate if _rate > 0 else 0
            _sys.stdout.write(
                f"\r    Scanning cache: {i:,}/{total:,}  ({removed:,} removed)  "
                f"ETA: {int(_eta)}s   "
            )
            _sys.stdout.flush()
    if total > 0:
        _sys.stdout.write("\n")
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
                import logging as _logging
                _logging.getLogger("PyPDF2").setLevel(_logging.ERROR)
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


def retry_js_citations(failed_yaml: str | None = None) -> tuple[int, int]:
    """Re-attempt failed citations using Playwright headless rendering.

    Reads URLs from a citations_failed.yaml produced by a previous run (or
    falls back to scanning all no-content cache entries) and tries each URL
    with the headless browser.  Successfully fetched pages are written into
    the cache so the next normal run picks them up automatically.

    Args:
        failed_yaml: Path to citations_failed.yaml. If None, scans the cache.

    Returns:
        (attempted, recovered) counts.
    """
    import yaml as _yaml

    # url → citation_name mapping for display
    _url_titles: dict[str, str] = {}
    urls: list[str] = []

    # 1. Collect URLs to retry
    if failed_yaml and Path(failed_yaml).exists():
        try:
            with open(failed_yaml) as _f:
                _entries = _yaml.safe_load(_f) or []
            for _e in _entries:
                _u = (_e.get("url") or "").strip()
                if _u:
                    urls.append(_u)
                    _url_titles[_u] = (_e.get("citation_name") or "").strip()
        except Exception:
            pass

    # Fall back to cache scan if no YAML or YAML had no URLs
    if not urls and CACHE_DIR.exists():
        for _cf in CACHE_DIR.glob("*.json"):
            try:
                _d = json.loads(_cf.read_text())
                if not _d.get("text", ""):
                    _u = _d.get("url", "").strip()
                    if _u:
                        urls.append(_u)
                        # no citation_name in raw cache entries
            except Exception:
                pass

    urls = list(dict.fromkeys(urls))  # deduplicate, preserve order
    if not urls:
        print("    -rJ: No failed URLs found to retry.")
        return 0, 0

    import time as _time
    total = len(urls)
    print(f"    -rJ: Retrying {total:,} URL(s) with Playwright headless...")
    attempted = 0
    recovered = 0
    _start = _time.time()
    _recent: list[float] = []  # timestamps of last N completions for rolling ETA

    for _url in urls:
        attempted += 1
        _title = _url_titles.get(_url, "")
        _label = f"{_title}  [{_url}]" if _title else f"[{_url}]"

        text, detail = _fetch_headless(_url)

        _now = _time.time()
        _recent.append(_now)
        if len(_recent) > 10:
            _recent = _recent[-10:]

        _elapsed = _now - _start
        _remaining = total - attempted
        if len(_recent) >= 2:
            _window = _recent[-1] - _recent[0]
            _avg = _window / (len(_recent) - 1)
            _eta = _avg * _remaining
        elif _elapsed > 0:
            _avg = _elapsed / attempted
            _eta = _avg * _remaining
        else:
            _eta = 0

        if _eta >= 60:
            _eta_str = f"{int(_eta // 60)}m {int(_eta % 60):02d}s"
        else:
            _eta_str = f"{int(_eta)}s"

        _elapsed_str = (
            f"{int(_elapsed // 60)}m {int(_elapsed % 60):02d}s"
            if _elapsed >= 60
            else f"{int(_elapsed)}s"
        )

        _progress = f"\033[90m[{attempted}/{total}  ✔ {recovered}  ⏱ {_eta_str} remaining  elapsed {_elapsed_str}]\033[0m"

        if text:
            _write_cache(_url, text, "headless")
            recovered += 1
            print(f"       \033[32m✅\033[0m {_progress}  {_label}")
        else:
            print(f"       \033[31m❌\033[0m {_progress}  {_label}  ({detail})")

    return attempted, recovered


def redistribute_citation_indicators(
    citation_refs: list,
    group_technique_mitre_indicators: dict,
) -> list:
    """Cross-technique indicator redistribution (Fix 1).

    After all citations have been collected, this function checks whether any
    indicator that was extracted from a citation document matches a MITRE-
    documented indicator for a *different* technique of the same group.  If so,
    a new synthetic citation entry is created for that technique, attributing
    the indicator to the same source URL.

    This handles two cases:
      1. Another technique of the same group cites the same URL — it gets the
         full indicator set even if its own relevance filter missed them.
      2. Another technique of the same group does NOT cite the URL — but its
         MITRE-documented indicators appear in the document, so they are added.

    Parameters
    ----------
    citation_refs : list[dict]
        All citation refs collected during the run.  Must include 'group',
        'technique_id', 'url', and 'full_indicators'.
    group_technique_mitre_indicators : dict
        {(group_name, technique_id): set[str]} of lowercase indicator strings
        extracted from MITRE procedure text.  Used to decide whether a full-
        document indicator is relevant to a given technique.

    Returns
    -------
    list[dict] : Additional synthetic refs to inject into the citation pipeline.
                 Each has 'extracted_indicators' populated with matched values.
    """
    new_refs: list = []

    # Build: url → set of (group, technique_id) pairs that already cited it
    url_cited_by: dict = {}
    for ref in citation_refs:
        _u = ref.get("url", "")
        if _u:
            url_cited_by.setdefault(_u, set()).add(
                (ref.get("group", ""), ref.get("technique_id", ""))
            )

    # For each URL whose full indicators we have cached
    for url, full_inds in _URL_FULL_INDICATORS.items():
        if not full_inds:
            continue

        # Flatten full-document indicators to a lowercase string set for lookup
        doc_indicator_set: set = set()
        for vals in full_inds.values():
            for v in vals:
                if isinstance(v, str):
                    doc_indicator_set.add(v.lower())
                elif isinstance(v, dict):
                    doc_indicator_set.update(str(k).lower() for k in v.keys())

        if not doc_indicator_set:
            continue

        citing_pairs = url_cited_by.get(url, set())
        citing_groups = {g for g, _ in citing_pairs}

        for (group, tid), mitre_inds in group_technique_mitre_indicators.items():
            # Only redistribute within groups that already cited this URL
            # (at least one of their techniques cited it)
            if group not in citing_groups:
                continue

            # Skip if this (group, technique) already cited the URL — it has
            # its own entry and the full_indicators are already available via
            # the cache
            if (group, tid) in citing_pairs:
                continue

            # Find indicators that appear in the document AND are MITRE-documented
            # for this technique
            matching_lower = doc_indicator_set & {i.lower() for i in mitre_inds}
            if not matching_lower:
                continue

            # Build matched subset preserving original values/types
            matched: dict = {}
            for ind_type, vals in full_inds.items():
                matched_vals = []
                for v in vals:
                    v_key = (list(v.keys())[0] if isinstance(v, dict) else str(v))
                    if v_key.lower() in matching_lower:
                        matched_vals.append(v)
                if matched_vals:
                    matched[ind_type] = matched_vals

            if matched:
                new_refs.append({
                    "group": group,
                    "technique_id": tid,
                    "technique_name": "",  # filled in by caller from consolidated_techniques
                    "url": url,
                    "citation_name": f"[cross-technique: {url[:60]}]",
                    "description": "",
                    "extracted_content": "",
                    "extracted_indicators": matched,
                    "full_indicators": matched,
                    "method": "redistributed",
                    "attempts": ["redistributed"],
                })

    return new_refs


def collect_references_parallel(
    citations: list,
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
            citations, technique_name, technique_id, indicators
        )

    results = []

    def _fetch_one(cit):
        return collect_reference_content(
            [cit], technique_name, technique_id, indicators
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
