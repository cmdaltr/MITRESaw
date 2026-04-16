#!/usr/bin/env python3 -tt
import argparse
import os
import time
from argparse import RawTextHelpFormatter
from src.main import mainsaw

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument(
    "-l", "--list",
    choices=["groups", "platforms", "strings"],
    metavar="CATEGORY",
    help="List available filter values and exit. CATEGORY must be one of:\n"
         "  groups    — all threat groups and their known aliases\n"
         "  platforms — all valid platform names for -p\n"
         "  strings   — suggested search string keywords for -s\n",
)
parser.add_argument(
    "-f", "--framework",
    default="Enterprise,ICS,Mobile",
    help="Specify which framework(s) to collect from (comma-separated).\n"
         "Options: Enterprise, ICS, Mobile.\n"
         "Default: all three (Enterprise,ICS,Mobile).\n"
         "Example: -f Enterprise or -f Enterprise,ICS\n",
)
parser.add_argument(
    "-p", "--platforms",
    default=".",
    help="Filter results based on provided platforms e.g. Windows,Linux,IaaS,Azure_AD (use _ instead of spaces)\n Use . to not filter i.e. obtain all Platforms (default: .)\n Valid options are: 'Azure_AD', 'Containers', 'Google_Workspace', 'IaaS', 'Linux', 'Network', 'Office_365', 'PRE', 'SaaS', 'Windows', 'macOS'\n\n",
)
parser.add_argument(
    "-s", "--strings",
    default=".",
    help="Filter results based on search strings e.g. mining,technology,defense,law (use _ instead of spaces)\n Use . to not filter i.e. obtain all results (default: .)\n\n",
)
parser.add_argument(
    "-g", "--threatgroups",
    default=".",
    help="Filter Threat Actor results based on specific group names or aliases e.g. APT29,Cozy_Bear,HAFNIUM,Turla (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors (default: .)\n",
)
parser.add_argument(
    "-a",
    "--asciiart",
    help="Show ASCII Art of the saw.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-n",
    "--navlayers",
    help="Obtain ATT&CK Navigator layers for Groups identified during extraction of identifable evidence\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-o",
    "--showotherlogsources",
    help="Show log sources which can detect identified techniques where the coverage is less than 1%%\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-q",
    "--quiet",
    help="Suppress per-identifier output; print only when each Threat Group has been fully processed.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-c",
    "--columns",
    help="Export a filtered CSV (ThreatActors_Keywords.csv) with only specified columns (comma-separated).\n"
         "Includes a 'keywords' column option for auto-matched industry keyword tagging.\n"
         "Example: -c group_software_name,keywords\n",
    default=None,
)
parser.add_argument(
    "-D",
    "--default",
    help="Export an express CSV (ThreatActors_Keywords.csv) with key columns:\n"
         "group_sw_id, group_sw_name, group_sw_description,\n"
         "technique_id, technique_name, technique_description,\n"
         "tactic, procedure_example, evidence, detectable_via.\n"
         "Shortcut for -c with the above columns. If -c is also provided, -c takes precedence.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-x",
    "--export",
    help="Export format for output files (default: csv)\n",
    choices=["csv", "json", "xml"],
    default="csv",
)
parser.add_argument(
    "-E",
    "--evidence-report",
    help="Generate a styled XLSX evidence report (EvidenceReport_<timestamp>.xlsx)\n"
         "with one row per atomic indicator extracted from procedure examples.\n"
         "Applies the same group/platform/term filters as the main run.\n"
         "Compatible with all other flags; runs as a post-processing step.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-C",
    "--citations",
    help="Collect ALL citation/reference material for each technique.\n"
         "Fetches source URLs (blog posts, reports, advisories) and extracts\n"
         "pertinent content. Requires -E. Adds 'Reference Detail' sheet.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--clear-cache",
    help="Clear the entire citation cache before running.\n"
         "Forces re-download of all citation sources.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-rS", "--retry-stix",
    help="Retry citations that fell back to STIX metadata.\n"
         "Removes stix_metadata cache entries and re-attempts fetch.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-rN", "--retry-nocontent",
    help="Retry citations that had no content at all.\n"
         "Removes empty cache entries and re-attempts fetch.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-rJ", "--retry-js",
    help="Retry failed citations using Playwright headless rendering.\n"
         "Reads URLs from citations_failed.yaml (pass path) or scans cache.\n"
         "Writes recovered pages into cache for the next normal run.\n"
         "Example: -rJ data/2026-04-15/citations_failed.yaml\n",
    nargs="?",
    const="",           # no path given → scan cache
    metavar="YAML",
    default=None,
)
parser.add_argument(
    "-I", "--import-citations",
    help="Import manually saved citation files (PDF/HTML) into cache.\n"
         "Default directory: data/citations/\n"
         "Save blocked pages as PDF from your browser into data/citations/\n",
    nargs="?",
    const="data/citations",
    metavar="DIR",
    default=None,
)
parser.add_argument(
    "-w", "--max-workers",
    type=int,
    default=50,
    help="Max parallel threads for citation fetching (default: 50).\n"
         "Auto-reduces on rate limiting, recovers when stable.\n",
)
parser.add_argument(
    "-A", "--auto",
    help="Skip the pre-run ETA confirmation prompt and start immediately.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-F",
    "--fetch",
    help="Force a fresh download of ATT&CK STIX data (default: re-download if older than 7 days)\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--dry-run",
    help="Preview scope and exit — loads STIX data, applies all filters, prints the pre-run\n"
         "summary (groups matched, procedures, citations, cache status, estimated time)\n"
         "without fetching any content or writing any output files.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--stats",
    help="Show ATT&CK coverage summary and exit — total groups/techniques/procedures in\n"
         "the framework, citation cache coverage (fetched vs STIX-only vs no-content),\n"
         "and aggregate indicator coverage across all output runs.\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--stats-history",
    help="Like --stats but shows a separate Output Coverage section for each past run,\n"
         "labelled by date/invocation folder (e.g. 2026-04-15/_Iran_).\n",
    action="store_const",
    const=True,
    default=False,
)


args = parser.parse_args()
_FRAMEWORK_CANONICAL = {"enterprise": "Enterprise", "ics": "ICS", "mobile": "Mobile"}
attack_frameworks = [
    _FRAMEWORK_CANONICAL.get(f.strip().lower(), f.strip().title())
    for f in args.framework.split(",")
]


# ---------------------------------------------------------------------------
# -l / --list: list available filter values and exit
# ---------------------------------------------------------------------------
if args.list:
    category = args.list

    if category == "platforms":
        platforms = [
            "Azure_AD", "Containers", "Google_Workspace", "IaaS",
            "Linux", "Network", "Office_365", "PRE", "SaaS",
            "Windows", "macOS",
        ]
        print("\nAvailable platforms (use _ instead of spaces with -p):\n")
        for p in sorted(platforms):
            print(f"  {p}")
        print()

    elif category == "strings":
        suggestions = [
            ("Country (attributed or targeted)",
             ["australia", "canada", "china", "france", "germany", "india",
              "iran", "israel", "japan", "north_korea", "russia", "taiwan",
              "ukraine", "united_kingdom", "united_states"]),
            ("Industry / sector",
             ["aerospace", "banking", "defense", "education", "energy",
              "finance", "government", "healthcare", "law", "manufacturing",
              "media", "mining", "oil_and_gas", "pharmaceutical",
              "technology", "telecommunications", "transport"]),
            ("Motivation / intent",
             ["cryptomining", "cyber_espionage", "data_theft", "destruction",
              "disinformation", "financial", "hacktivism", "political",
              "ransomware", "sabotage", "surveillance"]),
        ]
        print("\nSuggested search strings for -s (use _ instead of spaces):\n")
        for heading, terms in suggestions:
            print(f"  {heading}:")
            print("    " + ",  ".join(terms))
            print()

    elif category == "groups":
        from src.main import load_attack_data
        print("\nLoading ATT&CK group data...\n")
        all_groups_seen: dict = {}  # name -> sorted alias list
        for fw in attack_frameworks:
            try:
                attack_data, _, _cs = load_attack_data(fw, force_fetch=args.fetch)
                for group in attack_data.get_groups(remove_revoked_deprecated=True):
                    name = group.get("name", "").strip()
                    if not name:
                        continue
                    aliases = [
                        a.strip() for a in (group.get("aliases") or [])
                        if a.strip() and a.strip().lower() != name.lower()
                    ]
                    if name not in all_groups_seen:
                        all_groups_seen[name] = aliases
                    else:
                        # merge aliases from additional frameworks
                        existing = set(all_groups_seen[name])
                        all_groups_seen[name] = sorted(
                            existing | set(aliases),
                            key=str.lower,
                        )
            except Exception as e:
                print(f"  Warning: could not load {fw} data: {e}")

        print(f"{'Group':<30}  Aliases")
        print(f"{'─' * 30}  {'─' * 60}")
        for name in sorted(all_groups_seen, key=str.lower):
            aliases = all_groups_seen[name]
            alias_str = ",  ".join(aliases) if aliases else "—"
            print(f"  {name:<28}  {alias_str}")
        print(f"\n  {len(all_groups_seen)} groups listed\n")

    import sys
    sys.exit(0)


# ---------------------------------------------------------------------------
# --stats / --stats-history: ATT&CK coverage dashboard
# ---------------------------------------------------------------------------
if args.stats or args.stats_history:
    from src.main import show_coverage_stats
    show_coverage_stats(attack_frameworks, "16.1", fetch=args.fetch, history=args.stats_history)
    import sys
    sys.exit(0)


# ---------------------------------------------------------------------------
# Normal run
# ---------------------------------------------------------------------------
operating_platforms = [args.platforms]
search_terms = [args.strings]
provided_groups = [args.threatgroups]
show_others = args.showotherlogsources
art = args.asciiart
navigationlayers = args.navlayers
columns = args.columns
preset = args.default
export_format = args.export
quiet = args.quiet
fetch = args.fetch
evidence_report = args.evidence_report
collect_citations = args.citations
args.max_workers = max(1, min(50, args.max_workers))

# ---------------------------------------------------------------------------
# Flag compatibility warnings
# ---------------------------------------------------------------------------
if args.clear_cache:
    if args.retry_stix:
        print("    ⚠️  Warning: --clear-cache + -rS is redundant — cache is wiped before -rS runs, so it will find nothing to remove.")
    if args.retry_nocontent:
        print("    ⚠️  Warning: --clear-cache + -rN is redundant — cache is wiped before -rN runs, so it will find nothing to remove.")
    if args.retry_js is not None:
        print("    ⚠️  Warning: --clear-cache + -rJ is redundant — cache is wiped before -rJ runs, so it will find no failed URLs to retry.")
if args.retry_nocontent and args.retry_js is not None:
    print("    ⚠️  Warning: -rN + -rJ is redundant — -rN removes no-content entries before -rJ runs, so -rJ will find nothing to retry.")

if args.clear_cache:
    import shutil
    cache_dir = "data/.citation_cache"
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
        print(f"    -> Cleared citation cache ({cache_dir}/)")
    else:
        print(f"    -> No citation cache to clear")

if args.retry_stix:
    from src.citation_collector import CACHE_DIR
    _rs_marker = os.path.join(CACHE_DIR, ".last_retry_stix")
    _rs_skip = False
    if os.path.exists(_rs_marker):
        _rs_age = time.time() - os.path.getmtime(_rs_marker)
        _rs_days = _rs_age / 86400
        if _rs_days < 30:
            print(f"    -> -rS was last run {_rs_days:.1f} days ago — retrying the same URLs")
            print(f"       will likely produce the same results. Skip? [Y/n] ", end="")
            try:
                _rs_resp = input().strip().lower()
                if _rs_resp not in ("n", "no"):
                    _rs_skip = True
                    print(f"    -> Skipped -rS (use --clear-cache for a full reset)")
            except (EOFError, KeyboardInterrupt):
                _rs_skip = True
    if not _rs_skip:
        from src.citation_collector import clear_cache_stix_metadata
        _removed = clear_cache_stix_metadata()
        print(f"    -rS: Removed {_removed} stix_metadata cache entries (will retry on this run)")
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(_rs_marker, "w") as _f:
            _f.write(time.strftime("%Y-%m-%d %H:%M:%S"))

if args.retry_nocontent:
    from src.citation_collector import clear_cache_no_content
    _removed = clear_cache_no_content()
    print(f"    -rN: Removed {_removed} no-content cache entries (will retry on this run)")

if args.retry_js is not None:
    from src.citation_collector import retry_js_citations
    _yaml_path = args.retry_js or None
    _attempted, _recovered = retry_js_citations(_yaml_path)
    print(f"         {_recovered}/{_attempted} URL(s) recovered via headless rendering")
    print()

if args.import_citations:
    from src.citation_collector import import_citation_files
    _count = import_citation_files(args.import_citations)
    print(f"    -> {_count} citation files imported into cache")

if preset and not columns:
    columns = (
        "group_sw_id,group_sw_name,group_sw_description,"
        "technique_id,technique_name,technique_description,"
        "tactic,platforms,framework,"
        "procedure_example,evidence,detectable_via"
    )

attack_version = "16.1"  # Updated to latest version, will auto-fetch latest from TAXII
sheet_tabs = [
    "techniques-techniques",
    "techniques-procedure examples",
    "groups-groups",
    "groups-techniques used",
]
port_indicators = []
evts_indicators = []
terms_indicators = []
collected_indicators = []
group_techniques = {}


def main():
    mainsaw(
        operating_platforms,
        search_terms,
        provided_groups,
        show_others,
        art,
        navigationlayers,
        False,   # queries (removed)
        False,   # truncate (removed)
        attack_frameworks,
        attack_version,
        sheet_tabs,
        columns,
        preset,
        export_format,
        quiet,
        fetch,
        evidence_report=evidence_report,
        collect_citations=collect_citations,
        citation_workers=args.max_workers,
        auto_confirm=args.auto,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
