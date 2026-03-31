#!/usr/bin/env python3 -tt
import argparse
from argparse import RawTextHelpFormatter
from toolbox.main import mainsaw

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
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
    "-t", "--searchterms",
    default=".",
    help="Filter Threat Actor results based on specific industries e.g. mining,technology,defense,law (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors (default: .)\n\n",
)
parser.add_argument(
    "-g", "--threatgroups",
    default=".",
    help="Filter Threat Actor results based on specific group names e.g. APT29,HAFNIUM,Lazurus_Group,Turla (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors (default: .)\n",
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
    "-Q",
    "--queries",
    help="Build search queries based on results - to be imported into Splunk; Azure Sentinel; Elastic/Kibana\n",
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
    "-r",
    "--truncate",
    help="Truncate printing of indicators for a cleaner output (they are still written to output file)\n",
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
    "-d",
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
    "-F",
    "--fetch",
    help="Force a fresh download of ATT&CK STIX data (default: re-download if older than 7 days)\n",
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
operating_platforms = [args.platforms]
search_terms = [args.searchterms]
provided_groups = [args.threatgroups]
show_others = args.showotherlogsources
art = args.asciiart
navigationlayers = args.navlayers
queries = args.queries
truncate = args.truncate
columns = args.columns
preset = args.default
export_format = args.export
quiet = args.quiet
fetch = args.fetch
evidence_report = args.evidence_report
collect_references = args.citations

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
        queries,
        truncate,
        attack_frameworks,
        attack_version,
        sheet_tabs,
        columns,
        preset,
        export_format,
        quiet,
        fetch,
        evidence_report=evidence_report,
        collect_references=collect_references,
    )


if __name__ == "__main__":
    main()
