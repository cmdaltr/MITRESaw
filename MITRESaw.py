#!/usr/bin/env python3 -tt
import argparse
from argparse import RawTextHelpFormatter
from MITRESaw.toolbox.main import mainsaw

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument(
    "framework",
    nargs=1,
    help="Specify which framework to collect from - Enterprise, ICS or Mobile\n",
)
parser.add_argument(
    "platforms",
    nargs=1,
    help="Filter results based on provided platforms e.g. Windows,Linux,IaaS,Azure_AD (use _ instead of spaces)\n Use . to not filter i.e. obtain all Platforms\n Valid options are: 'Azure_AD', 'Containers', 'Google_Workspace', 'IaaS', 'Linux', 'Network', 'Office_365', 'PRE', 'SaaS', 'Windows', 'macOS'\n\n",
)
parser.add_argument(
    "searchterms",
    nargs=1,
    help="Filter Threat Actor results based on specific industries e.g. mining,technology,defense,law (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors\n\n",
)
parser.add_argument(
    "threatgroups",
    nargs=1,
    help="Filter Threat Actor results based on specific group names e.g. APT29,HAFNIUM,Lazurus_Group,Turla (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors\n",
)
parser.add_argument(
    "-a",
    "--asciiart",
    help="Don't show ASCII Art of the saw.\n",
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
    help="Show log sources which can detect identified techniques where the coverage is less than 1%\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-q",
    "--queries",
    help="Build search queries based on results - to be imported into Splunk; Azure Sentinel; Elastic/Kibana\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-t",
    "--truncate",
    help="Truncate printing of indicators for a cleaner output (they are still written to output file)\n",
    action="store_const",
    const=True,
    default=False,
)


args = parser.parse_args()
attackframework = args.framework
operating_platforms = args.platforms
search_terms = args.searchterms
provided_groups = args.threatgroups
show_others = args.showotherlogsources
art = args.asciiart
navigationlayers = args.navlayers
queries = args.queries
truncate = args.truncate

attack_framework = attackframework[0].title()
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
        attack_framework,
        attack_version,
        sheet_tabs,
    )


if __name__ == "__main__":
    main()
