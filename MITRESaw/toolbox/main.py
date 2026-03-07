#!/usr/bin/env python3 -tt
import os
import json
import random
import re
import requests
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Set

from mitreattack.stix20 import MitreAttackData
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server, Collection

import pandas

from MITRESaw.toolbox.extract import extract_indicators
from MITRESaw.toolbox.tools.write_csv import write_csv_summary
from MITRESaw.toolbox.tools.write_csv import write_csv_techniques_mapped_to_logsources
from MITRESaw.toolbox.output.matrix import build_matrix
from MITRESaw.toolbox.output.query import build_queries
from MITRESaw.toolbox.tools.keywords import match_keywords
from MITRESaw.toolbox.tools.read_files import collect_files
from MITRESaw.toolbox.tools.print_saw import print_saw


def get_latest_attack_version() -> str:
    """Fetch the latest MITRE ATT&CK version from STIX data."""
    try:
        # Use the TAXII server to get the latest version
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        collections = api_root.collections

        for collection in collections:
            if "Enterprise ATT&CK" in collection.title:
                # Get collection source
                collection_source = TAXIICollectionSource(collection)
                # Get the x-mitre-collection object to find version
                filters = [Filter("type", "=", "x-mitre-collection")]
                collections_data = collection_source.query(filters)
                if collections_data:
                    version = collections_data[0].get("x_mitre_version", "Unknown")
                    return version

        # Fallback to web scraping if STIX method fails
        version_history = requests.get("https://attack.mitre.org/resources/versions/", timeout=10)
        latest_version = re.findall(
            r"<span><strong>([^<]+)",
            str(version_history.content)
            .split("<h5><strong>Current Version</strong></h5>")[1]
            .split("<h5><strong>Most Recent Versions</strong></h5>")[0],
        )[0].split("ATT&amp;CK v")[1]
        return latest_version
    except Exception as e:
        print(f"\n\n\tWarning: Could not determine latest version: {e}")
        return "Unknown"


def load_attack_data(framework: str = "enterprise") -> MitreAttackData:
    """Load MITRE ATT&CK data using STIX via the mitreattack-python library."""
    print(f"    -> Loading {framework} ATT&CK data from STIX...")

    framework_map = {
        "enterprise": "enterprise-attack",
        "mobile": "mobile-attack",
        "ics": "ics-attack"
    }

    stix_source = framework_map.get(framework.lower(), "enterprise-attack")
    attack_data = MitreAttackData(stix_source)

    return attack_data


def process_technique_parallel(args: Tuple) -> List[Dict]:
    """Process a single technique in parallel."""
    technique, groups, platforms, attack_data = args
    results = []

    try:
        technique_id = technique.get("external_references", [{}])[0].get("external_id", "")
        technique_name = technique.get("name", "")
        technique_description = technique.get("description", "")

        # Get platforms
        tech_platforms = technique.get("x_mitre_platforms", [])

        # Check if platform matches
        if platforms != ["."] and not any(p in tech_platforms for p in platforms):
            return results

        # Get tactics
        kill_chain_phases = technique.get("kill_chain_phases", [])
        tactics = [phase.get("phase_name", "").replace("-", " ").title() for phase in kill_chain_phases]

        # Get data sources
        data_sources = []
        data_components = technique.get("x_mitre_data_sources", [])
        if isinstance(data_components, list):
            data_sources = data_components

        # Get detection info
        detection = technique.get("x_mitre_detection", "")

        result = {
            "id": technique_id,
            "name": technique_name,
            "description": technique_description,
            "platforms": tech_platforms,
            "tactics": tactics,
            "data_sources": data_sources,
            "detection": detection,
            "stix_id": technique.get("id", "")
        }
        results.append(result)

    except Exception as e:
        print(f"    Warning: Error processing technique: {e}")

    return results


def get_group_techniques_parallel(attack_data: MitreAttackData, groups: List[str],
                                   platforms: List[str], max_workers: int = 10) -> Tuple[Dict, Dict, List]:
    """Get techniques used by groups using parallel processing."""
    print(f"    -> Extracting techniques with {max_workers} parallel workers...")

    group_techniques = {}
    group_info = {}
    all_techniques = []

    # Get all groups
    all_groups = attack_data.get_groups(remove_revoked_deprecated=True)

    # Filter groups if specified
    if groups != ["."]:
        filtered_groups = []
        for group in all_groups:
            group_name = group.get("name", "")
            group_aliases = group.get("aliases", [])
            # Check if group matches any provided group names
            if any(g.replace("_", " ").lower() in [group_name.lower()] + [a.lower() for a in group_aliases]
                   for g in groups):
                filtered_groups.append(group)
        all_groups = filtered_groups

    # Process each group
    for group in all_groups:
        try:
            group_name = group.get("name", "")
            group_id = group.get("external_references", [{}])[0].get("external_id", "")
            group_description = group.get("description", "")

            group_info[group_id] = {
                "name": group_name,
                "description": group_description,
                "aliases": group.get("aliases", [])
            }

            # Get techniques used by this group
            techniques = attack_data.get_techniques_used_by_group(group.get("id"))

            group_techniques[group_id] = []

            # Process techniques in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for technique in techniques:
                    futures.append(executor.submit(process_technique_parallel,
                                                  (technique, groups, platforms, attack_data)))

                for future in as_completed(futures):
                    try:
                        results = future.result()
                        for result in results:
                            group_techniques[group_id].append(result)
                            all_techniques.append(result)
                    except Exception as e:
                        print(f"    Warning: Thread error: {e}")

        except Exception as e:
            print(f"    Warning: Error processing group {group.get('name', 'Unknown')}: {e}")
            continue

    return group_techniques, group_info, all_techniques


def replace_commas_in_group_desc(csv_line):
    return re.sub(
        r"^((?:[^,]+,){6}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4}[^\[]+[^\(]+\([^\)]+\)[^,]+), ",
        r"\1%2C ",
        csv_line,
    )


def mainsaw(
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
    columns=None,
    preset=False,
):

    # checking latest version and loading STIX data
    try:
        print("    -> Checking for latest ATT&CK version...")
        latest_version = get_latest_attack_version()

        if latest_version != "Unknown" and latest_version != attack_version:
            print(
                "\n\n\tNote: ATT&CK version in \033[1;36mMITRESaw.py\033[1;m (\033[1;31m{}\033[1;m) differs from \n\tlatest published version (\033[1;31m{}\033[1;m). \n\tUsing latest STIX data from TAXII server...\n".format(
                    attack_version, latest_version
                )
            )
            attack_version = latest_version

        # Load STIX data
        attack_data = load_attack_data(attack_framework)

    except requests.exceptions.ConnectionError:
        print("\n\n\tUnable to connect to the Internet. Please try again.\n\n\n")
        sys.exit()
    except Exception as e:
        print(f"\n\n\tError loading ATT&CK data: {e}\n\n\n")
        sys.exit()

    # Setup output directories
    mitresaw_root_date = os.path.join(".", str(datetime.now())[0:10])
    if not os.path.exists(mitresaw_root_date):
        os.makedirs(mitresaw_root_date)
    mitre_files = os.path.join(
        mitresaw_root_date, "{}-{}-stix".format(attack_framework.lower(), attack_version)
    )
    if not os.path.exists(mitre_files):
        os.makedirs(mitre_files)

    # Cache STIX data locally for faster subsequent runs
    stix_cache_file = os.path.join(mitre_files, "attack_data_cache.json")
    print(f"    -> Using STIX data from TAXII server (cached locally)...")

    time.sleep(0.1)
    saw = """
@                                                         ,
@                 ╓╗╗,                          ,╓▄▄▄Φ▓▓██▌╫D
@                ║▌ `▓L            ,,, ╓▄▄▄Φ▓▓▀▀▀╫╫╫╫╫╫╫▀▀╫▓▓▄
@                 ▓▄▓▓▓        ,▄▄B░▀╫Ñ╬░░╫╫▓▓▓▓╫╫╫╫▓▓▓╫╫╫╫╣▓▓▓▄
@                 ║████L   ,╓#▀▀▀╨╫ÑÑ╦▄▒▀╣▓▄▄▀╣▌╫▀    ██╫╫╫╫▓▓╫▓▓φ
@                  ▓╫╫╫▀]Ñ░░░░ÑÑÑÑ░░░░░╠▀W▄╠▀▓▒░╫Ñ╖   ╙└"╜▀▓▓▓▓▓█▓▓
@                  ║░░░╦╬╫╫╫╫╫╫╫╫╫╫╫╫╫ÑÑ░░░╠Ñ░╨╫Ñ░╫╫╫╫N     ▀▓▓▓╫██▓╕
@                ,]░╦╬╫╫╫╫╫╫╫▓▓▓▓▓▓╫╫╫╫╫╫╫Ñ░░╠░░╫M░╠╫╫╫╫╦,    ▀▓▓▓▓▓▓⌐
@       ╗▄╦     ]░░╬╫╫╫╫╫▓▓██████████▓▓▒╫╫╫╫Ñ░░╟▒╟▓▒ñ▓▓▓▓░N    ╙▓▓▓▓▓▓
@   ║███╫█╫    ]░░╫╫╫╫╫▓███▓▓▓▓▓▓▓▓▓▓███▓╫╫╫╫╫░░╟▒╟▓Ü╟▓▓▓▓░H    ╟▓▓▓▓▓L
@   ║███╫█╫   ]░░╫╫╫╫▓██▓╫▓▓▓▀▀╠╠╬▀▓▓▓╫▓██▓╫╫╫╫░░ÑÑ╠▄░╠▓▓▓▄▄▄▄▄▓▓▓╫╫╫╫
@    ╓▄▄╫█╫╖╖╖╦░╫╫╫╫╫██▓▓▓▓▀░╬Ñ╣╬╫Ñ░╟▓▓▓▓██╫╫╫╫Ñ░╦]░░░║████▀▀╫╫╫▓╩╨╟╫
@    ╟▓▓╫█╫▀▀▀╩╬╩╫╫▓██▓▓▓▓▌░╫░╟▓▓K╫Ñ░▓▓▓▓╫██▓▒╩╩╩╩ ╙╩╨▀▓M╨╩╨╙╝╣N╦╗Φ╝
@       ╫█╫     ▀███▀╣▓▓▓▓▓░╫Ñ░╠▀░╫Ü░▓▓▓▓▓▀▀███╕      ▐▓▌╖
@   ▄▄▄▄▓█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄╛
@                ▀╩╫╫╫╠╣▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀░╫╫╫╫▌
@                 ╗▄╫╫Ñ░╠▀▓▓▓▓▓▓▓▓▓▓▓▓▀░╦╬╫╫∩
@                   `⌠╫╫╫Ñ░░Å╣▀▀▀▀▀▒░╦╬╫╫╫`█
@                    ╙╙""╫╫╫½╫╫╫╬╫╫╫╫╫M"▓╛
@                       └╙└ ▄▓╩`║▓╩ Å▀\n\n
    """
    titles = [
        """
       ███▄ ▄███▓ ██▓▄▄▄█████▓ ██▀███  ▓█████   ██████  ▄▄▄       █     █░
      ▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▒████▄    ▓█░ █ ░█░
      ▓██    ▓██░▒██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒██  ▀█▄  ▒█░ █ ░█ 
      ▒██    ▒██ ░██░░ ▓██▓ ░ ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░██▄▄▄▄██ ░█░ █ ░█ 
      ▒██▒   ░██▒░██░  ▒██▒ ░ ░██▓ ▒██▒░▒████▒▒██████▒▒ ▓█   ▓██▒░░██▒██▓ 
      ░ ▒░   ░  ░░▓    ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░ ▓░▒ ▒  
      ░  ░      ░ ▒ ░    ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░  ▒   ▒▒ ░  ▒ ░ ░  
      ░      ░    ▒ ░  ░        ░░   ░    ░   ░  ░  ░    ░   ▒     ░   ░  
             ░    ░              ░        ░  ░      ░        ░  ░    ░    
""",
        """
      ______  ___________________________ __________________                   
      ___   |/  /____  _/___  __/___  __ \\___  ____/__  ___/______ ____      __
      __  /|_/ /  __  /  __  /   __  /_/ /__  __/   _____ \\ _  __ `/__ | /| / /
      _  /  / /  __/ /   _  /    _  _, _/ _  /___   ____/ / / /_/ / __ |/ |/ / 
      /_/  /_/   /___/   /_/     /_/ |_|  /_____/   /____/  \\__,_/  ____/|__/  
""",
        """
                   ______      ______    ____        ____       ____                              
       /'\\_/`\\    /\\__  _\\    /\\__  _\\  /\\  _`\\     /\\  _`\\    /\\  _`\\                            
      /\\      \\   \\/_/\\ \\/    \\/_/\\ \\/  \\ \\ \\L\\ \\   \\ \\ \\L\\_\\  \\ \\,\\L\\_\\      __      __  __  __  
      \\ \\ \\__\\ \\     \\ \\ \\       \\ \\ \\   \\ \\ ,  /    \\ \\  _\\L   \\/_\\__ \\    /'__`\\   /\\ \\/\\ \\/\\ \\ 
       \\ \\ \\_/\\ \\     \\_\\ \\__     \\ \\ \\   \\ \\ \\\\ \\    \\ \\ \\L\\ \\   /\\ \\L\\ \\ /\\ \\L\\.\\_ \\ \\ \\_/ \\_/ \\
        \\ \\_\\\\ \\_\\    /\\_____\\     \\ \\_\\   \\ \\_\\ \\_\\   \\ \\____/   \\ `\\____\\\\ \\__/.\\_\\ \\ \\___x___/'
         \\/_/ \\/_/    \\/_____/      \\/_/    \\/_/\\/ /    \\/___/     \\/_____/ \\/__/\\/_/  \\/__//__/  
""",
        """
         _____   .___ _____________________ ___________  _________                 
        /     \\  |   |\\__    ___/\\______   \\\\_   _____/ /   _____/_____   __  _  __
       /  \\ /  \\ |   |  |    |    |       _/ |    __)_  \\_____  \\ \\__  \\  \\ \\/ \\/ /
      /    Y    \\|   |  |    |    |    |   \\ |        \\ /        \\ / __ \\_ \\     / 
      \\____|__  /|___|  |____|    |____|_  //_______  //_______  /(____  /  \\/\\_/  
              \\/                         \\/         \\/         \\/      \\/          
""",
        """
        ___ ___   ___   _______   _______   _______   _______                    
       |   Y   | |   | |       | |   _   \\ |   _   | |   _   | .---.-. .--.--.--.
       |.      | |.  | |.|   | | |.  l   / |.  1___| |   1___| |  _  | |  |  |  |
       |. \\_/  | |.  | `-|.  |-' |.  _   1 |.  __)_  |____   | |___._| |________|
       |:  |   | |:  |   |:  |   |:  |   | |:  1   | |:  1   |                   
       |::.|:. | |::.|   |::.|   |::.|:. | |::.. . | |::.. . |                   
       `--- ---' `---'   `---'   `--- ---' `-------' `-------'                   
""",
    ]
    chosen_title = random.choice(titles)
    tagline = "{}        *ATT&CK for {} v{}\n".format(
        chosen_title, attack_framework.title(), attack_version
    )
    time.sleep(1)
    subprocess.Popen(["clear"]).communicate()
    if not art:
        if saw:
            print_saw(saw, tagline, "                                        ")
            print_saw(saw, tagline, "                                      ")
            print_saw(saw, tagline, "                                    ")
            print_saw(saw, tagline, "                                  ")
            print_saw(saw, tagline, "                                ")
            print_saw(saw, tagline, "                              ")
            print_saw(saw, tagline, "                            ")
    platforms = str(operating_platforms)[2:-2].split(",")
    platforms = list(filter(None, platforms))
    if not art:
        print_saw(saw, tagline, "                          ")
    terms = str(search_terms)[2:-2].split(",")
    terms = list(filter(None, terms))
    if not art:
        print_saw(saw, tagline, "                        ")
    groups = str(provided_groups)[2:-2].split(",")
    groups = list(filter(None, groups))
    if not art:
        print_saw(saw, tagline, "                      ")
    else:
        print(tagline)
    if True:  # creating MITRESaw output file names
        if str(platforms) == "['.']":
            platforms_filename_insert = ""
        else:
            platforms_filename_insert = "{}".format(
                str(platforms)[2:-2].replace("', '", "-")
            )
        if str(terms) == "['.']":
            terms_filename_insert = ""
        else:
            terms_filename_insert = "{}".format(str(terms)[2:-2].replace("', '", "-"))
        if str(groups) == "['.']":
            groups_filename_insert = ""
            groups_insert = "Threat Actors"
            all_insert = "all "
        else:
            groups_filename_insert = "{}".format(str(groups)[2:-2].replace("', '", "-"))
            groups_insert = "{}".format(str(groups)[2:-2])
            all_insert = ""
        mitresaw_output_directory = os.path.join(
            mitresaw_root_date,
            "{}_{}_{}".format(
                platforms_filename_insert.replace("_", ""),
                terms_filename_insert.replace("_", ""),
                groups_filename_insert.replace("_", ""),
            ),
        )
        if not os.path.exists(os.path.join(mitresaw_output_directory)):
            os.makedirs(os.path.join(mitresaw_output_directory))
    (
        additional_terms,
        evidence_found,
        valid_procedures,
        all_evidence,
        log_sources,
        logsources,
        groups_in_scope,
        techniques_in_scope,
        groups_techniques_in_scope,
    ) = ([] for _ in range(9))
    (
        group_procedures,
        group_descriptions,
        contextual_information,
        previous_findings,
    ) = ({} for _ in range(4))
    if not art:
        if saw:
            print_saw(saw, tagline, "                    ")
            print_saw(saw, tagline, "                  ")
            print_saw(saw, tagline, "                ")
            print_saw(saw, tagline, "              ")
            print_saw(saw, tagline, "            ")
            print_saw(saw, tagline, "          ")
            print_saw(saw, tagline, "        ")
            print_saw(saw, tagline, "      ")
            print_saw(saw, tagline, "    ")
            print_saw(saw, tagline, "  ")
            print_saw(saw, tagline, "partial")
            print_saw(saw, tagline, "-")  # remove saw
            print()
    if str(terms) != "['.']":
        terms_insert = " associated with '\033[1;36m{}\033[1;m'".format(
            str(terms)[2:-2].replace("_", " ").replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = ""
    # Use STIX-based parallel processing instead of CSV files
    print()
    print(
        "    -> Extracting \033[1;31mIdentifiers\033[1;m from \033[1;32mTechniques\033[1;m using STIX data based on {}\033[1;33m{}\033[1;m{}".format(
            all_insert,
            groups_insert.replace("', '", "\033[1;m, \033[1;33m"),
            terms_insert,
        )
    )

    # Get group techniques using parallel processing
    group_techniques_data, group_info_data, all_techniques_data = get_group_techniques_parallel(
        attack_data, groups, platforms, max_workers=10
    )

    # Process the STIX data into the format expected by the rest of the tool
    contextual_information = []
    for group_id, techniques in group_techniques_data.items():
        group_name = group_info_data[group_id]["name"]
        group_description = group_info_data[group_id]["description"]

        for technique in techniques:
            technique_id = technique["id"]
            technique_name = technique["name"]
            technique_description = technique["description"]
            technique_platforms = ", ".join(technique["platforms"])
            technique_tactics = ", ".join(technique["tactics"])
            technique_detection = technique["detection"]
            technique_data_sources = ", ".join(technique["data_sources"]) if technique["data_sources"] else ""

            # Build context string in the format expected by the rest of the tool
            context = f"{group_id}||{group_name}||-||{technique_id}"
            contextual_information.append(context)

            # obtaining navigation layers for all identified threat groups
            if navigationlayers:
                navlayer_output_directory = os.path.join(
                    mitresaw_root_date,
                    "{}_navigationlayers".format(str(datetime.now())[0:10]),
                )
                navlayer_json = os.path.join(
                    navlayer_output_directory,
                    "{}_{}-enterprise-layer.json".format(group_id, group_name),
                )
                if not os.path.exists(navlayer_json):
                    if not os.path.exists(navlayer_output_directory):
                        os.makedirs(navlayer_output_directory)
                        print(
                            "     -> Obtaining ATT&CK Navigator Layers for \033[1;33mThreat Actors\033[1;m related to identified \033[1;32mTechniques\033[1;m..."
                        )
                    try:
                        group_navlayer = requests.get(
                            f"https://attack.mitre.org/groups/{group_id}/{group_id}-enterprise-layer.json",
                            timeout=10
                        )
                        if group_navlayer.status_code == 200:
                            with open(navlayer_json, "wb") as navlayer_file:
                                navlayer_file.write(group_navlayer.content)
                    except Exception as e:
                        print(f"    Warning: Could not download nav layer for {group_name}: {e}")

            # Build valid procedure
            valid_procedure = f"{context}||{technique_description}||{technique_detection}||{technique_platforms}||{technique_data_sources}"
            valid_procedures.append(valid_procedure)

            # Track techniques
            techniques_in_scope.append(f"{technique_id}||{technique_name}")
            groups_techniques_in_scope.append(f"{group_name}||{technique_id}||{technique_name}||{technique_tactics}")
            groups_in_scope.append(group_name)
    print()
    consolidated_procedures = sorted(list(set(valid_procedures)))
    counted_techniques = Counter(techniques_in_scope)
    sorted_techniques = sorted(
        counted_techniques.items(), key=lambda x: x[1], reverse=True
    )
    sorted_threat_actors_techniques_in_scope = list(set(groups_techniques_in_scope))
    technique_combos = []
    for technique in counted_techniques.most_common():
        technique_count = technique[1]
        if ": " in technique[0]:
            parent_technique = technique[0].split(": ")[0]
            sub_technique = technique[0].split(": ")[1]
        else:
            parent_technique = technique[0]
            sub_technique = "-"
        technique_combo = [parent_technique, sub_technique, technique_count]
        technique_combos.append(technique_combo)
    for each_procedure in consolidated_procedures:
        (
            technique_findings,
            previous_findings,
        ) = extract_indicators(
            each_procedure,
            terms,
            evidence_found,
            "",
            previous_findings,
            truncate,
        )
        threat_actor_technique_id_name_findings = []

        # constructing sub-technique pairing due to format of sub-techniques in mitre output files e.g. T1566.001||Spearphishing Attachment
        for technique_found in technique_findings:
            threat_actor_found = technique_found.split("||")[1]
            technique_id_found = technique_found.split("||")[2]
            technique_name_found = technique_found.split("||")[3]
            if "." in technique_id_found:
                parent_technique_found = "{}||{}".format(
                    technique_id_found,
                    str(sorted_techniques)
                    .split("{}||".format(technique_id_found))[1]
                    .split("{}".format(technique_name_found))[0][0:-2],
                )
                technique_id_name_found = "{}: {}".format(
                    parent_technique_found, technique_name_found
                )
            else:
                technique_id_name_found = "{}||{}".format(
                    technique_id_found, technique_name_found
                )
            threat_actor_technique_id_name_found = "{}||{}".format(
                threat_actor_found, technique_id_name_found
            )
            threat_actor_technique_id_name_findings.append(
                threat_actor_technique_id_name_found
            )
    threat_actor_technique_id_name_findings = list(
        set(threat_actor_technique_id_name_findings)
    )
    all_evidence.append(technique_findings)
    consolidated_techniques = all_evidence[0]
    if len(consolidated_techniques) > 0:
        print("\n     Correlating results and creating intersecting matrix...")

        # outputting relevant queries
        query_pairings, mapped_log_sources = build_matrix(
            mitresaw_output_directory,
            consolidated_techniques,
            sorted_threat_actors_techniques_in_scope,
            threat_actor_technique_id_name_findings,
        )
        """if queries:
            print()
            print(
                "    -> Compiling queries based on \033[1;31midentifiers\033[1;m based on {}".format(
                    terms_insert
                )
            )"""
        write_csv_techniques_mapped_to_logsources(
            mitresaw_output_directory, mapped_log_sources
        )
        # outputting csv file for ingestion into other tools
        write_csv_summary(
            consolidated_techniques,
            mitresaw_output_directory,
            mitre_files,
            queries,
            query_pairings,
            log_sources,
        )
        # Generate filtered keywords CSV if --columns is specified
        if columns:
            valid_columns = [
                "group_software_id", "group_software_name", "technique_id",
                "item_identifier", "group_software", "relation_identifier",
                "created", "last_modified", "group_software_description",
                "technique_name", "technique_tactics", "technique_description",
                "technique_detection", "technique_platforms", "technique_datasources",
                "evidence_type", "evidence_indicators", "keywords",
            ]
            requested_columns = [c.strip() for c in columns.split(",")]
            invalid = [c for c in requested_columns if c not in valid_columns]
            if invalid:
                print(f"\n    Error: Invalid column(s): {', '.join(invalid)}")
                print(f"    Valid columns: {', '.join(valid_columns)}")
            else:
                csv_path = os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
                df = pandas.read_csv(csv_path, on_bad_lines="warn")

                if "keywords" in requested_columns:
                    keyword_map = {}
                    for gid, info in group_info_data.items():
                        keyword_map[gid] = match_keywords(info["description"])
                    df["keywords"] = df["group_software_id"].map(keyword_map).fillna("")

                df = df[requested_columns].drop_duplicates()
                if preset:
                    filtered_csv_name = "mitre_procedures.csv"
                else:
                    filtered_csv_name = "ThreatActors_Keywords.csv"
                keywords_csv_path = os.path.join(mitresaw_output_directory, filtered_csv_name)
                df.to_csv(keywords_csv_path, index=False)
                print(f"      Keywords CSV written to {keywords_csv_path}")

        mitresaw_techniques = re.findall(
            r"\|\|(T\d{3}[\d\.]+)\|\|", str(consolidated_techniques)
        )
        mitresaw_techniques = list(set(mitresaw_techniques))
        mitresaw_techniques_insert = str(mitresaw_techniques)[2:-2].replace(
            "', '",
            '", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}, {{"techniqueID": "',
        )
        print("      Done.")

        # enterprise-attack navigation layer only currently
        mitresaw_navlayer = '{{"description": "Enterprise techniques used by various Threat Actors, produced by MITRESaw", "name": "{}", "domain": "enterprise-attack", "versions": {{"layer": "4.4", "attack": "15", "navigator": "4.8.1"}}, "techniques": [{{"techniqueID": "{}", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}], "gradient": {{"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1}}, "legendItems": [{{"label": "identified from MITRESaw analysis", "color": "#66b1ff"}}]}}\n'.format(
            mitresaw_output_directory.split("/")[2][11:], mitresaw_techniques_insert
        )
        with open(
            os.path.join(mitresaw_output_directory, "enterprise-layer.json"), "w"
        ) as mitresaw_navlayer_json:
            mitresaw_navlayer_json.write(
                mitresaw_navlayer.replace("{{", "{").replace("}}", "}")
            )
        build_queries(queries, mitresaw_output_directory, query_pairings)
        log_sources = sorted(
            str(log_sources)[3:-3]
            .replace(", ", "; ")
            .replace("'; '", "; ")
            .replace('"; "', "; ")
            .replace("; ", ", ")
            .split(", ")
        )
        # removing specific event IDs as they are not needed for reporting stats in stdout
        for log_source in log_sources:
            if ": " in log_source:
                logsources.append(log_source.split(": ")[0])
            elif log_source.startswith("*nix /var/log/"):
                logsources.append(f"{log_source.split("/log/")[0]}/log")
            else:
                logsources.append(log_source)
        # counting the occurance of each log source
        counted_log_sources = Counter(list(filter(None, logsources)))
        log_coverage = list(
            filter(
                None,
                sorted(counted_log_sources.items(), key=lambda x: x[1], reverse=True),
            )
        )
        print(
            "\n     The following log sources are recommended to \033[4;37maid with detecting\033[1;m the aforementioned ATT&CK techniques:"
        )
        print()
        time.sleep(0.5)
        total = 0
        for log_count in log_coverage:
            log = log_count[0].split(": ")[0]
            count = log_count[1]
            percentage = str(int(count / len(log_sources) * 100))
            if percentage == "0" and show_others:
                percentage = "<1"
                print(
                    "       - {}: \033[1;37m{}%\033[1;m".format(
                        log.strip().strip('"'), percentage
                    )
                )
            elif percentage != "0":
                print(
                    "       - {}: \033[1;37m{}%\033[1;m".format(
                        log.strip().strip('"'), percentage
                    )
                )
                total += int(percentage)
        if not show_others:
            others = 100 - total
            print("       - Others: \033[1;37m{}%\033[1;m".format(others))
    else:
        print("\n    -> No evidence could be found which match the provided criteria.")
    print("\n\n")
