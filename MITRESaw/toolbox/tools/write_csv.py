import json
import re
import os
from MITRESaw.toolbox.tools.map_general_logs import generic_mapping
from MITRESaw.toolbox.tools.map_bespoke_logs import bespoke_mapping

# Priority order for selecting the primary evidence type for log source mapping
_EVIDENCE_PRIORITY = ["cve", "evt", "reg", "cmd", "ports", "software", "filepath"]


def write_csv_techniques_mapped_to_logsources(
    mitresaw_output_directory,
    mapped_log_sources,
):
    with open(
        os.path.join(
            mitresaw_output_directory, "ThreatActors_Techniques_LogSourceDetections.csv"
        ),
        "w",
    ) as mapped_logsources:
        mapped_logsources.write(
            "group_name,technique_id,technique_name,technique_description,technique_platforms,technique_datasources,evidence_indicators,cve_description\n"
        )
    with open(
        os.path.join(
            mitresaw_output_directory, "ThreatActors_Techniques_LogSourceDetections.csv"
        ),
        "a",
    ) as mapped_logsources:
        for mapping in mapped_log_sources:
            mapped_entry = re.sub(
                r"\(Citation: [^\)]+\)",
                r"",
                mapping.replace("..  ", ". ")
                .replace("\\\\\\\\\\\\\\'", "'")
                .replace("\\\\\\\\\\\\'", "'")
                .replace("\\\\\\\\\\'", "'")
                .replace("\\\\\\\\'", "'")
                .replace("\\\\\\'", "'")
                .replace("\n\n", "\n"),
            )
            mapped_logsources.write(f"{mapped_entry}\n")


def _clean_field(text):
    """Strip MITRE citation markers and normalise whitespace."""
    text = re.sub(r"\(Citation: [^\)]+\)", "", text)
    return text.replace("..  ", ". ").replace("\n\n", "\n").strip()


def write_csv_summary(
    consolidated_techniques,
    mitresaw_output_directory,
    mitre_files,
    queries,
    query_pairings,
    log_sources,
):
    # Entry format (after extract_indicators appends consolidated evidence):
    # [0]group_id  [1]group_name  [2]technique_id  [3]technique_name
    # [4]usage  [5]-  [6]group_desc  [7]tech_desc  [8]tech_detection
    # [9]tech_platforms  [10]tech_datasources  [11]tech_tactics
    # [12]evidence_dict (JSON)
    import csv

    csv_path = os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
    with open(csv_path, "a", newline="") as opmitre_csv:
        writer = csv.writer(opmitre_csv)
        for dataset in consolidated_techniques:
            parts = dataset.split("||")
            technique_platforms = parts[9] if len(parts) > 9 else ""
            evidence_json = parts[12] if len(parts) > 12 else "{}"
            # Extract primary evidence type for log source mapping
            try:
                evidence_dict = json.loads(evidence_json)
            except json.JSONDecodeError:
                evidence_dict = {}
            primary_type = next(
                (t for t in _EVIDENCE_PRIORITY if t in evidence_dict and evidence_dict[t]),
                "",
            )
            primary_evidence = str(evidence_dict.get(primary_type, "")) if primary_type else ""

            # Compute detectable_via: generic mapping -> bespoke mapping
            technique_datasources = parts[10] if len(parts) > 10 else ""
            generic_logsource = generic_mapping(
                parts[2],
                technique_platforms,
                technique_datasources,
                primary_type,
            )
            generic_list = []
            for ls in generic_logsource[1:-1].split(", "):
                if ls.strip():
                    generic_list.append(ls.strip())
            deduped = sorted(list(set(
                str(list(set(generic_list)))[2:-2]
                .replace("; ", "', '")
                .split("', '")
            )))
            full_logsources = bespoke_mapping(
                parts[2],
                technique_platforms,
                deduped,
                primary_type,
                primary_evidence,
            )
            detectable_via = str(full_logsources)

            writer.writerow([
                parts[0],                        # group_software_id
                parts[1],                        # group_software_name
                parts[2],                        # technique_id
                "-",                             # item_identifier
                "-",                             # group_software
                "-",                             # relation_identifier
                "-",                             # created
                "-",                             # last_modified
                _clean_field(parts[6]),           # group_software_description
                parts[3],                        # technique_name
                parts[11] if len(parts) > 11 else "",  # technique_tactics
                _clean_field(parts[7]),           # technique_description
                _clean_field(parts[8]),           # technique_detection
                technique_platforms,             # technique_platforms
                technique_datasources,           # technique_datasources
                evidence_json,                   # evidence_indicators (JSON dict)
                detectable_via,                  # detectable_via (log source array)
            ])
            if queries:
                all_indicators = []
                for indicators_list in evidence_dict.values():
                    all_indicators.extend(indicators_list)
                query_pairings.append(
                    "{}||{}||{}".format(
                        parts[2], parts[3],
                        str(all_indicators).replace("\\\\\\\\", "\\\\").lower(),
                    )
                )
            log_sources.append(generic_logsource.replace(", , ", ", "))
