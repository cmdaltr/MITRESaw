#!/usr/bin/env python3 -tt
import json
import os
import pandas
from collections import Counter
from toolbox.tools.map_general_logs import generic_mapping
from toolbox.tools.map_bespoke_logs import bespoke_mapping

# Priority order for selecting the primary evidence type for log source mapping
_EVIDENCE_PRIORITY = ["cve", "evt", "reg", "cmd", "ports", "software", "filepath"]


def find_parent_sub_technique(technique, sorted_threat_actors_techniques_in_scope):
    if (
        "||{}||".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = technique
        sub_technique = "-"
    elif (
        "||{}: ".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = technique
        sub_technique = (
            str(sorted_threat_actors_techniques_in_scope)[2:-2]
            .split("{}: ".format(technique))[1]
            .split("', '")[0]
        )
    elif (
        ": {}||".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = (
            str(sorted_threat_actors_techniques_in_scope)[2:-2]
            .split(": {}".format(technique))[0]
            .split("||")[-1]
        )
        sub_technique = technique
    return parent_technique, sub_technique


def map_log_sources(detectable_threat_actor_technique):
    # Entry format (consolidated evidence):
    # [0]group_id  [1]group_name  [2]technique_id  [3]technique_name
    # [4]usage  [5]-  [6]group_desc  [7]tech_desc  [8]tech_detection
    # [9]tech_platforms  [10]tech_datasources  [11]tech_tactics
    # [12]evidence_dict (JSON)
    log_sources = []
    parts = detectable_threat_actor_technique.split("||")
    group = parts[0]
    technique_id = parts[2]
    technique_name = parts[3]
    technique_desc = parts[7]
    platform = parts[9]

    # Parse consolidated evidence dict
    evidence_dict = {}
    if len(parts) > 12:
        try:
            evidence_dict = json.loads(parts[12])
        except (json.JSONDecodeError, IndexError):
            evidence_dict = {}

    # Select primary evidence type for log source mapping
    primary_type = ""
    primary_evidence = ""
    for etype in _EVIDENCE_PRIORITY:
        if etype in evidence_dict and evidence_dict[etype]:
            primary_type = etype
            primary_evidence = str(evidence_dict[etype])
            break

    evidence_str = json.dumps(evidence_dict).replace(",", "%2C")

    # mapping to identifiable evidence according to https://attack.mitre.org/datasources/
    logsources = generic_mapping(
        technique_id,
        platform,
        parts[10] if len(parts) > 10 else "",
        primary_type,
    )
    for logsource in logsources[1:-1].split(", "):
        log_sources.append(logsource)
    # mapping to specific log sources available within Company X
    log_sources = bespoke_mapping(
        technique_id,
        platform,
        sorted(
            list(
                set(
                    str(list(set(log_sources)))[2:-2]
                    .replace("; ", "', '")
                    .split("', '")
                )
            )
        ),
        primary_type,
        primary_evidence
    )
    if not log_sources:
        return f"{group},{technique_id},{technique_name},{technique_desc.replace(',', '%2C')},{platform},-,{evidence_str}"
    if log_sources[0].startswith("CVE-") or "', 'CVE-" in str(log_sources):
        cves = ""
        for cve in log_sources:
            if not cve.startswith("CVE-"):
                continue
            parts_cve = cve.split(",")
            if len(parts_cve) >= 4:
                cves = f"{cves}{group},{technique_id},{technique_name},{technique_desc.replace(',', '%2C')},{platform},{parts_cve[1]} ({parts_cve[2]}),{parts_cve[0]},{parts_cve[3]}\n"
        return cves
    else:
        return f"{group},{technique_id},{technique_name},{technique_desc.replace(',', '%2C')},{platform},{str(log_sources)[2:-2].replace(chr(39) + ', ' + chr(39), '; ')},{evidence_str}"


def build_matrix(
    mitresaw_output_directory,
    consolidated_techniques,
    sorted_threat_actors_techniques_in_scope,
    threat_actor_technique_id_name_findings,
):
    (
        threat_actors_xaxis,
        techniques_yaxis,
        threat_actor_techniques,
        markers,
        rows_techniques,
        query_pairings,
        threat_actors_count,
        techniques_count,
        parent_sub_techniques_yaxis,
        parent_sub_counts,
    ) = ([] for _ in range(10))
    with open(
        os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv"), "w"
    ) as mitresaw_csv:
        mitresaw_csv.write(
            "group_sw_id,group_sw_name,group_sw_description,technique_id,technique_name,technique_description,tactic,procedure_example,evidence,detectable_via\n"
        )
    mapped_log_sources = []

    # Pre-build lookup: (actor_name, technique_name) -> list of entries
    entries_by_actor_tech = {}
    for entry in consolidated_techniques:
        p = entry.split("||")
        key = (p[1], p[3])
        entries_by_actor_tech.setdefault(key, []).append(entry)

    # compile intersect
    for dataset in consolidated_techniques:
        threat_actors_xaxis.append(dataset.split("||")[1])
        techniques_yaxis.append(dataset.split("||")[3])
        threat_actor_techniques.append(
            "{}||{}".format(dataset.split("||")[1], dataset.split("||")[3])
        )
    threat_actors = Counter(threat_actors_xaxis)
    threat_actors = sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)
    for threat_actors_pair in threat_actors:
        threat_actors_count.append(list(threat_actors_pair))
    uniq_threat_actors_xaxis = sorted(list(set(threat_actors_xaxis)))
    uniq_techniques_yaxis = sorted(list(set(techniques_yaxis)))
    # uniq_threat_actor_techniques = sorted(list(set(threat_actor_techniques)))
    for each_technique in techniques_yaxis:
        parent_technique, sub_technique = find_parent_sub_technique(
            each_technique, sorted_threat_actors_techniques_in_scope
        )
        parent_sub_techniques_yaxis.append(
            "{}||{}".format(parent_technique, sub_technique)
        )
    techniques_count = Counter(parent_sub_techniques_yaxis)
    techniques_count = sorted(
        techniques_count.items(), key=lambda x: x[1], reverse=True
    )

    # collect potential sub-technique and tactics
    for uniq_technique in uniq_techniques_yaxis:
        parent_technique, sub_technique = find_parent_sub_technique(
            uniq_technique, sorted_threat_actors_techniques_in_scope
        )
        technique_tactics = (
            str(sorted_threat_actors_techniques_in_scope)
            .split("{}||".format(uniq_technique))[1]
            .split("', '")[0]
        )

        # need to identify criteria for what is detectable, non-detectable and out-of-scope
        for threat_actor in uniq_threat_actors_xaxis:
            matching = entries_by_actor_tech.get((threat_actor, uniq_technique), [])
            if matching:
                # Check if any entry has real evidence (non-empty dict)
                has_evidence = any(
                    e.split("||")[12] != "{}" for e in matching if len(e.split("||")) > 12
                )
                if has_evidence:
                    marker = "X"
                    for e in matching:
                        ep = e.split("||")
                        if len(ep) > 12 and ep[12] != "{}":
                            mapping = map_log_sources(e)
                            mapped_log_sources.append(mapping)
                            break
                else:
                    marker = "O"
            else:
                marker = "-"
            markers.append(marker)
            if len(markers) == len(uniq_threat_actors_xaxis):
                formatted_technique_row = []
                row_technique = [
                    technique_tactics.replace(",", ";"),
                    parent_technique,
                    sub_technique,
                    str(markers)[2:-2],
                    "{}".format(str(markers)[2:-2].count("X")),
                    "{}".format(str(markers)[2:-2].count("O")),
                    str(len(markers)),
                ]

                # readjusting the count from int->str->int
                if str(row_technique[-2]) != "0" and str(row_technique[-3]) != "0":
                    row_technique = (
                        str(row_technique).replace('"', "'")[2:-2].split("', '")
                    )
                    for element in row_technique[0:-3]:
                        formatted_technique_row.append(element)
                    formatted_technique_row.append(int(row_technique[-3]))
                    formatted_technique_row.append(int(row_technique[-2]))
                    formatted_technique_row.append(int(row_technique[-1]))
                    rows_techniques.append(formatted_technique_row)
        markers.clear()

    # output intersect
    for technique_count in techniques_count:
        parent_sub_count = [
            str(technique_count)[2:-1].split("||")[0],
            str(technique_count)[2:-1].split("||")[1].split("', ")[0],
            int(str(technique_count)[2:-1].split("||")[1].split("', ")[1]),
        ]
        parent_sub_counts.append(list(parent_sub_count))
    column_threat_actors_count = ["Threat Actor", "Count"]
    threat_actor_count_data_frame = pandas.DataFrame(
        threat_actors_count, columns=column_threat_actors_count
    )
    column_techniques_count = ["Technique", "Sub-technique", "Count"]
    techniques_subtechniques_count_data_frame = pandas.DataFrame(
        parent_sub_counts, columns=column_techniques_count
    )
    column_threat_actors = (  # sort count columns by Total, Identifable, Uidentifiable
        ["Tactic", "Parent Technique", "Sub-technique"]
        + uniq_threat_actors_xaxis
        + ["Identifiable"]
        + ["Unidentifiable"]
        + ["Total"]
    )
    intersect_data_frame = pandas.DataFrame(
        rows_techniques, columns=column_threat_actors
    )
    sorted_intersect_data_frame = intersect_data_frame.sort_values(
        [
            "Total",
            "Identifiable",
            "Unidentifiable",
            "Parent Technique",
            "Sub-technique",
        ],
        ascending=[False, False, False, True, True],
    )
    with pandas.ExcelWriter(
        os.path.join(
            mitresaw_output_directory, "ThreatActors_Techniques_Intersect.xlsx"
        )
    ) as intersect_writer:
        threat_actor_count_data_frame.to_excel(
            intersect_writer, sheet_name="ThreatActorCount"
        )
        techniques_subtechniques_count_data_frame.to_excel(
            intersect_writer, sheet_name="TechniqueCount"
        )
        sorted_intersect_data_frame.to_excel(
            intersect_writer, sheet_name="DetectableMatrix"
        )
    return query_pairings, mapped_log_sources
