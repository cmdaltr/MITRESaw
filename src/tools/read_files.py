#!/usr/bin/env python3 -tt
import os
import re
import sys


def collect_files(
    mitresaw_mitre_files,
    groups,
    group_procedures,
    group_descriptions,
    terms,
    additional_terms,
):
    all_groups_procedures = {}

    # cleaning up procedure_examples
    os.rename(
        os.path.join(
            mitresaw_mitre_files,
            "techniques-procedure_examples.csv",
        ),
        os.path.join(
            mitresaw_mitre_files,
            ".techniques-procedure_examples.csv",
        ),
    )
    with open(
        os.path.join(
            mitresaw_mitre_files,
            "techniques-procedure_examples.csv",
        ),
        "a",
    ) as procedure_examples_csv:
        with open(
            os.path.join(
                mitresaw_mitre_files,
                ".techniques-procedure_examples.csv",
            )
        ) as hidden_examples_csv:
            csvfilepath_content = re.sub(
                r"\\?\\n(?:\"|\\'), (?:\"|\\')((?:C|G|S)\d{4},)",
                r"§§§§\1",
                str(hidden_examples_csv.readlines())[2:-5],
            )
            for eachline in csvfilepath_content.split("§§§§"):
                procedure_examples_csv.write(
                    "{}\n".format(
                        eachline.replace("\\\\n\\', \\'", "")
                        .replace("\\\\£\\\\t£", "\\t")
                        .replace("£\\\\t£", "")
                    )
                )
    os.remove(
        os.path.join(
            mitresaw_mitre_files,
            ".techniques-procedure_examples.csv",
        )
    )

    # obtaining group procedure
    for groupsfile in os.listdir(mitresaw_mitre_files):
        if groupsfile.endswith("groups-techniques_used.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, groupsfile)),
                encoding="utf-8",
            ) as groups_procedure_csv:
                for groups_procedure in groups_procedure_csv:
                    groups_procedure = re.sub(
                        r"\\n[\"'], [\"'](G\d{4},)",
                        r"\\n',<##>'\1",
                        groups_procedure,
                    )
                    for group_procedure_csv_row in groups_procedure.split("\\n',<##>'"):
                        row_elements = re.findall(
                            r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                            group_procedure_csv_row.strip(),
                        )
                        if len(row_elements) > 0:
                            if row_elements[0][0] != "source ID":
                                group_id = row_elements[0][0]
                                group_name = row_elements[0][1]
                                technique_id = row_elements[0][2]
                                technique_name = row_elements[0][3]
                                procedure_description = row_elements[0][4]
                                all_groups_procedures[
                                    "{}||{}||{}||{}||{}".format(
                                        group_id,
                                        group_name,
                                        technique_id,
                                        technique_name,
                                        procedure_description,
                                    )
                                ] = "-"
                        if str(groups) == "['.']":
                            group_procedures = all_groups_procedures
                        else:
                            for group in groups:
                                if f"{group.replace(
                                    "_", " "
                                ).lower()}," in group_procedure_csv_row.lower() and group_procedure_csv_row.startswith(
                                    "G"
                                ):
                                    row_elements = re.findall(
                                        r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                                        group_procedure_csv_row.strip(),
                                    )
                                    if len(row_elements) > 0:
                                        if row_elements[0][0] != "source ID":
                                            group_id = row_elements[0][0]
                                            group_name = row_elements[0][1]
                                            technique_id = row_elements[0][2]
                                            technique_name = row_elements[0][3]
                                            procedure_description = row_elements[0][4]
                                            group_procedures[
                                                "{}||{}||{}||{}||{}".format(
                                                    group_id,
                                                    group_name,
                                                    technique_id,
                                                    technique_name,
                                                    procedure_description,
                                                )
                                            ] = "-"
                                        all_groups_procedures[
                                            "{}||{}||{}||{}||{}".format(
                                                group_id,
                                                group_name,
                                                technique_id,
                                                technique_name,
                                                procedure_description,
                                            )
                                        ] = "-"

    # obtaining group description
    for groupsfile in os.listdir(mitresaw_mitre_files):
        if groupsfile.endswith("groups-groups.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, groupsfile)),
                encoding="utf-8",
            ) as groupscsv:
                for group_rows in groupscsv:
                    group_rows = re.sub(
                        r"\\n[\"'], [\"'](G\d{4},)",
                        r"\\n',<##>'\1",
                        group_rows,
                    )
                    for group_row in group_rows.split("\\n',<##>'")[1:]:
                        group_description_row = re.findall(
                            r"^([^,]+),([^,]+),([^,]+),([^\n]+),https:\/\/attack\.mitre\.org\/groups\/\1,\d{1,2} ",
                            group_row,
                        )
                        if len(group_description_row) > 0:
                            group_id = group_description_row[0][0]
                            group_name = group_description_row[0][2]
                            group_description = group_description_row[0][3]
                            group_id_name = (
                                "[{}](https://attack.mitre.org/groups/{})".format(
                                    group_name, group_id
                                )
                            )
                            if str(terms) == "['.']":
                                for group_procedure in group_procedures.keys():
                                    if (
                                        group_procedure.split("||")[0] == group_id
                                        and group_procedure.split("||")[1] == group_name
                                        and group_id_name in str(group_procedure)
                                    ):
                                        group_descriptions[
                                            "{}||{}||{}{}".format(
                                                group_procedure,
                                                group_description,
                                                ".",
                                                additional_terms,
                                            )
                                        ] = "-"
                                additional_terms.clear()
                            else:
                                for term in terms:
                                    if (
                                        term.lower().replace("_", " ")
                                        in group_description.lower()
                                    ):
                                        for additional_term in terms:
                                            if (
                                                additional_term.lower()
                                                in group_description.lower()
                                            ):
                                                additional_terms.append(additional_term)
                                        for group_procedure in group_procedures.keys():
                                            if (
                                                group_procedure.split("||")[0]
                                                == group_id
                                                and group_procedure.split("||")[1]
                                                == group_name
                                                and group_id_name
                                                in str(group_procedure)
                                            ):
                                                group_descriptions[
                                                    "{}||{}||{}{}".format(
                                                        group_procedure,
                                                        group_description,
                                                        term,
                                                        additional_terms,
                                                    )
                                                ] = "-"
                                        additional_terms.clear()
    if len(group_descriptions) == 0:
        print()
        print(
            "\n    No \033[1;33mgroups\033[1;m could be found with the keywords provided. Perhaps try again with less restrictive \033[1;36msearch terms\033[1;m.\n\n\n"
        )
        sys.exit()
    return group_descriptions, group_procedures
