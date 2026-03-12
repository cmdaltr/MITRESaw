#!/usr/bin/env python3 -tt
import re
import time


def make_evidence_insert(evidence_type, identifiers):
    if evidence_type == "ports":
        evidence_insert = " (port(s))"
        identifiers = re.findall(r"\d+", str(identifiers))
    elif evidence_type == "evt":
        evidence_insert = " (Windows event log ID(s))"
        identifiers = re.findall(r"\d+", str(identifiers))
    elif evidence_type == "software":
        evidence_insert = " (software)"
    elif evidence_type == "filepath":
        evidence_insert = " (file path(s))"
        identifiers = list(identifiers)
    else:
        evidence_insert = ""
    return evidence_insert


def make_terms_insert(terms, software_group_terms):
    if str(terms) != "['.']":
        extracted_terms = re.findall(r"\w+", str(software_group_terms))
        software_group_terms_insert = sorted(list(set(extracted_terms)))
        terms_insert = " -> '\033[1;36m{}\033[1;m' ->".format(
            str(software_group_terms_insert)[2:-2]
            .replace("_", " ")
            .replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = " ->"
    return terms_insert


def make_spacer(software_group_name):
    """if len(software_group_name) == 25:
        group_spacer = ""
    elif len(software_group_name) == 24:
        group_spacer = " "
    elif len(software_group_name) == 23:
        group_spacer = " "
    elif len(software_group_name) == 22:
        group_spacer = " "
    elif len(software_group_name) == 21:
        group_spacer = " "
    """
    if len(software_group_name) == 20:
        group_spacer = " "
    elif len(software_group_name) == 19:
        group_spacer = " "
    elif len(software_group_name) == 18:
        group_spacer = "  "
    elif len(software_group_name) == 17:
        group_spacer = "   "
    elif len(software_group_name) == 16:
        group_spacer = "    "
    elif len(software_group_name) == 15:
        group_spacer = "     "
    elif len(software_group_name) == 14:
        group_spacer = "      "
    elif len(software_group_name) == 13:
        group_spacer = "       "
    elif len(software_group_name) == 12:
        group_spacer = "        "
    elif len(software_group_name) == 11:
        group_spacer = "         "
    elif len(software_group_name) == 10:
        group_spacer = "          "
    elif len(software_group_name) == 9:
        group_spacer = "           "
    elif len(software_group_name) == 8:
        group_spacer = "            "
    elif len(software_group_name) == 7:
        group_spacer = "             "
    elif len(software_group_name) == 6:
        group_spacer = "              "
    elif len(software_group_name) == 5:
        group_spacer = "               "
    elif len(software_group_name) == 4:
        group_spacer = "                "
    elif len(software_group_name) == 3:
        group_spacer = "                 "
    return group_spacer


def extract_indicators(
    valid_procedure,
    terms,
    evidence_found,
    identifiers,
    previous_findings,
    truncate,
    quiet=False,
):

    def finding_to_stdout(
        technique_id,
        software_group_name,
        evidence_type,
        identifiers,
        software_group_terms,
        terms,
        truncate,
    ):
        evidence_insert = make_evidence_insert(evidence_type, identifiers)
        terms_insert = make_terms_insert(terms, software_group_terms)
        if "." in technique_id:
            spacer = " "
        else:
            spacer = "     "
        group_spacer = make_spacer(software_group_name)
        identifiers = (
            str(identifiers)[2:-2]
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\", "\\\\")
            .replace('"reg" add ', "reg add ")
        )
        if "', '" in identifiers:
            evidence_insert = evidence_insert.replace("(s)", "s")
        else:
            evidence_insert = evidence_insert.replace("(s)", "")
        print_statement = "  -> '\033[1;33m{}\033[1;m'{}{} '\033[1;32m{}\033[1;m'{}: '\033[1;31m{}\033[1;m'{}".format(
            software_group_name,
            group_spacer,
            terms_insert,
            technique_id,
            spacer,
            identifiers.replace("', '", "\033[1;m', '\033[1;31m"),
            evidence_insert,
        )
        if not quiet:
            if truncate:
                print(print_statement.split(": ")[0])
            else:
                print(print_statement)
            time.sleep(0.1)
        return identifiers.replace("', '", "++")

    def extract_port_indicators(description):
        description = re.sub(
            r"\(Citation[^\)]+\)",
            r"",
            re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
        )
        description = (
            description.replace('""', '"')
            .replace(". . ", ". ")
            .replace(".. ", ". ")
            .replace("\\\\\\'", "'")
            .replace("\\\\'", "'")
            .replace("\\'", "'")
            .strip(",")
            .strip('"')
            .strip(",")
            .strip('"')
        )
        port_identifiers = re.findall(
            r"(?:(?:[Pp]orts?(?: of)? |and |& |or |, |e\.g\.? |tcp: ?|udp: ?)|(?:\())(\d{2,})(?: |/|\. |,|\<)",
            description,
        )
        port_identifiers = list(
            filter(
                lambda port: "365" != port,
                list(filter(lambda port: "10" != port, port_identifiers)),
            )
        )  # remove string from list
        port_identifiers = sorted(list(set(port_identifiers)))
        return port_identifiers

    def extract_evt_indicators(description):
        description = re.sub(
            r"\(Citation[^\)]+\)",
            r"",
            re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
        )
        description = (
            description.replace('""', '"')
            .replace(". . ", ". ")
            .replace(".. ", ". ")
            .replace("\\\\\\'", "'")
            .replace("\\\\'", "'")
            .replace("\\'", "'")
            .replace("'), ('", "")
            .strip(",")
            .strip('"')
            .strip(",")
            .strip('"')
        )
        evt_identifiers = re.findall(
            r"(?:(?:Event ?|E)I[Dd]( ==)? ?\"?(\d{1,5}))", description
        )
        evt_identifiers = re.findall(
            r"'(\d+)'", str(sorted(list(set(evt_identifiers))))
        )
        return evt_identifiers

    def extract_reg_indicators(
        description,
    ):
        description = re.sub(
            r"\(Citation[^\)]+\)",
            r"",
            re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
        )
        description = (
            description.replace('""', '"')
            .replace(". . ", ". ")
            .replace(".. ", ". ")
            .replace("\\\\\\'", "'")
            .replace("\\\\'", "'")
            .replace("\\'", "'")
            .strip(",")
            .strip('"')
            .strip(",")
            .strip('"')
            .strip("'")
        )
        reg_identifiers = re.findall(
            r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}\|\"'!$<>`]+)",
            description.lower()
            .replace("hkey_local_machine", "hklm")
            .replace("hkey_current_user", "hkcu")
            .replace("[hklm]", "hklm")
            .replace("[hkcu]", "hkcu")
            .replace("hklm]", "hklm")
            .replace("hkcu]", "hkcu")
            .replace("“", '"')
            .replace("”", '"')
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\", "\\")
            .replace("£\\\\t£", "\\\\t")
            .replace('""', '"')
            .replace("  ", " ")
            .replace("[.]", ".")
            .replace("[:]", ":")
            .replace("&#42;", "*")
            .replace("&lbrace;", "{")
            .replace("&rbrace;", "}")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("[username]", "%username%")
            .replace("\\]\\", "]\\")
            .replace('""', '"')
            .replace('""', '"')
            .strip("\\")
            .strip(),
        )
        registry_identifiers = sorted(list(set(reg_identifiers)))
        return registry_identifiers

    def extract_cmd_indicators(description):
        terms_identifiers = re.findall(
            r"(?:(?:<code> ?([^\{\}!<>`]{3,}) ?<\/code>)|(?:` ?([^\{\}!<>`]{3,}) ?`)|(?:\[ ?([^\{\}!<>`]{3,}) ?\]\(https:\/\/attack\.mitre\.org\/software))",
            description,
        )
        cmd_identifiers = []
        all_identifiers = sorted(list(set(terms_identifiers)))
        for identifier_set in all_identifiers:
            for each_identifier in identifier_set:
                if (
                    len(each_identifier) > 0
                    and "](https://attack.mitre.org/" not in each_identifier
                    and "example" not in each_identifier.lower()
                    and "citation" not in each_identifier.lower()
                    and not each_identifier.startswith(")")
                    and not each_identifier.endswith("(")
                    and not each_identifier.lower().startswith("hklm\\")
                    and not each_identifier.lower().startswith("hkcu\\")
                    and not each_identifier.lower().startswith("hkey\\")
                    and not each_identifier.lower().startswith("[hklm")
                    and not each_identifier.lower().startswith("[hkcu")
                    and not each_identifier.lower().startswith("[hkey")
                    and not each_identifier == ", and "
                    and not each_identifier == "or"
                ):
                    identifier = (
                        each_identifier.lower()
                        .replace("“", '"')
                        .replace("”", '"')
                        .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                        .replace("\\\\\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\", "\\")
                        .replace("£\\\\t£", "\\\\t")
                        .replace('""', '"')
                        .replace("  ", " ")
                        .replace("[.]", ".")
                        .replace("[:]", ":")
                        .replace("&#42;", "*")
                        .replace("&lbrace;", "{")
                        .replace("&rbrace;", "}")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("[username]", "%username%")
                        .replace("\\]\\", "]\\")
                        .replace('""', '"')
                        .replace('""', '"')
                        .strip("\\")
                        .strip()
                    )
                    identifier = (
                        identifier.replace("\\\\\\\\\\'", "'")
                        .replace("\\\\\\\\'", "'")
                        .replace("\\\\\\'", "'")
                        .replace("\\\\'", "'")
                        .replace("\\'", "'")
                        .replace("'process", "process")
                        .replace("\"'", '"')
                    )
                    if len(identifier) > 1:
                        cmd_identifiers.append(identifier)
        # filtering out strings which match exactly
        strings_match = ["or"]
        cmd_identifiers = list(
            filter(
                lambda x: any("or" != x for string in strings_match),
                cmd_identifiers,
            )
        )
        # filtering out strings contained in identifier
        strings_in = ["where the"]
        cmd_identifiers = list(
            filter(
                lambda x: any(string not in x for string in strings_in),
                cmd_identifiers,
            )
        )
        cmd_identifiers = sorted(list(set(cmd_identifiers)))
        return cmd_identifiers

    def extract_cve_indicators(description):
        cve_identifiers = re.findall(
            r"(CVE\-\d+\-\d+)",
            description,
        )
        cve_identifiers = sorted(list(set(cve_identifiers)))
        return cve_identifiers

    def extract_software_indicators(description):
        software_identifiers = re.findall(
            r"\[([^\]]+)\]\(https:\/\/attack\.mitre\.org\/software/S",
            description,
        )
        software_identifiers = sorted(list(set(software_identifiers)))
        return software_identifiers

    def extract_filepath_indicators(description):
        description = re.sub(
            r"\(Citation[^\)]+\)",
            r"",
            re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
        )
        description = (
            description.replace('""', '"')
            .replace("\\\\\\'", "'")
            .replace("\\\\'", "'")
            .replace("\\'", "'")
            .replace("[.]", ".")
            .replace("[:]", ":")
            .strip(",")
            .strip('"')
        )
        filepath_identifiers = []
        # Windows paths: C:\..., %ENV%\...
        win_paths = re.findall(
            r"((?:[A-Za-z]:\\|%[A-Za-z_]+%\\)[^\s\"'<>|,\)]{3,})",
            description,
        )
        filepath_identifiers.extend(win_paths)
        # Unix paths: /etc/..., /tmp/..., /var/..., /usr/..., /opt/..., /home/...
        unix_paths = re.findall(
            r"((?:/etc|/tmp|/var|/usr|/opt|/home|/bin|/sbin|/dev|/proc|/sys)/[^\s\"'<>|,\)]{2,})",
            description,
        )
        filepath_identifiers.extend(unix_paths)
        # Notable file names with extensions (standalone or in paths)
        file_names = re.findall(
            r"(?:[\s\\/\"'`>]|^)([A-Za-z0-9_\-\.]{2,}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|scr|cpl|lnk|hta|msi|msp|jar|py|sh|pif|inf|reg))\b",
            description,
            re.IGNORECASE,
        )
        filepath_identifiers.extend(file_names)
        # Deduplicate and clean
        cleaned = []
        for fp in filepath_identifiers:
            fp = fp.strip().strip("`").rstrip(".").rstrip(",").rstrip(";").rstrip(")")
            # Skip URLs and examples
            if "www." in fp or "example" in fp.lower() or "http" in fp.lower():
                continue
            if len(fp) > 3 and fp not in cleaned:
                cleaned.append(fp)
        return sorted(list(set(cleaned)))

    def add_to_evidence(
        valid_procedure,
        previous_findings,
        evidence_found,
        technique_id,
        technique_name,
        software_group_name,
        evidence_type,
        identifiers,
        software_group_terms,
        terms,
        truncate,
    ):
        evidence = "{}||{}||{}".format(
            valid_procedure,
            evidence_type,
            str(identifiers),
        )
        evidence_found.append(evidence)
        if "{}||{}||{}||{}".format(
            technique_id, technique_name, software_group_name, evidence_type
        ) not in str(previous_findings):
            if len(identifiers) > 0:
                identifiers = finding_to_stdout(
                    technique_name,
                    software_group_name,
                    evidence_type,
                    identifiers,
                    software_group_terms,
                    terms,
                    truncate,
                )
                previous_findings[
                    "{}||{}||{}||{}".format(
                        technique_id, technique_name, software_group_name, evidence_type
                    )
                ] = "-"
        return evidence_found

    software_group_name = valid_procedure.split("||")[1]
    technique_id = valid_procedure.split("||")[2]
    technique_name = valid_procedure.split("||")[3]
    software_group_usage = valid_procedure.split("||")[4]
    software_group_terms = valid_procedure.split("||")[6]
    technique_description = valid_procedure.split("||")[7]
    technique_detection = valid_procedure.split("||")[8]
    description = "{}||{}||{}".format(
        software_group_usage, technique_description, technique_detection
    )

    # extracting ports
    port_identifiers = []
    if (
        technique_id != "T1070.006"
        and technique_id != "T1098"
        and technique_id != "T1529"
    ):
        port_identifiers = extract_port_indicators(description)
        if len(port_identifiers) > 0:
            evidence_found = add_to_evidence(
                valid_procedure,
                previous_findings,
                evidence_found,
                technique_id,
                technique_name,
                software_group_name,
                "ports",
                port_identifiers,
                software_group_terms,
                terms,
                truncate,
            )
        else:
            port_identifiers = []

    # extracting event IDs
    if "Event ID" in description or "EID" in description or "EventId" in description:
        evt_identifiers = extract_evt_indicators(description)
    else:
        evt_identifiers = []
    if len(evt_identifiers) > 0:
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "evt",
            evt_identifiers,
            software_group_terms,
            terms,
            truncate,
        )
    else:
        evt_identifiers = []

    # extracting registry artefacts
    if (
        "hklm\\" in description.lower()
        or "hkcu\\" in description.lower()
        or "hkey\\" in description.lower()
        or "hkey_" in description.lower()
        or "hklm]" in description.lower()
        or "hkcu]" in description.lower()
        or "hkey_local_machine]" in description.lower()
        or "hkey_current_user]" in description.lower()
    ):
        reg_identifiers = extract_reg_indicators(description)
    else:
        reg_identifiers = []
    if len(reg_identifiers) > 0:
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "reg",
            reg_identifiers,
            software_group_terms,
            terms,
            truncate,
        )
    else:
        reg_identifiers = []

    # extracting commands
    if "<code>" in description or "`" in description:
        cmd_identifiers = extract_cmd_indicators(description)
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "cmd",
            cmd_identifiers,
            software_group_terms,
            terms,
            truncate,
        )
    else:
        cmd_identifiers = []
    if "CVE" in description.upper():
        cve_identifiers = extract_cve_indicators(description)
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "cve",
            cve_identifiers,
            software_group_terms,
            terms,
            truncate,
        )
    else:
        cve_identifiers = []
    if "/software/" in description.lower():
        software_identifiers = extract_software_indicators(description)
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "software",
            software_identifiers,
            software_group_terms,
            terms,
            truncate,
        )
    else:
        software_identifiers = []

    # extracting file paths and file names
    filepath_identifiers = extract_filepath_indicators(description)
    if len(filepath_identifiers) > 0:
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "filepath",
            filepath_identifiers,
            software_group_terms,
            terms,
            truncate,
        )

    if (
        len(port_identifiers) == 0
        and len(evt_identifiers) == 0
        and len(reg_identifiers) == 0
        and len(cmd_identifiers) == 0
        and len(filepath_identifiers) == 0
    ):
        evidence_found = add_to_evidence(
            valid_procedure,
            previous_findings,
            evidence_found,
            technique_id,
            technique_name,
            software_group_name,
            "N/A",
            [],
            software_group_terms,
            terms,
            truncate,
        )
    return evidence_found, previous_findings
