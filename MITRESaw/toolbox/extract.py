#!/usr/bin/env python3 -tt
import json
import re
import time


def make_evidence_label(evidence_type):
    labels = {
        "ports": "🌐",
        "evt": "🪵",
        "software": "📦",
        "filepath": "📁",
        "cve": "🔒",
        "reg": "🔑",
        "cmd": "💻",
    }
    return labels.get(evidence_type, "")


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
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
        .replace("\\\\\\\\\\\\\\\\", "\\")
        .replace("\\\\\\\\\\\\", "\\")
        .replace("\\\\\\\\", "\\")
        .replace("\u00a3\\\\t\u00a3", "\\\\t")
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
                    .replace("\u201c", '"')
                    .replace("\u201d", '"')
                    .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                    .replace("\\\\\\\\\\\\\\\\", "\\")
                    .replace("\\\\\\\\\\\\", "\\")
                    .replace("\\\\\\\\", "\\")
                    .replace("\u00a3\\\\t\u00a3", "\\\\t")
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
                # Strip bracketed placeholders e.g. [session number to be stolen]
                identifier = re.sub(r"\s*\[[^\]]*(?:to be|number|name|address|path|file|user|password|target|host|domain|value)[^\]]*\]", "", identifier).strip()
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
    # filtering out prose fragments mistakenly captured between backticks
    prose_phrases = [
        "where the", "such as", "can be used", "can additionally",
        "information about", "information such", "the type of",
        "for example", "is used to", "are used to", "may use",
        "can also", "can list", "will be", "used by",
        "providers also", "cloud providers", "infrastructure as",
        "as well as",
    ]
    prose_starts = [
        "in ", "on ", "the ", "that ", "which ", "a ", "an ", "and ",
        "or ", "for ", "to ", "from ", "with ", "this ", "these ",
        "can ", "may ", "is ", "are ", "it ", "its ", "also ",
    ]
    cmd_identifiers = [
        x for x in cmd_identifiers
        if len(x) <= 150
        and not any(phrase in x for phrase in prose_phrases)
        and not any(x.startswith(prefix) for prefix in prose_starts)
    ]
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
        label = make_evidence_label(evidence_type)
        identifiers_str = (
            str(identifiers)[2:-2]
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\", "\\\\")
            .replace('"reg" add ', "reg add ")
            .replace("', '", ", ")
        )
        # Lowercase unless the technique specifies otherwise (e.g. CVE IDs)
        if evidence_type != "cve":
            identifiers_str = identifiers_str.lower()
        # Wrap each identifier in backticks
        identifiers_str = ", ".join(f"`{x.strip()}`" for x in identifiers_str.split(", "))
        if len(identifiers_str) > 60:
            truncated = identifiers_str[:60]
            if truncated.count("`") % 2 != 0:
                truncated += "`"
            identifiers_str = truncated + "..."
        col_group = f"\033[1;31m{software_group_name}\033[0m".ljust(25 + 11)
        col_technique = f"\033[1;32m{technique_id}\033[0m".ljust(45 + 11)
        col_indicators = f"\033[1;33m{identifiers_str}\033[0m".ljust(65 + 11)
        if not quiet:
            if truncate:
                print(f"   {col_group} | {col_technique}")
                print(f"   {'-' * 25} | {'-' * 45}")
            else:
                print(f"   {col_group} | {col_technique} | {label} {col_indicators}")
                print(f"   {'-' * 25} | {'-' * 45} | {'-' * 68}")
            time.sleep(0.1)

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

    # Build consolidated evidence dict: {type: [identifiers]}
    evidence_dict = {}

    # extracting ports
    if technique_id not in ("T1070.006", "T1098", "T1529"):
        port_identifiers = extract_port_indicators(description)
        if port_identifiers:
            evidence_dict["ports"] = port_identifiers

    # extracting event IDs
    if "Event ID" in description or "EID" in description or "EventId" in description:
        evt_identifiers = extract_evt_indicators(description)
        if evt_identifiers:
            evidence_dict["evt"] = evt_identifiers

    # extracting registry artefacts
    desc_lower = description.lower()
    if any(k in desc_lower for k in [
        "hklm\\", "hkcu\\", "hkey\\", "hkey_",
        "hklm]", "hkcu]", "hkey_local_machine]", "hkey_current_user]",
    ]):
        reg_identifiers = extract_reg_indicators(description)
        if reg_identifiers:
            evidence_dict["reg"] = reg_identifiers

    # extracting commands
    if "<code>" in description or "`" in description:
        cmd_identifiers = extract_cmd_indicators(description)
        if cmd_identifiers:
            evidence_dict["cmd"] = cmd_identifiers

    # extracting CVEs (enriched with actionable intelligence)
    if "CVE" in description.upper():
        cve_identifiers = extract_cve_indicators(description)
        if cve_identifiers:
            from MITRESaw.toolbox.tools.map_bespoke_logs import enrich_cves_for_evidence
            evidence_dict["cve"] = enrich_cves_for_evidence(cve_identifiers)

    # extracting software references
    if "/software/" in description.lower():
        software_identifiers = extract_software_indicators(description)
        if software_identifiers:
            evidence_dict["software"] = software_identifiers

    # extracting file paths and file names
    filepath_identifiers = extract_filepath_indicators(description)
    if filepath_identifiers:
        evidence_dict["filepath"] = filepath_identifiers

    # Append single consolidated entry with JSON-serialized evidence dict
    evidence_entry = "{}||{}".format(valid_procedure, json.dumps(evidence_dict))
    evidence_found.append(evidence_entry)

    # Print findings to stdout (iterate over dict entries)
    for ev_type, ev_identifiers in evidence_dict.items():
        if ev_identifiers:
            key = "{}||{}||{}||{}".format(
                technique_id, technique_name, software_group_name, ev_type
            )
            if key not in previous_findings:
                # For CVEs, print just CVE IDs and their indicators (not descriptions)
                if ev_type == "cve":
                    display_identifiers = []
                    for cve_entry in ev_identifiers:
                        for cve_id, cve_value in cve_entry.items():
                            parts = cve_value.split("|") if cve_value else []
                            indicators_part = parts[2] if len(parts) > 2 else ""
                            if indicators_part:
                                display_identifiers.append(f"{cve_id}: {indicators_part}")
                            else:
                                display_identifiers.append(cve_id)
                    stdout_identifiers = display_identifiers
                else:
                    stdout_identifiers = ev_identifiers
                finding_to_stdout(
                    technique_name,
                    software_group_name,
                    ev_type,
                    stdout_identifiers,
                    software_group_terms,
                    terms,
                    truncate,
                )
                previous_findings[key] = "-"

    if not quiet and evidence_dict:
        time.sleep(0.5)

    return evidence_found, previous_findings
