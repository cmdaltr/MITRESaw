#!/usr/bin/env python3 -tt
import os
import re


def upper_repl(match):
    return match.group(1).upper()


def lower_repl(match):
    return match.group(1).lower()


def elastic_query_repl(match):
    upper_match = upper_repl(match)
    lower_match = lower_repl(match)
    return "[{}{}]".format(upper_match, lower_match)


def build_queries(queries, mitresaw_output_directory, query_pairings):
    if queries:
        if os.path.exists(os.path.join(mitresaw_output_directory, "queries.conf")):
            os.remove(os.path.join(mitresaw_output_directory, "queries.conf"))
        with open(
            os.path.join(mitresaw_output_directory, "queries.conf"), "a"
        ) as opmitre_queries:
            for query in query_pairings:
                query_combinations = []
                queries_to_write = []
                technique_id = query.split("||")[0]
                technique_name = query.split("||")[1]
                query_strings = query.split("||")[2]
                if " " in query_strings:
                    if not query_strings.startswith("hk"):
                        if " " in query_strings:
                            andor_query = '("{}")'.format(
                                query_strings.strip("'")
                                .replace('"', '\\"')
                                .replace(" ", '" and "')
                                .replace("*", "")
                                .strip('"')
                                .strip("\\")
                            )
                else:
                    andor_query = query_strings
                if '"), ("' in andor_query and not andor_query.startswith('("'):
                    or_queries = '("{}")'.format(andor_query.replace("++", '", "'))
                else:
                    or_queries = andor_query.replace("++", '", "')
                if not or_queries.startswith('("') and not or_queries.endswith('")'):
                    or_queries = '("{}")'.format(or_queries)
                or_queries = re.sub(r'(" and "[^\"]+")(, ")', r"\1§§\2", or_queries)
                or_queries = re.sub(r'(" and "[^\"]+")(\))', r"\1)\2", or_queries)
                or_queries = re.sub(r'(", )("[^\"]+" and ")', r"\1§§\2", or_queries)
                or_queries = re.sub(r'(\()("[^\"]+" and ")', r"\1(\2", or_queries)
                or_queries = or_queries.replace('(("', '("').replace('"))', '")')
                multiple_queries = re.findall(r"§§([^§]+)(?:§§|\)$)", or_queries)
                if len(multiple_queries) > 0:
                    and_queries = multiple_queries
                    or_queries = re.sub(r"§§[^§]+(?:§§|\)$)", "", or_queries)
                    or_queries = or_queries.replace('", , "', '", "')
                else:
                    and_queries = or_queries
                query_combinations.append("{}||{}".format(or_queries, and_queries))
                if (
                    str(query_combinations)[2:-2].split("||")[0]
                    == str(query_combinations)[2:-2].split("||")[1]
                ):
                    final_query = str(query_combinations)[2:-2].split("||")[0]
                else:
                    final_query = (
                        str(query_combinations)[2:-2]
                        .replace("\", \\', \\', \"", '", "')
                        .replace("[\\', \"", '"')
                        .replace("\"\\']", '"')
                    )
                final_query_combo = final_query.replace("\\\\\\\\", "\\\\").replace(
                    '""', '"'
                )
                stanza_title = str("[{}: {}]").format(technique_id, technique_name)
                for query_combo_type in final_query_combo.split("||"):
                    if '" and "' in query_combo_type:
                        splunk_queries = (
                            "where {} IN(<field_name>)  // SPL [Splunk]".format(
                                query_combo_type.strip("(")
                                .strip(")")
                                .replace("[\\'\"", '"')
                                .replace("\\', \\'", "§§")
                                .replace(" and ", " IN(<field_name>) AND where ")
                                .replace(
                                    "§§",
                                    " IN(<field_name>)  // SPL [Splunk]\nwhere ",
                                )
                            )
                        )
                        sentinel_queries = (
                            "<field_name> has_all{})  // KQL [Sentinel]".format(
                                query_combo_type.replace('" and "', '", "')
                                .replace("[\\'\"", '("')
                                .replace(
                                    "\\', \\'",
                                    ")  // KQL [Sentinel]\n<field_name> has_all(",
                                )
                            )
                        )
                        kql_queries = (
                            "<field_name>:({})  // KQL [Elastic/Kibana]".format(
                                query_combo_type.strip("(")
                                .strip(")")
                                .replace("[\\'\"", '"')
                                .replace("\\', \\'", "§§")
                                .replace(
                                    "§§",
                                    ")  // KQL [elastic/Kibana]\n<field_name>:(",
                                )
                                .replace('", "', '" OR "')
                                .replace('" and "', '" AND "')
                            )
                        )
                        lucene_queries = (
                            (
                                "/.*{}.*/  // Lucene [elastic/Kibana]".format(
                                    re.sub(
                                        r"(\w)",
                                        elastic_query_repl,
                                        query_combo_type.replace(
                                            '" and "', "¬¬"
                                        ).replace("/", "\\\\/"),
                                    )
                                    .strip("(")
                                    .strip(")")
                                    .strip('"')
                                    .replace("[\\'\"", '"')
                                    .replace("\\', \\'", "§§")
                                    .replace(".", "\\\\.")
                                    .replace(" ", "\\\\ ")
                                    .replace('", "', '" or "')
                                    .replace(
                                        "§§",
                                        ".*/  // Lucene [elastic/Kibana]\n/.*",
                                    )
                                    .replace("¬¬", ".*")
                                    .replace(
                                        '*,\\\\ "',
                                        ".*/  // Lucene [elastic/Kibana]\n/.*",
                                    )
                                    .replace(
                                        '",\\\\ "',
                                        ".*/  // Lucene [elastic/Kibana]\n/.*",
                                    )
                                    .replace('/.*"', "/.*")
                                    .replace('".*/', ".*/")
                                )
                            )
                            .replace('/.*"[', "/.*[")
                            .replace("-", "\\\\-")
                            .replace("(", "\\\\(")
                            .replace(")", "\\\\)")
                            .replace('"[remote" and "address]', "[remote address]")
                            .replace("\n/..*/  // Lucene [elastic/Kibana]\n", "")
                        )
                        dsl_queries = '{{"bool": {{"must": [{{"query_string": {{"query": "{}","fields": ["<field_name>","<field_name>"]}}}}]}}}}'.format(
                            lucene_queries.replace(" Lucene ", " Query DSL ")
                        )
                        elastic_api_queries = '{{"query": {{"terms": {{"<field name>": [ "{}" ]}}}}}}  // API [elastic/Kibana]'.format(
                            lucene_queries.replace(" Lucene ", " Query DSL ")
                        )
                        queries_to_write.append(
                            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n\n".format(
                                stanza_title,
                                splunk_queries,
                                sentinel_queries,
                                lucene_queries,
                                kql_queries,
                                dsl_queries,
                                elastic_api_queries,
                            )
                        )
                    else:
                        splunk_query = (
                            "where {} IN(<field_name>)  // SPL [Splunk]".format(
                                query_combo_type
                            )
                        )
                        sentinel_query = (
                            "<field_name> has_any{}  // KQL [Sentinel]".format(
                                query_combo_type
                            )
                        )
                        kql_query = "<field_name>:({})  // KQL [elastic/Kibana]".format(
                            query_combo_type.replace("', '", '" or "')
                        )
                        lucene_query = "/.*{}.*/  // Lucene [elastic/Kibana]".format(
                            re.sub(
                                r"(\w)",
                                elastic_query_repl,
                                query_combo_type,
                            ).replace("', '", '" OR "')
                        )
                        dsl_query = '{{"bool": {{"must": [{{"query_string": {{"query": "{}","fields": ["<field_name>","<field_name>"]}}}}]}}}}  // API [elastic/Kibana]'.format(
                            query_combo_type
                        )
                        elastic_api_query = '{{"query": {{"terms": {{"<field name>": [ "{}" ]}}}}}}  // Query DSL [elastic/Kibana]'.format(
                            query_combo_type
                        )
                        queries_to_write.append(
                            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n\n".format(
                                stanza_title,
                                splunk_query,
                                sentinel_query,
                                lucene_query,
                                kql_query,
                                dsl_query,
                                elastic_api_query,
                            )
                        )
                    for query_to_write in queries_to_write:
                        opmitre_queries.write(query_to_write)
