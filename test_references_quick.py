#!/usr/bin/env python3
"""
Quick test for the -R reference collection pipeline.
Tests against cached STIX data without running the full MITRESaw pipeline.

Usage:
    python3 test_references_quick.py
    python3 test_references_quick.py --fetch    # Actually fetch URLs (slow)
"""

import json
import sys

from toolbox.citation_collector import resolve_citations, collect_reference_content


def main():
    fetch = "--fetch" in sys.argv

    # Load STIX bundle
    print("[1] Loading STIX data...")
    with open("stix_data/enterprise-attack.json") as f:
        bundle = json.load(f)

    # Find a relationship with citations and external_references
    print("[2] Finding relationships with citations...")
    test_cases = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        desc = obj.get("description", "")
        ext_refs = obj.get("external_references", [])
        if "(Citation:" in desc and ext_refs:
            # Get source group name
            src_ref = obj.get("source_ref", "")
            group_name = ""
            for o in bundle["objects"]:
                if o.get("id") == src_ref and o.get("type") == "intrusion-set":
                    group_name = o.get("name", "")
                    break

            # Get target technique
            tgt_ref = obj.get("target_ref", "")
            tech_name = ""
            tech_id = ""
            for o in bundle["objects"]:
                if o.get("id") == tgt_ref and o.get("type") == "attack-pattern":
                    tech_name = o.get("name", "")
                    for ref in o.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id", "")
                            break
                    break

            if group_name and tech_id:
                test_cases.append({
                    "group": group_name,
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "procedure": desc,
                    "ext_refs": ext_refs,
                })
                if len(test_cases) >= 3:
                    break

    if not test_cases:
        print("ERROR: No relationships with citations found in STIX data")
        sys.exit(1)

    print(f"    Found {len(test_cases)} test cases\n")

    # Test resolve_citations
    for i, tc in enumerate(test_cases, 1):
        print(f"[{i+2}] Testing: {tc['group']} → {tc['technique_id']} ({tc['technique_name']})")
        print(f"    Procedure (first 100 chars): {tc['procedure'][:100]}...")

        citations = resolve_citations(tc["procedure"], tc["ext_refs"])
        print(f"    Citations resolved: {len(citations)}")
        for cit in citations:
            url = cit.get("url", "(no URL)")
            print(f"      - {cit['citation_name']}")
            print(f"        URL: {url}")

        if fetch and citations:
            print(f"    Fetching content...")
            results = collect_reference_content(
                citations,
                tc["group"],
                tc["technique_name"],
                tc["technique_id"],
                verbose=True,
            )
            for r in results:
                content_len = len(r.get("extracted_content", ""))
                print(f"      {r['citation_name']}: status={r['status']}, "
                      f"content={content_len} chars")
                if content_len > 0:
                    print(f"        Preview: {r['extracted_content'][:150]}...")

        print()

    # Test the hash lookup (same method as _collect_and_append_references)
    print("[*] Testing hash-based STIX lookup...")
    ext_ref_lookup = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        desc = obj.get("description", "")
        if desc and obj.get("external_references"):
            ext_ref_lookup[hash(desc)] = obj["external_references"]

    matched = 0
    for tc in test_cases:
        h = hash(tc["procedure"])
        if h in ext_ref_lookup:
            matched += 1

    print(f"    Hash lookup: {matched}/{len(test_cases)} matched")
    print(f"    Total relationships indexed: {len(ext_ref_lookup)}")

    print("\n[*] All tests passed!" if matched == len(test_cases) else "\n[!] Some hash lookups failed")


if __name__ == "__main__":
    main()
