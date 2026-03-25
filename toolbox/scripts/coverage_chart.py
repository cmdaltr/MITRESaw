#!/usr/bin/env python3
"""Generate a MITRE ATT&CK technique coverage comparison bar chart for a given group.

The three collection methods are:
  1. Native:      parent techniques only from the group's ATT&CK page (no sub-techniques)
  2. Direct STIX: all techniques (parent + sub) via group and campaign STIX relationships
  3. All Paths:   direct STIX + software-attributed techniques

Usage:
    python coverage_chart.py -g Scattered_Spider
    python coverage_chart.py -g APT29 -o apt29_coverage.png
    python coverage_chart.py -g Lazarus_Group --stix stix_data/enterprise-attack.json
"""

import argparse
import os
import sys

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STIX_PATH = os.path.join(SCRIPT_DIR, "stix_data", "enterprise-attack.json")


def find_group(attack_data, group_query):
    """Resolve a group query (name or alias, underscores as spaces) to a STIX group object."""
    query = group_query.replace("_", " ").lower()
    for group in attack_data.get_groups(remove_revoked_deprecated=True):
        name = group.get("name", "")
        aliases = group.get("aliases", [])
        if query in [name.lower()] + [a.lower() for a in aliases]:
            return group
    return None


def _ext_id(stix_obj):
    """Extract the ATT&CK external ID (e.g. T1059.001) from a STIX object."""
    obj = stix_obj.get("object", stix_obj)
    refs = obj.get("external_references", [{}])
    return refs[0].get("external_id", "") if refs else ""


def count_native(attack_data, group):
    """Count unique PARENT technique IDs from direct group→technique relationships.

    This represents what you'd get from a basic scrape of the group's ATT&CK page
    without expanding sub-techniques — the 'native' view.
    """
    parent_ids = set()
    for t in attack_data.get_techniques_used_by_group(group.get("id")):
        tid = _ext_id(t)
        if tid:
            parent_ids.add(tid.split(".")[0])
    return len(parent_ids)


def count_direct_stix(attack_data, group):
    """Count unique technique IDs (parent + sub) from group and campaign STIX relationships.

    This represents proper STIX traversal: direct group→technique plus
    techniques from campaigns attributed to the group.
    """
    technique_ids = set()

    for t in attack_data.get_techniques_used_by_group(group.get("id")):
        tid = _ext_id(t)
        if tid:
            technique_ids.add(tid)

    try:
        for campaign_entry in (attack_data.get_campaigns_attributed_to_group(group.get("id")) or []):
            campaign_obj = campaign_entry.get("object", campaign_entry)
            try:
                for ct in attack_data.get_techniques_used_by_campaign(campaign_obj.get("id", "")):
                    tid = _ext_id(ct)
                    if tid:
                        technique_ids.add(tid)
            except Exception:
                pass
    except Exception:
        pass

    return len(technique_ids)


def count_all_paths(attack_data, group):
    """Count unique technique IDs from all collection methods.

    Combines direct STIX (group + campaigns) with software-attributed techniques:
    for each software used by the group, include all techniques that software employs.
    """
    technique_ids = set()

    # Group→technique
    for t in attack_data.get_techniques_used_by_group(group.get("id")):
        tid = _ext_id(t)
        if tid:
            technique_ids.add(tid)

    # Campaign→technique
    try:
        for campaign_entry in (attack_data.get_campaigns_attributed_to_group(group.get("id")) or []):
            campaign_obj = campaign_entry.get("object", campaign_entry)
            try:
                for ct in attack_data.get_techniques_used_by_campaign(campaign_obj.get("id", "")):
                    tid = _ext_id(ct)
                    if tid:
                        technique_ids.add(tid)
            except Exception:
                pass
    except Exception:
        pass

    # Software→technique
    try:
        for sw in attack_data.get_software_used_by_group(group.get("id")):
            sw_obj = sw.get("object", sw)
            try:
                for t in attack_data.get_techniques_used_by_software(sw_obj.get("id", "")):
                    tid = _ext_id(t)
                    if tid:
                        technique_ids.add(tid)
            except Exception:
                pass
    except Exception:
        pass

    return len(technique_ids)


def generate_chart(group_name, values, output_path):
    """Generate and save the coverage comparison bar chart."""
    categories = ["Native", "Direct STIX", "All Paths"]
    colors = ["#ef4444", "#f59e0b", "#22c55e"]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(categories, values, color=colors, height=0.55,
                   edgecolor="white", linewidth=1.5)

    # Value labels on bars
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_width() - 3, bar.get_y() + bar.get_height() / 2,
            f"{val}",
            va="center", ha="right",
            fontsize=18, fontweight="bold", color="white",
        )

    # Arrows between bars
    for i in range(len(values) - 1):
        ax.annotate(
            "",
            xy=(values[i + 1] * 0.15, (i + 1) - 0.05),
            xytext=(values[i] * 0.15, i + 0.05),
            arrowprops=dict(
                arrowstyle="->,head_width=0.3,head_length=0.15",
                color="#64748b", lw=2,
                connectionstyle="arc3,rad=0.3",
            ),
        )

    ax.set_xlabel("Techniques Identified", fontsize=13, fontweight="medium", labelpad=10)
    ax.set_title(
        f"{group_name} \u2014 MITRE ATT&CK Technique Coverage",
        fontsize=16, fontweight="bold", pad=18,
    )

    ax.set_xlim(0, max(values) * 1.12)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(25))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0, labelsize=13)
    ax.tick_params(axis="x", labelsize=11)
    ax.grid(axis="x", linestyle="--", alpha=0.3)

    # Multiplier annotations (relative to native baseline)
    baseline = values[0] if values[0] > 0 else 1
    for i in range(1, len(values)):
        multiplier = values[i] / baseline
        ax.text(values[i] + 4, i, f"{multiplier:.1f}\u00d7",
                fontsize=12, color=colors[i], fontweight="bold", va="center")

    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"Saved {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate MITRE ATT&CK technique coverage comparison chart for a group."
    )
    parser.add_argument(
        "-g", "--group", required=True,
        help="MITRE ATT&CK group name or alias (use underscores for spaces, e.g. Scattered_Spider)"
    )
    parser.add_argument(
        "-o", "--output", default="coverage_comparison.png",
        help="Output PNG path (default: coverage_comparison.png)"
    )
    parser.add_argument(
        "--stix", default=STIX_PATH,
        help=f"Path to enterprise-attack.json (default: {STIX_PATH})"
    )
    args = parser.parse_args()

    print(f"Loading STIX data from {args.stix}...")
    try:
        from mitreattack.stix20 import MitreAttackData
    except ImportError:
        sys.exit("Error: mitreattack-python not installed. Run: pip install mitreattack-python")

    attack_data = MitreAttackData(args.stix)

    group = find_group(attack_data, args.group)
    if not group:
        sys.exit(f"Error: group '{args.group}' not found in STIX data.")

    group_name = group.get("name", args.group.replace("_", " "))
    print(f"Found group: {group_name}")

    print("Counting techniques...")
    native = count_native(attack_data, group)
    direct = count_direct_stix(attack_data, group)
    all_paths = count_all_paths(attack_data, group)

    print(f"  Native (parent techniques):           {native}")
    print(f"  Direct STIX (parent + sub + campaigns): {direct}")
    print(f"  All Paths (+ software-attributed):      {all_paths}")

    generate_chart(group_name, [native, direct, all_paths], args.output)


if __name__ == "__main__":
    main()
