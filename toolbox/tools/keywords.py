#!/usr/bin/env python3 -tt

# Predefined industry/sector keywords commonly found in MITRE ATT&CK group descriptions.
# Used to auto-tag threat groups with their targeted industries.
INDUSTRY_KEYWORDS = [
    "aerospace",
    "agriculture",
    "automotive",
    "aviation",
    "banking",
    "biotechnology",
    "chemical",
    "communications",
    "construction",
    "consulting",
    "critical infrastructure",
    "cryptocurrency",
    "defense",
    "diplomatic",
    "dissident",
    "education",
    "electronics",
    "energy",
    "engineering",
    "entertainment",
    "financial",
    "food",
    "gaming",
    "government",
    "healthcare",
    "hospitality",
    "humanitarian",
    "industrial",
    "insurance",
    "journalism",
    "legal",
    "logistics",
    "manufacturing",
    "maritime",
    "media",
    "military",
    "mining",
    "nuclear",
    "oil and gas",
    "petrochemical",
    "pharmaceutical",
    "policy",
    "political",
    "real estate",
    "research",
    "retail",
    "satellite",
    "semiconductor",
    "shipping",
    "space",
    "steel",
    "supply chain",
    "technology",
    "telecommunications",
    "telecom",
    "think tank",
    "transportation",
    "travel",
    "utility",
    "video game",
    "water",
]


def match_keywords(description, keywords=None):
    """Match industry keywords against a group description.

    Returns matched keywords as a semicolon-delimited string.
    """
    if keywords is None:
        keywords = INDUSTRY_KEYWORDS
    if not description:
        return ""
    desc_lower = description.lower()
    matched = [kw for kw in keywords if kw in desc_lower]
    return "; ".join(sorted(set(matched)))
