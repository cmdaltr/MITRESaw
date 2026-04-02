"""
Indicator exclusion list.

Loads data/exclusions.csv and provides a lookup for filtering
indicators during extraction and citation collection.
"""

import csv
import os
from pathlib import Path
from typing import Dict, Set, Tuple

_EXCLUSIONS_PATH = Path("data/exclusions.csv")
_exclusions: Dict[str, str] = {}  # indicator_lower → reason
_loaded = False


def _load():
    """Load exclusions from CSV on first access."""
    global _exclusions, _loaded
    if _loaded:
        return
    _loaded = True
    if not _EXCLUSIONS_PATH.exists():
        return
    try:
        with open(_EXCLUSIONS_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ind = row.get("indicator", "").strip()
                reason = row.get("reason", "").strip()
                if ind:
                    _exclusions[ind.lower()] = reason
    except Exception:
        pass


def is_excluded(indicator: str) -> bool:
    """Check if an indicator is in the exclusion list (case-insensitive)."""
    _load()
    return indicator.strip().lower() in _exclusions


def get_exclusion_reason(indicator: str) -> str:
    """Get the reason an indicator is excluded, or empty string if not excluded."""
    _load()
    return _exclusions.get(indicator.strip().lower(), "")


def filter_indicators(indicators: dict) -> Tuple[dict, list]:
    """Filter a dict of {type: [values]} against the exclusion list.

    Returns:
        (filtered_dict, excluded_list) where excluded_list contains
        tuples of (indicator, type, reason) for reporting.
    """
    _load()
    if not _exclusions:
        return indicators, []

    filtered = {}
    excluded = []

    for ind_type, values in indicators.items():
        kept = []
        for v in values:
            reason = _exclusions.get(str(v).strip().lower(), "")
            if reason:
                excluded.append((v, ind_type, reason))
            else:
                kept.append(v)
        if kept:
            filtered[ind_type] = kept

    return filtered, excluded


def reload():
    """Force reload of exclusions from disk."""
    global _loaded
    _loaded = False
    _exclusions.clear()
    _load()
