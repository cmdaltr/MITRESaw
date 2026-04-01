#!/usr/bin/env python3
"""
Generate a chart showing MITRE ATT&CK technique counts per attribution path
for key threat groups. Demonstrates why three-path extraction matters.

Data sourced from Archer's mitre_procedures.csv (STIX 2.1, ATT&CK v18.1).
"""

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# --- Real data from mitre_procedures.csv ---
groups = ["APT29\n(G0016)", "Wizard Spider\n(G0102)", "Lazarus Group\n(G0032)", "Scattered Spider\n(G1015)"]
direct =    [66,  64,  93,  64]
software =  [204, 198, 106, 94]
campaign =  [75,  0,   55,  28]
total =     [249, 209, 166, 150]

# What a naive (direct-only) tool would find
naive_pct = [round(d / t * 100, 1) for d, t in zip(direct, total)]
missed_pct = [round(100 - p, 1) for p in naive_pct]

# --- Chart 1: Stacked bar — techniques by attribution path ---
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), gridspec_kw={"width_ratios": [3, 2]})
fig.patch.set_facecolor("#0d1117")

x = np.arange(len(groups))
bar_width = 0.55

colors = {
    "direct":   "#58a6ff",
    "software": "#f78166",
    "campaign": "#7ee787",
    "bg":       "#0d1117",
    "text":     "#e6edf3",
    "grid":     "#21262d",
    "accent":   "#f0883e",
}

# Stacked bars
bars1 = ax1.bar(x, direct, bar_width, label="Direct (Group → Technique)",
                color=colors["direct"], edgecolor=colors["bg"], linewidth=0.5)
bars2 = ax1.bar(x, software, bar_width, bottom=direct,
                label="Via Software (Group → Tool → Technique)",
                color=colors["software"], edgecolor=colors["bg"], linewidth=0.5)
bars3 = ax1.bar(x, campaign, bar_width, bottom=[d + s for d, s in zip(direct, software)],
                label="Via Campaign (Campaign → Group + Technique)",
                color=colors["campaign"], edgecolor=colors["bg"], linewidth=0.5)

# Total labels on top
for i, t in enumerate(total):
    stack_top = direct[i] + software[i] + campaign[i]
    ax1.text(i, stack_top + 8, f"{t} total",
             ha="center", va="bottom", fontsize=11, fontweight="bold", color=colors["text"])

ax1.set_xticks(x)
ax1.set_xticklabels(groups, fontsize=10, color=colors["text"])
ax1.set_ylabel("Technique Count", fontsize=12, color=colors["text"])
ax1.set_title("Techniques per STIX Attribution Path", fontsize=14, fontweight="bold",
              color=colors["text"], pad=15)
ax1.legend(loc="upper right", fontsize=9, facecolor="#161b22", edgecolor=colors["grid"],
           labelcolor=colors["text"])
ax1.set_facecolor(colors["bg"])
ax1.tick_params(colors=colors["text"])
ax1.spines["top"].set_visible(False)
ax1.spines["right"].set_visible(False)
ax1.spines["left"].set_color(colors["grid"])
ax1.spines["bottom"].set_color(colors["grid"])
ax1.yaxis.set_major_locator(ticker.MultipleLocator(50))
ax1.set_ylim(0, max(d + s + c for d, s, c in zip(direct, software, campaign)) + 50)
ax1.grid(axis="y", color=colors["grid"], linewidth=0.5, alpha=0.7)

# --- Chart 2: Coverage gap — what direct-only tools miss ---
bars_found = ax2.barh(x, naive_pct, bar_width, label="Found (Direct only)",
                      color=colors["direct"], edgecolor=colors["bg"], linewidth=0.5)
bars_missed = ax2.barh(x, missed_pct, bar_width, left=naive_pct, label="Missed",
                       color="#f8514966", edgecolor="#f85149", linewidth=1.0,
                       hatch="///", alpha=0.85)

# Percentage labels
for i in range(len(groups)):
    ax2.text(naive_pct[i] / 2, i, f"{naive_pct[i]}%",
             ha="center", va="center", fontsize=10, fontweight="bold", color="white")
    if missed_pct[i] > 0:
        ax2.text(naive_pct[i] + missed_pct[i] / 2, i, f"{missed_pct[i]}%",
                 ha="center", va="center", fontsize=10, fontweight="bold", color="white")

ax2.set_yticks(x)
ax2.set_yticklabels(groups, fontsize=10, color=colors["text"])
ax2.set_xlabel("% of Total Techniques", fontsize=12, color=colors["text"])
ax2.set_title("What Direct-Only Extraction Misses", fontsize=14, fontweight="bold",
              color=colors["text"], pad=15)
ax2.legend(loc="lower right", fontsize=9, facecolor="#161b22", edgecolor=colors["grid"],
           labelcolor=colors["text"])
ax2.set_facecolor(colors["bg"])
ax2.tick_params(colors=colors["text"])
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)
ax2.spines["left"].set_color(colors["grid"])
ax2.spines["bottom"].set_color(colors["grid"])
ax2.set_xlim(0, 105)
ax2.xaxis.set_major_locator(ticker.MultipleLocator(25))
ax2.grid(axis="x", color=colors["grid"], linewidth=0.5, alpha=0.7)

plt.tight_layout(pad=2.0)

output_path = "attribution_path_comparison.png"
plt.savefig(output_path, dpi=200, bbox_inches="tight", facecolor=fig.get_facecolor())
plt.close()
print(f"Chart saved to {output_path}")
