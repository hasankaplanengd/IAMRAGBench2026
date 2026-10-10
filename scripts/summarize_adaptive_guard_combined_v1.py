#!/usr/bin/env python3
import csv
from pathlib import Path

INPUTS = [
    Path("tables/table_adaptive_guard_nova_pro_clean_v1.csv"),
    Path("tables/table_adaptive_guard_llama3_8b_clean_v1.csv"),
]

OUT_CSV = Path("tables/table_adaptive_guard_combined_clean_v1.csv")
OUT_MD = Path("summaries/adaptive_guard_combined_clean_v1_summary.md")

def parse_num(x):
    if not x:
        return 0
    return int(str(x).split("/")[0])

rows = []
for p in INPUTS:
    with p.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)

# Build paired standard/guarded rows.
by_key = {}
for r in rows:
    key = (r["model"], r["variant"])
    by_key.setdefault(key, {})[r["style"]] = r

summary = []
for (model, variant), d in sorted(by_key.items()):
    std = d.get("standard")
    grd = d.get("guarded")
    if not std or not grd:
        continue

    std_att = parse_num(std["confirmed_attacks"])
    grd_att = parse_num(grd["confirmed_attacks"])
    delta = grd_att - std_att

    summary.append({
        "model": model,
        "variant": variant,
        "poison_at_5": std.get("poison_at_5", ""),
        "standard_control_pass": std.get("control_pass", ""),
        "standard_confirmed_attacks": std.get("confirmed_attacks", ""),
        "guarded_control_pass": grd.get("control_pass", ""),
        "guarded_confirmed_attacks": grd.get("confirmed_attacks", ""),
        "delta_guarded_minus_standard": str(delta),
        "interpretation": "reduced" if delta < 0 else ("unchanged" if delta == 0 else "increased"),
    })

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
    fields = list(summary[0].keys())
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(summary)

lines = []
lines.append("# Adaptive guarded-prompt stress test, combined")
lines.append("")
lines.append("| Model | Variant | Poison@5 | Standard attacks | Guarded attacks | Δ guarded-standard | Interpretation |")
lines.append("|---|---|---:|---:|---:|---:|---|")
for r in summary:
    lines.append(
        f"| {r['model']} | {r['variant']} | {r['poison_at_5']} | "
        f"{r['standard_confirmed_attacks']} | {r['guarded_confirmed_attacks']} | "
        f"{r['delta_guarded_minus_standard']} | {r['interpretation']} |"
    )
lines.append("")
lines.append(f"CSV: `{OUT_CSV}`")

OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(OUT_MD.read_text(encoding="utf-8"))
