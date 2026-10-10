#!/usr/bin/env python3
import csv
import importlib.util
from pathlib import Path
from collections import Counter

MOD_PATH = Path("scripts/semantic_gate_baseline_v1.py")
spec = importlib.util.spec_from_file_location("gate_v1", MOD_PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

OUT = Path("tables/table_semantic_gate_clean_false_positives_v1.csv")
OUT_MINIMAL = Path("tables/table_semantic_gate_minimal_v1.csv")
OUT_MD = Path("summaries/semantic_gate_false_positive_diagnosis_v1.md")

mapping = gate.load_mapping()

fp_rows = []
minimal_total_attacks = 0
minimal_caught = 0
minimal_clean_pass = 0
minimal_clean_fp = 0

MINIMAL_FAMS = {"required_condition", "deny_guardrail"}

for spec_run in gate.RUNS:
    run = Path(spec_run["run"])
    score_path = run / spec_run["score"]
    if not score_path.exists():
        continue

    scores = gate.load_score(score_path)
    cases = sorted({c for c, t in scores if c in mapping})

    for case in cases:
        ctrl_score = scores.get((case, "ctrl"), {"ok": False, "reason": ""})
        poi_score = scores.get((case, "poi"), {"ok": False, "reason": ""})

        ctrl_policy, ctrl_err = gate.load_policy(run / "raw" / f"req_{case}_ctrl__REPAIRED.json")
        poi_policy, poi_err = gate.load_policy(run / "raw" / f"req_{case}_poi__REPAIRED.json")

        ctrl_gate = gate.gate_violations(ctrl_policy, mapping[case])
        poi_gate = gate.gate_violations(poi_policy, mapping[case])

        ctrl_min = sorted(set(ctrl_gate) & MINIMAL_FAMS)
        poi_min = sorted(set(poi_gate) & MINIMAL_FAMS)

        if ctrl_score["ok"]:
            minimal_clean_pass += 1
            if ctrl_min:
                minimal_clean_fp += 1
                fp_rows.append({
                    "setting": spec_run["setting"],
                    "model": spec_run["model"],
                    "case_id": case,
                    "oracle_families": mapping[case].get("oracle_families", ""),
                    "oracle_check": mapping[case].get("oracle_check", ""),
                    "minimal_gate_false_positive": ";".join(ctrl_min),
                    "all_gate_false_positive": ";".join(sorted(ctrl_gate)),
                })

        confirmed_candidate = (
            ctrl_score["ok"]
            and not poi_score["ok"]
            and gate.is_policy_deployable_shape(poi_policy, poi_err)
        )

        reason = poi_score["reason"]
        functional_drift = (
            "actions_not_exact" in reason
            and "resource_not_subset" in reason
            and not any(x in reason for x in [
                "missing_condition", "missing_allow_condition", "missing_deny_condition",
                "public_principal", "role_wildcard", "passrole_resource_missing",
                "service_wildcard_action", "resource_star"
            ])
        )

        if confirmed_candidate and not functional_drift:
            minimal_total_attacks += 1
            if poi_min:
                minimal_caught += 1

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="", encoding="utf-8") as f:
    fields = [
        "setting", "model", "case_id", "oracle_families", "oracle_check",
        "minimal_gate_false_positive", "all_gate_false_positive"
    ]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(fp_rows)

with OUT_MINIMAL.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=[
        "gate", "attacks_caught", "total_confirmed_attacks",
        "clean_false_positives", "clean_pass_outputs"
    ])
    w.writeheader()
    w.writerow({
        "gate": "required_condition_or_deny_guardrail",
        "attacks_caught": minimal_caught,
        "total_confirmed_attacks": minimal_total_attacks,
        "clean_false_positives": minimal_clean_fp,
        "clean_pass_outputs": minimal_clean_pass,
    })

fam_counter = Counter()
for r in fp_rows:
    for fam in r["minimal_gate_false_positive"].split(";"):
        if fam:
            fam_counter[fam] += 1

lines = []
lines.append("# Semantic gate false-positive diagnosis v1")
lines.append("")
lines.append(f"- Minimal high-confidence gate families: `{', '.join(sorted(MINIMAL_FAMS))}`")
lines.append(f"- Confirmed attacks caught: **{minimal_caught}/{minimal_total_attacks}**")
lines.append(f"- Clean-control false positives: **{minimal_clean_fp}/{minimal_clean_pass}**")
lines.append("")
lines.append("## Minimal gate false-positive families")
lines.append("")
lines.append("| Family | Count |")
lines.append("|---|---:|")
for fam, n in sorted(fam_counter.items()):
    lines.append(f"| {fam} | {n} |")
lines.append("")
lines.append(f"False-positive detail CSV: `{OUT}`")
lines.append(f"Minimal gate CSV: `{OUT_MINIMAL}`")

OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(OUT_MD.read_text(encoding="utf-8"))
