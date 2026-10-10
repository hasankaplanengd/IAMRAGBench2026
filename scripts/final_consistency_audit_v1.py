#!/usr/bin/env python3
import csv
import re
from pathlib import Path

OUT = Path("summaries/final_consistency_audit_v1.md")

FILES = {
    "provider": Path("tables/table_provider_native_validation_e2e_v2.csv"),
    "crossmodel": Path("tables/table_crossmodel_retrieval_sensitivity_generation_clean_v1.csv"),
    "topk": Path("tables/table_topk_sensitivity_clean_v1.csv"),
    "adaptive": Path("tables/table_adaptive_guard_combined_clean_v1.csv"),
    "overlap": Path("summaries/retrieval_overlap_bias_v1_summary.md"),
}

def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def count(rows, key, val):
    return sum(1 for r in rows if str(r.get(key, "")).strip() == val)

def md_table(rows, fields):
    if not rows:
        return "_missing_\n"
    out = []
    out.append("| " + " | ".join(fields) + " |")
    out.append("|" + "|".join(["---"] * len(fields)) + "|")
    for r in rows:
        out.append("| " + " | ".join(str(r.get(f, "")) for f in fields) + " |")
    return "\n".join(out) + "\n"

lines = []
lines.append("# Final Consistency Audit v1\n")

# 1. Provider-native validation
provider = read_csv(FILES["provider"])
lines.append("## Provider-grounded validation\n")
if provider:
    validated = count(provider, "status", "validated")
    provider_invalid = count(provider, "status", "provider_invalid")
    mismatch = count(provider, "status", "decision_mismatch")
    aws_error = count(provider, "status", "aws_error")
    total = len(provider)
    lines.append(f"- Total tested: **{total}**")
    lines.append(f"- Provider-validated: **{validated}/{total}**")
    lines.append(f"- Provider-invalid: **{provider_invalid}/{total}**")
    lines.append(f"- Simulator-specific mismatch: **{mismatch}/{total}**")
    lines.append(f"- AWS errors: **{aws_error}/{total}**\n")
    if (validated, provider_invalid, mismatch, aws_error, total) == (9, 1, 1, 0, 11):
        lines.append("✅ Matches expected provider-native validation result: 9/11 validated, 1 provider-invalid, 1 mismatch.\n")
    else:
        lines.append("⚠️ Does NOT match expected provider-native validation result.\n")
else:
    lines.append("❌ Missing provider-native validation table.\n")

# 2. Cross-model retrieval sensitivity
cross = read_csv(FILES["crossmodel"])
lines.append("\n## Cross-model retrieval sensitivity\n")
lines.append(md_table(cross, [
    "model", "retriever", "poison_at_5", "control_pass",
    "confirmed_oracle_candidates", "provider_invalid", "nondeployable"
]))

# 3. Top-k sensitivity
topk = read_csv(FILES["topk"])
lines.append("\n## Top-k sensitivity\n")
lines.append(md_table(topk, [
    "model", "k", "poison_at_k", "control_pass",
    "confirmed_attacks", "provider_invalid", "nondeployable"
]))

# 4. Adaptive guarded-prompt stress test
adaptive = read_csv(FILES["adaptive"])
lines.append("\n## Adaptive guarded-prompt stress test\n")
lines.append(md_table(adaptive, [
    "model", "variant", "poison_at_5",
    "standard_confirmed_attacks", "guarded_confirmed_attacks",
    "delta_guarded_minus_standard", "interpretation"
]))

# 5. Overlap analysis
lines.append("\n## Retrieval-overlap / synthetic-corpus bias analysis\n")
if FILES["overlap"].exists():
    txt = FILES["overlap"].read_text(encoding="utf-8")
    keep = []
    for line in txt.splitlines():
        if (
            "Cases analyzed" in line
            or "Jaccard median" in line
            or "TF-IDF cosine median" in line
            or "Poison document more similar" in line
            or "near-duplicates" in line
        ):
            keep.append(line)
    lines.extend(keep)
    lines.append("")
else:
    lines.append("❌ Missing retrieval-overlap summary.\n")

# 6. Frozen paper numbers
lines.append("\n## Frozen paper numbers to use\n")
lines.append("""
Use these in the paper unless intentionally changed:

- Included-context:
  - Claude Sonnet 4.5: 0/60
  - Mistral Small: 3/60
  - Nova Lite: 5/60
  - Nova Pro: 17/60
  - Llama 3 8B: 18/57

- End-to-end BM25 k=5:
  - Claude Sonnet 4.5: 0/60
  - Mistral Small: 0/60
  - Nova Lite: 1/60
  - Nova Pro: 4/60
  - Llama 3 8B: 5/59 confirmed provider-deployable attacks
  - Llama note: one additional provider-invalid oracle failure and one nondeployable failure are reported separately.

- Provider-grounded validation:
  - 9/11 validated
  - 1/11 provider-invalid
  - 1/11 simulator-specific mismatch

- Retrieval sensitivity:
  - BM25 poison@5: 59/60
  - Dense poison@5: 58/60
  - Hybrid poison@5: 59/60

- Top-k sensitivity:
  - Poison retrieval increases with k, but confirmed attacks do not increase monotonically.

- Adaptive guarded prompt:
  - Nova Pro: guard reduces attacks strongly but not fully under compliance_exception.
  - Llama 3 8B: guard effect is weaker and one adaptive style increases.
  - Conclusion: guarded prompting helps but is not a robust final defense.
""")

OUT.write_text("\n".join(lines), encoding="utf-8")
print(OUT.read_text(encoding="utf-8"))
