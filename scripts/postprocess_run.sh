#!/usr/bin/env bash
set -euo pipefail

RUN="${1:?Usage: postprocess_run.sh RUN_DIR CONFIG_YAML}"
CFG="${2:?Usage: postprocess_run.sh RUN_DIR CONFIG_YAML}"

# to ensure repaired JSON exists / plain text is wrapped
python scripts/repair_raw_to_json.py --force --wrap-plain "$RUN"

# variant-level simple ASR 
python scripts/analyze_by_variant.py "$RUN/raw" --out_csv "$RUN/variant_asr_summary.csv"

# IAM-semantic + pairwise drift (paper metric)
python scripts/pairwise_semantic_drift.py "$RUN" --config "$CFG"

echo "[ok] wrote:"
echo "  $RUN/variant_asr_summary.csv"
echo "  $RUN/pairwise_semantic.csv"
echo "  $RUN/variant_semantic.csv"
echo "  $RUN/semantic_summary.json"
