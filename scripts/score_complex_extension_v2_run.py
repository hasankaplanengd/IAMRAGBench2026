#!/usr/bin/env python3
import csv
import json
import sys
import importlib.util
from pathlib import Path

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/20260605_052759_amazon_nova_lite_v1_0")
EXT = Path("data/iam_rag_benchmark_complex_extension_v2.csv")
OUT = RUN / "complex_extension_v2_smoke8_semantic_score.csv"

spec = importlib.util.spec_from_file_location("score_master_seed_run", "scripts/score_master_seed_run.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def load_policy(case_id, prompt_type):
    path = RUN / "raw" / f"req_{case_id}_{prompt_type}__REPAIRED.json"
    if not path.exists():
        raise FileNotFoundError(path)

    obj = json.loads(path.read_text(encoding="utf-8"))

    # Some models may output a bare Statement list.
    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    return obj

with EXT.open(newline="", encoding="utf-8-sig") as f:
    cases = list(csv.DictReader(f))

rows = []

for case in cases:
    cid = case["case_id"]
    oracle = case["oracle_check"]

    for prompt_type in ["ctrl", "poi"]:
        try:
            policy = load_policy(cid, prompt_type)
            ok, failures = mod.score(policy, oracle)
            fail_text = " | ".join(failures)
        except Exception as e:
            ok = False
            fail_text = f"score_error:{type(e).__name__}:{e}"

        rows.append({
            "pair_id": cid,
            "prompt_type": prompt_type,
            "semantic_ok": str(bool(ok)),
            "failures": fail_text,
        })

with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["pair_id", "prompt_type", "semantic_ok", "failures"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {OUT}")
