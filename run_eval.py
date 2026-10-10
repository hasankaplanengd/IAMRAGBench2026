#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Self-contained evaluation runner.

- Reads a YAML config describing the model + dataset.
- Loads a JSONL dataset of paired prompts (control vs. poisoned).
- Calls Bedrock models (Anthropic/Cohere via Converse; Titan via invoke_model).
- Saves raw outputs + repaired JSON.
- Emits per_sample.csv and a summary_overall.json.

Expected dataset fields:
  - pair_id (string)
  - is_poisoned (bool)
  - prompt_control (string)      # on control rows
  - prompt_poisoned (string)     # on poisoned rows
  - expected_actions (any JSON)

Config (example):
model:
  provider: bedrock
  model_id: "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
  region: us-east-1
  max_tokens: 800
  temperature: 0.0
  top_p: null
  use_converse: true

dataset:
  path: ../datasets/policy_bench_v3_strict_s55.jsonl
  format: jsonl
  pair_key: pair_id
  expected_actions_key: expected_actions
  ctrl_key: prompt_control
  poi_key:  prompt_poisoned

eval:
  task: generation
  metrics: [exact_match]
  sample_size_pairs: 6            # set to 200 for full pass
"""

import os, sys, json, csv, yaml, time, datetime, hashlib
from collections import defaultdict, Counter

import boto3
from botocore.exceptions import BotoCoreError, ClientError

VERSION = "custom.v4"

# ---------- small utils ----------

def now_utc_ts():
    return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def slug(s, repl="_"):
    return "".join(ch if ch.isalnum() else repl for ch in str(s))

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def read_jsonl(fp, limit=None):
    items = []
    with open(fp, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                # debugging-friendly behavior
                items.append({"__parse_error__": line})
            if limit is not None and len(items) >= limit:
                break
    return items

def write_json(fp, obj):
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def write_text(fp, text):
    with open(fp, "w", encoding="utf-8") as f:
        f.write(text)

# ---------- JSON extraction (no recursive regex) ----------

def strip_code_fences(s):
    # Remove surrounding ```...``` if present
    t = s.strip()
    if t.startswith("```"):
        t = t[3:]
        # possible language tag
        t = t.lstrip("jsonJSON \t\r\n")
        # find ending ```
        end = t.rfind("```")
        if end != -1:
            t = t[:end]
    return t.strip()

def first_balanced_json_snippet(s):
    """
    Best-effort: scan for a top-level {...} or [...] block with balanced braces.
    Returns snippet or None.
    """
    t = s
    # quick pass over codefences first
    if "```" in t:
        parts = t.split("```")
        # examine fenced blocks (odd indexes)
        for i in range(1, len(parts), 2):
            candidate = parts[i]
            cand = candidate
            # drop possible lang token at start of block
            if cand.lower().lstrip().startswith("json"):
                cand = cand.split("\n", 1)[1] if "\n" in cand else ""
            cand = cand.strip()
            obj = _balanced_scan(cand)
            if obj is not None:
                return obj

    # otherwise scan whole string
    return _balanced_scan(t)

def _balanced_scan(t):
    # find first '{' or '['
    starts = []
    for idx, ch in enumerate(t):
        if ch in "{[":
            starts.append((idx, ch))
    # try each start in order
    for start_idx, ch in starts:
        stack = []
        in_str = False
        esc = False
        for j in range(start_idx, len(t)):
            c = t[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c in "{[":
                    stack.append(c)
                elif c in "}]":
                    if not stack:
                        break
                    op = stack.pop()
                    if (op == "{" and c != "}") or (op == "[" and c != "]"):
                        break
                    if not stack:
                        snippet = t[start_idx:j+1]
                        # quick sanity check
                        sn = snippet.strip()
                        if sn and (sn[0] in "{[" and sn[-1] in "}]"):
                            return sn
        # try next start
    return None

def try_parse_json(text):
    """
    Try to extract JSON:
      1) strip code fences if the whole thing looks fenced
      2) direct json.loads
      3) find first balanced snippet and parse
    Returns (obj, repair_tag) where repair_tag is None or "wrapped_plain".
    """
    t = text.strip()
    # try direct (fenced removed)
    unfenced = strip_code_fences(t)
    for candidate in (unfenced, t):
        try:
            return json.loads(candidate), None
        except Exception:
            pass

    # best-effort balanced scan
    snippet = first_balanced_json_snippet(t)
    if snippet:
        try:
            return json.loads(snippet), None
        except Exception:
            pass

    # fallback: wrap plain
    return {"ok": False, "repair": "wrapped_plain", "text": t}, "wrapped_plain"

# ---------- model calling ----------

def call_bedrock_converse(rt, model_id, user_text, system_text, max_tokens, temperature, top_p,
                          for_anthropic):
    """
    Bedrock Converse API.
    - system must be a list (not None)
    - For Anthropic specifically, avoid sending topP together with temperature.
    """
    messages = [{"role": "user", "content": [{"text": user_text}]}]
    system = []
    if system_text:
        system = [{"text": system_text}]

    inference = {}
    if max_tokens is not None:
        inference["maxTokens"] = int(max_tokens)
    if temperature is not None:
        inference["temperature"] = float(temperature)
    # Only include topP when it's explicitly provided and safe
    if (top_p is not None) and (not for_anthropic):
        inference["topP"] = float(top_p)

    # Converse
    resp = rt.converse(
        modelId=model_id,
        messages=messages,
        system=system,                 # list required, not None
        inferenceConfig=inference
    )
    # extract text
    out = resp.get("output", {}) or {}
    msg = out.get("message", {}) or {}
    chunks = msg.get("content", []) or []
    text = "".join(c.get("text", "") for c in chunks)
    return text

def call_bedrock_titan(rt, model_id, user_text, max_tokens, temperature, top_p):
    """
    Titan text (invoke_model). Do NOT send extra keys the model doesn't accept.
    """
    body = {
        "inputText": user_text,
        "textGenerationConfig": {
            "maxTokenCount": int(max_tokens) if max_tokens is not None else 512,
            "temperature": float(temperature) if temperature is not None else 0.0
        }
    }
    # topP 
    if top_p is not None:
        body["textGenerationConfig"]["topP"] = float(top_p)

    resp = rt.invoke_model(
        modelId=model_id,
        accept="application/json",
        contentType="application/json",
        body=json.dumps(body)
    )
    payload = json.loads(resp["body"].read().decode("utf-8"))
    results = payload.get("results") or []
    if results:
        return results[0].get("outputText", "") or ""
    return ""

def call_bedrock(model_id, region, user_text, provider_hint=None,
                 system_text=None, max_tokens=512, temperature=0.0, top_p=None,
                 use_converse=True):
    """
    Unified entrypoint for Bedrock calls.

    Returns dict:
      { ok: bool, raw_text: str, error: str|None }
    """
    rt = boto3.client("bedrock-runtime", region_name=region)

    # detect if Anthropic profile ID is used
    # Bedrock inference-profile model id example: "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    is_anthropic = (provider_hint and "anthropic" in provider_hint.lower()) or \
                   ("anthropic" in model_id.lower())

    try:
        if use_converse:
            text = call_bedrock_converse(
                rt=rt,
                model_id=model_id,
                user_text=user_text,
                system_text=system_text,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                for_anthropic=is_anthropic
            )
        else:
            # Titan path (invoke_model)
            text = call_bedrock_titan(
                rt=rt,
                model_id=model_id,
                user_text=user_text,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p
            )

        return {"ok": True, "raw_text": (text or "").strip(), "error": None}

    except ClientError as e:
        return {"ok": False, "raw_text": f"[ERROR] {e.__class__.__name__}: {str(e)}", "error": str(e)}
    except BotoCoreError as e:
        return {"ok": False, "raw_text": f"[ERROR] {e.__class__.__name__}: {str(e)}", "error": str(e)}
    except Exception as e:
        return {"ok": False, "raw_text": f"[ERROR] Unhandled: {str(e)}", "error": str(e)}


def safe_json_get(obj, key, default=None):
    """Like dict.get, but safe when the repaired JSON is a list/string/etc."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default

# ---------- dataset -> pairs ----------

def build_pairs(recs, pair_key, ctrl_key, poi_key):
    """
    Construct {pair_id: {"ctrl": str|None, "poi": str|None, "meta": any}}.
    We tolerate datasets where control/poison prompts are on separate rows.
    """
    pairs = defaultdict(lambda: {"ctrl": None, "poi": None, "meta": {}})
    for r in recs:
        if "__parse_error__" in r:
            # skip broken line
            continue
        pid = r.get(pair_key)
        if pid is None:
            # ignore rows without pair_id
            continue

        # carry along some metadata (last wins)
        pairs[pid]["meta"] = r

        # Case A: explicit keys on each record
        if ctrl_key in r and r[ctrl_key]:
            pairs[pid]["ctrl"] = r[ctrl_key]
        if poi_key in r and r[poi_key]:
            pairs[pid]["poi"] = r[poi_key]

        # Case B: single "prompt" and boolean flag
        if "prompt" in r and isinstance(r["prompt"], str):
            isp = r.get("is_poisoned")
            if isp is True and pairs[pid]["poi"] is None:
                pairs[pid]["poi"] = r["prompt"]
            elif isp is False and pairs[pid]["ctrl"] is None:
                pairs[pid]["ctrl"] = r["prompt"]

    # filter to only complete pairs
    complete = {pid: v for pid, v in pairs.items() if v["ctrl"] and v["poi"]}
    return complete

# ---------- main ----------

def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--config":
        print(f"Usage: {os.path.basename(sys.argv[0])} --config <config.yaml>")
        sys.exit(2)

    cfg_path = sys.argv[2]
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    model_cfg = cfg.get("model", {})
    ds_cfg    = cfg.get("dataset", {})
    ev_cfg    = cfg.get("eval", {})

    provider     = model_cfg.get("provider", "bedrock")
    model_id     = model_cfg.get("model_id")
    region       = model_cfg.get("region", "us-east-1")
    max_tokens   = model_cfg.get("max_tokens", 800)
    temperature  = model_cfg.get("temperature", 0.0)
    top_p        = model_cfg.get("top_p", None)
    use_converse = bool(model_cfg.get("use_converse", True))
    system_text  = model_cfg.get("system_text", None)  # optional

    path = ds_cfg.get("path")
    pair_key = ds_cfg.get("pair_key", "pair_id")
    exp_key  = ds_cfg.get("expected_actions_key", "expected_actions")
    ctrl_key = ds_cfg.get("ctrl_key", "prompt_control")
    poi_key  = ds_cfg.get("poi_key", "prompt_poisoned")

    sample_n = int(ev_cfg.get("sample_size_pairs", 6))

    print(f">>> RUN_EVAL VERSION: {VERSION}")
    print(f"CONFIG: {cfg_path}")

    # Load dataset
    recs = read_jsonl(path, limit=None)
    pairs = build_pairs(recs, pair_key=pair_key, ctrl_key=ctrl_key, poi_key=poi_key)

    all_ids = sorted(pairs.keys())
    selected = all_ids[:sample_n]
    print("SUMMARY")
    print(f" - total pairs : {len(all_ids)}")
    print(f" - first 5 ids : {selected[:5]}")

    # Create run folder
    run_id = f"{now_utc_ts()}_{slug(model_id).lower()}"
    run_dir = os.path.join("runs", run_id)
    raw_dir = os.path.join(run_dir, "raw")
    ensure_dir(raw_dir)

    # CSV rows + counters
    rows = []
    counters = Counter()

    # Process
    for pid in selected:
        item = pairs[pid]
        ctrl_prompt = item["ctrl"]
        poi_prompt  = item["poi"]

        # ---- CONTROL ----
        res_c = call_bedrock(
            model_id=model_id,
            region=region,
            user_text=ctrl_prompt,
            provider_hint=provider,
            system_text=system_text,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            use_converse=use_converse
        )
        raw_c = (res_c.get("raw_text") or "").strip()
        raw_fp_c = os.path.join(raw_dir, f"req_{pid}_ctrl.txt")
        write_text(raw_fp_c, raw_c)

        if raw_c.startswith("[ERROR]"):
            repaired_c = {"ok": False, "error_stub": True, "text": raw_c}
            counters["error_stub"] += 1
            rep_tag_c = None
        else:
            repaired_c, rep_tag_c = try_parse_json(raw_c)
            if rep_tag_c == "wrapped_plain":
                counters["wrapped_plain"] += 1
            else:
                counters["ok_json"] += 1

        rep_fp_c = os.path.join(raw_dir, f"req_{pid}_ctrl__REPAIRED.json")
        write_json(rep_fp_c, repaired_c)

        rows.append({
            "pair_id": pid,
            "prompt_type": "ctrl",
            "ok": bool(safe_json_get(repaired_c, "ok", False)),
            "repair": safe_json_get(repaired_c, "repair"),
            "error_stub": safe_json_get(repaired_c, "error_stub", False),
            "model_id": model_id,
            "provider": provider
        })

        # ---- POISONED ----
        res_p = call_bedrock(
            model_id=model_id,
            region=region,
            user_text=poi_prompt,
            provider_hint=provider,
            system_text=system_text,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            use_converse=use_converse
        )
        raw_p = (res_p.get("raw_text") or "").strip()
        raw_fp_p = os.path.join(raw_dir, f"req_{pid}_poi.txt")
        write_text(raw_fp_p, raw_p)

        if raw_p.startswith("[ERROR]"):
            repaired_p = {"ok": False, "error_stub": True, "text": raw_p}
            counters["error_stub"] += 1
            rep_tag_p = None
        else:
            repaired_p, rep_tag_p = try_parse_json(raw_p)
            if rep_tag_p == "wrapped_plain":
                counters["wrapped_plain"] += 1
            else:
                counters["ok_json"] += 1

        rep_fp_p = os.path.join(raw_dir, f"req_{pid}_poi__REPAIRED.json")
        write_json(rep_fp_p, repaired_p)

        rows.append({
            "pair_id": pid,
            "prompt_type": "poi",
            "ok": bool(safe_json_get(repaired_p, "ok", False)),
            "repair": safe_json_get(repaired_p, "repair"),
            "error_stub": safe_json_get(repaired_p, "error_stub", False),
            "model_id": model_id,
            "provider": provider
        })

    # Write per-sample CSV
    csv_fp = os.path.join(run_dir, "per_sample.csv")
    with open(csv_fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["pair_id","prompt_type","ok","repair","error_stub","model_id","provider"])
        w.writeheader()
        w.writerows(rows)

    # Summary
    summary = {
        "version": VERSION,
        "model_id": model_id,
        "provider": provider,
        "pairs_total": len(all_ids),
        "pairs_evaluated": len(selected),
        "counts": {
            "ok_json": counters.get("ok_json", 0),
            "wrapped_plain": counters.get("wrapped_plain", 0),
            "error_stub": counters.get("error_stub", 0)
        }
    }
    write_json(os.path.join(run_dir, "summary_overall.json"), summary)

    print("✅ Done.")
    print(f"📁 Outputs in: {run_dir}")
    print("   - per_sample.csv")
    print("   - summary_overall.json")
    print("   - raw/*.txt  (provider errors or raw model outputs)")
    print("   - raw/*__REPAIRED.json (clean JSON if extracted; wrapper otherwise)")

if __name__ == "__main__":
    main()
