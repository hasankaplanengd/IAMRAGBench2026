#!/usr/bin/env python3
import csv
from pathlib import Path
from collections import Counter

MASTER = Path("data/iam_rag_benchmark_master.csv")
EXT = Path("data/iam_rag_benchmark_complex_extension_v2.csv")
SCORER = Path("scripts/score_master_seed_run.py")

REQUIRED_NONEMPTY = [
    "case_id",
    "status",
    "split",
    "iam_category",
    "aws_service",
    "user_task",
    "trusted_intent_actions",
    "trusted_intent_resources",
    "trusted_conditions_or_guardrails",
    "clean_doc_type",
    "clean_doc_text",
    "poison_doc_type",
    "poison_position",
    "poison_family",
    "poison_doc_text",
    "attacker_goal",
    "expected_safe_policy_summary",
    "security_violation_type",
    "oracle_check",
]

KNOWN_ORACLE_RULES = {
    "parse_json",
    "allow_actions_exact",
    "allow_actions_subset_of",
    "must_include_action",
    "resources_subset_of",
    "allow_resources_subset_of",
    "resource_exact",
    "resources_exact",
    "no_resource_star",
    "must_preserve_condition",
    "must_have_allow_condition",
    "must_include_condition",
    "must_have_deny_condition",
    "principal_exact",
    "no_public_principal",
    "passrole_resource_exact",
    "no_role_wildcard",
    "trust_action_exact",
    "must_include_trust_action",
    "sub_must_equal",
    "trust_sub_must_equal",
    "no_service_wildcard",
    "boundary_exact",
    "no_policy",
    "must_have_deny_notresource_guardrail",
    "must_have_deny_notaction_guardrail",
    "no_action",
}

SCORER_REQUIRED_STRINGS = [
    "must_have_deny_notaction_guardrail",
    "no_policy",
    "no_action",
    "boundary_exact",
    "allow_actions_subset_of",
]

def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def split_multi(x):
    return [p.strip() for p in str(x or "").replace(",", ";").split(";") if p.strip()]

def oracle_rule_keys(oracle):
    out = []
    for part in split_multi(oracle):
        if "=" in part:
            out.append(part.split("=", 1)[0].strip())
        else:
            out.append(part.strip())
    return out

def p_class(row):
    text = (row.get("iam_category", "") + " " + row.get("security_violation_type", "")).lower()
    if any(k in text for k in ["passrole", "trust", "assumerole", "privilege"]):
        return "P3: privilege escalation enablement"
    if any(k in text for k in ["boundary", "admin_policy", "managed_policy", "policy_version", "commit", "rollback"]):
        return "P4: over-privileged execution/commit risk"
    if any(k in text for k in ["public", "principal_widening"]):
        return "P5: public/resource-policy exposure"
    if any(k in text for k in ["condition", "abac", "deny_guardrail", "notresource", "notaction"]):
        return "P2: constraint or guardrail weakening"
    if any(k in text for k in ["action_widening", "resource_widening", "resource_star", "service_wildcard"]):
        return "P1: action/resource widening"
    return "Other"

master = read_csv(MASTER)
ext = read_csv(EXT)

master_ids = {r["case_id"] for r in master if r.get("case_id")}
ext_ids = [r["case_id"] for r in ext if r.get("case_id")]

errors = []
warnings = []

# Duplicate checks
dups_in_ext = [cid for cid, n in Counter(ext_ids).items() if n > 1]
dups_against_master = sorted(set(ext_ids) & master_ids)

if dups_in_ext:
    errors.append(f"Duplicate case_id inside extension: {dups_in_ext}")
if dups_against_master:
    errors.append(f"Extension case_id already exists in master: {dups_against_master}")

# Required fields and oracle parsing
unknown_rules = []
for r in ext:
    cid = r.get("case_id", "<missing>")
    for col in REQUIRED_NONEMPTY:
        if not str(r.get(col, "")).strip():
            errors.append(f"{cid}: missing required column {col}")

    for rule in oracle_rule_keys(r.get("oracle_check", "")):
        if rule not in KNOWN_ORACLE_RULES:
            unknown_rules.append((cid, rule))

if unknown_rules:
    for cid, rule in unknown_rules:
        errors.append(f"{cid}: unknown oracle rule {rule}")

# Scorer support check
scorer_text = SCORER.read_text(encoding="utf-8") if SCORER.exists() else ""
missing_scorer = [s for s in SCORER_REQUIRED_STRINGS if s not in scorer_text]

# Merged coverage
merged = master + ext

print("COMPLEX EXTENSION V2 VALIDATION")
print(f"Master cases: {len(master)}")
print(f"Extension cases: {len(ext)}")
print(f"Merged total would be: {len(merged)}")

print("\nExtension categories:")
for k, v in sorted(Counter(r["iam_category"] for r in ext).items()):
    print(f"  {k}: {v}")

print("\nMerged IAM weakness classes:")
for k, v in sorted(Counter(p_class(r) for r in merged).items()):
    print(f"  {k}: {v}")

print("\nOracle rules used in extension:")
rules = Counter()
for r in ext:
    for rule in oracle_rule_keys(r.get("oracle_check", "")):
        rules[rule] += 1
for k, v in sorted(rules.items()):
    print(f"  {k}: {v}")

print("\nScorer support check:")
if not missing_scorer:
    print("  scorer appears to contain all required rule strings")
else:
    for s in missing_scorer:
        print(f"  MISSING_IN_SCORER: {s}")

print("\nErrors:")
if not errors:
    print("  none")
else:
    for e in errors:
        print(" ", e)

print("\nWarnings:")
if not warnings:
    print("  none")
else:
    for w in warnings:
        print(" ", w)
