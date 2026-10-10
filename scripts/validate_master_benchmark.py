#!/usr/bin/env python3
import csv
from pathlib import Path
from collections import Counter, defaultdict

MASTER = Path("data/iam_rag_benchmark_master.csv")

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
    "rag_setting",
]

KNOWN_RULE_PREFIXES = [
    "parse_json",
    "allow_actions_exact=",
    "allow_actions_subset_of=",
    "must_include_action=",
    "no_action=",
    "resources_subset_of=",
    "allow_resources_subset_of=",
    "resource_exact=",
    "must_preserve_condition=",
    "must_have_allow_condition=",
    "must_have_deny_condition=",
    "no_service_wildcard",
    "no_resource_star",
    "no_public_principal",
    "principal_exact=",
    "must_have_deny_notresource_guardrail",
    "no_policy=",
    "boundary_exact=",
    "must_include_condition=",
    "passrole_resource_exact=",
    "no_role_wildcard",
    "effect_allow_only_sts_assume_role_web_identity",
    "sub_must_equal_repo_acme_payments_main",
    "no_sub_wildcard_above_repo",
]

def known_rule(rule: str) -> bool:
    return any(rule == p or rule.startswith(p) for p in KNOWN_RULE_PREFIXES)

with MASTER.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

errors = []
warnings = []

ids = [r.get("case_id", "").strip() for r in rows]
dups = [x for x, c in Counter(ids).items() if c > 1]
if dups:
    errors.append(f"Duplicate case_id values: {dups}")

for i, r in enumerate(rows, start=2):
    cid = r.get("case_id", f"row_{i}")

    for col in REQUIRED_NONEMPTY:
        if not r.get(col, "").strip():
            errors.append(f"{cid}: missing required column {col}")

    oracle = r.get("oracle_check", "")
    rules = [x.strip() for x in oracle.split(";") if x.strip()]
    for rule in rules:
        if not known_rule(rule):
            warnings.append(f"{cid}: unknown oracle rule: {rule}")

    actions = [x.strip() for x in r.get("trusted_intent_actions", "").replace(",", ";").split(";") if x.strip()]
    if len(actions) > 1:
        warnings.append(f"{cid}: multiple trusted actions; make sure oracle handles this: {actions}")

    if "Resource '*'" in r.get("poison_doc_text", "") or 'Resource "*"' in r.get("poison_doc_text", ""):
        if "no_resource_star" not in oracle:
            warnings.append(f"{cid}: poison asks for Resource * but oracle lacks no_resource_star")

    if ":*" in r.get("poison_doc_text", ""):
        if "no_service_wildcard" not in oracle and "no_action=" not in oracle:
            warnings.append(f"{cid}: poison may ask for service wildcard but oracle may not check it")

print("MASTER VALIDATION SUMMARY")
print(f"Rows: {len(rows)}")

print("\nBy split:")
for k, v in sorted(Counter(r.get("split", "") for r in rows).items()):
    print(f"  {k}: {v}")

print("\nBy category:")
for k, v in sorted(Counter(r.get("iam_category", "") for r in rows).items()):
    print(f"  {k}: {v}")

print("\nBy AWS service:")
for k, v in sorted(Counter(r.get("aws_service", "") for r in rows).items()):
    print(f"  {k}: {v}")

print("\nErrors:")
if errors:
    for e in errors:
        print(f"  ERROR: {e}")
else:
    print("  none")

print("\nWarnings:")
if warnings:
    for w in warnings[:120]:
        print(f"  WARN: {w}")
    if len(warnings) > 120:
        print(f"  ... {len(warnings) - 120} more warnings")
else:
    print("  none")

if errors:
    raise SystemExit(1)
