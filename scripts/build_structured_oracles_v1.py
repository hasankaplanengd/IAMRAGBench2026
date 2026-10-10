#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import Counter, defaultdict

MASTER = Path("data/iam_rag_benchmark_master.csv")
OUT = Path("data/oracles_v1/structured_oracles_v1.jsonl")
TABLE = Path("tables/table_oracle_family_coverage_v1.csv")
SUMMARY = Path("summaries/structured_oracles_v1_summary.md")

def split_multi(x):
    return [p.strip() for p in str(x or "").replace(",", ";").split(";") if p.strip()]

def split_pipe(x):
    return [p.strip() for p in str(x or "").split("|") if p.strip()]

def parse_rule(rule):
    rule = rule.strip()
    if "=" in rule:
        k, v = rule.split("=", 1)
        return k.strip(), v.strip()
    return rule, True

def parse_oracle(oracle_text):
    oracle = {
        "requires_valid_json": False,
        "allowed_actions": {
            "exact": [],
            "subset_of": [],
            "must_include": [],
        },
        "resources": {
            "subset_of": [],
            "exact": [],
            "forbid_star": False,
        },
        "conditions": {
            "must_preserve": [],
            "must_include_allow": [],
            "must_include_any": [],
            "must_include_deny": [],
        },
        "principals": {
            "exact": [],
            "forbid_public": False,
        },
        "passrole": {
            "resource_exact": [],
            "forbid_role_wildcard": False,
        },
        "trust": {
            "required_action": [],
            "subject_must_equal": [],
            "forbid_service_wildcard": False,
        },
        "boundaries": {
            "boundary_exact": [],
            "forbid_policy": [],
        },
        "notresource": {
            "must_have_deny_notresource_guardrail": False,
        },
        "forbidden": {
            "actions": [],
            "services_wildcard": False,
            "resource_star": False,
            "public_principal": False,
        },
        "raw_rules": [],
        "unparsed_rules": [],
    }

    for raw in split_multi(oracle_text):
        k, v = parse_rule(raw)
        oracle["raw_rules"].append(raw)

        if k == "parse_json":
            oracle["requires_valid_json"] = True

        elif k == "allow_actions_exact":
            oracle["allowed_actions"]["exact"].extend(split_pipe(v))
        elif k == "allow_actions_subset_of":
            oracle["allowed_actions"]["subset_of"].extend(split_pipe(v))
        elif k == "must_include_action":
            oracle["allowed_actions"]["must_include"].extend(split_pipe(v))

        elif k in {"resources_subset_of", "allow_resources_subset_of"}:
            oracle["resources"]["subset_of"].extend(split_pipe(v))
        elif k in {"resource_exact", "resources_exact"}:
            oracle["resources"]["exact"].extend(split_pipe(v))
        elif k == "no_resource_star":
            oracle["resources"]["forbid_star"] = True
            oracle["forbidden"]["resource_star"] = True

        elif k == "must_preserve_condition":
            oracle["conditions"]["must_preserve"].append(v)
        elif k == "must_have_allow_condition":
            oracle["conditions"]["must_include_allow"].append(v)
        elif k == "must_include_condition":
            oracle["conditions"]["must_include_any"].append(v)
        elif k == "must_have_deny_condition":
            oracle["conditions"]["must_include_deny"].append(v)

        elif k == "principal_exact":
            oracle["principals"]["exact"].append(v)
        elif k == "no_public_principal":
            oracle["principals"]["forbid_public"] = True
            oracle["forbidden"]["public_principal"] = True

        elif k == "passrole_resource_exact":
            oracle["passrole"]["resource_exact"].append(v)
        elif k == "no_role_wildcard":
            oracle["passrole"]["forbid_role_wildcard"] = True

        elif k in {"trust_action_exact", "must_include_trust_action"}:
            oracle["trust"]["required_action"].append(v)
        elif k in {"sub_must_equal", "trust_sub_must_equal"}:
            oracle["trust"]["subject_must_equal"].append(v)
        elif k == "no_service_wildcard":
            oracle["trust"]["forbid_service_wildcard"] = True
            oracle["forbidden"]["services_wildcard"] = True

        elif k == "boundary_exact":
            oracle["boundaries"]["boundary_exact"].append(v)
        elif k == "no_policy":
            oracle["boundaries"]["forbid_policy"].append(v)

        elif k == "must_have_deny_notresource_guardrail":
            oracle["notresource"]["must_have_deny_notresource_guardrail"] = True

        elif k == "no_action":
            oracle["forbidden"]["actions"].extend(split_pipe(v))

        else:
            oracle["unparsed_rules"].append(raw)

    return oracle

def oracle_families(oracle):
    fams = []

    if oracle["allowed_actions"]["exact"] or oracle["allowed_actions"]["subset_of"] or oracle["allowed_actions"]["must_include"]:
        fams.append("action")
    if oracle["resources"]["subset_of"] or oracle["resources"]["exact"] or oracle["resources"]["forbid_star"]:
        fams.append("resource")
    if any(oracle["conditions"].values()):
        fams.append("condition")
    if oracle["principals"]["exact"] or oracle["principals"]["forbid_public"]:
        fams.append("principal")
    if oracle["passrole"]["resource_exact"] or oracle["passrole"]["forbid_role_wildcard"]:
        fams.append("passrole")
    if any(oracle["trust"].values()):
        fams.append("trust")
    if oracle["boundaries"]["boundary_exact"] or oracle["boundaries"]["forbid_policy"]:
        fams.append("boundary")
    if oracle["notresource"]["must_have_deny_notresource_guardrail"]:
        fams.append("notresource")
    if oracle["forbidden"]["actions"] or oracle["forbidden"]["services_wildcard"] or oracle["forbidden"]["resource_star"] or oracle["forbidden"]["public_principal"]:
        fams.append("forbidden")

    return sorted(set(fams))

def make_request_test_skeleton(row, oracle):
    actions = split_multi(row.get("trusted_intent_actions", ""))
    resources = split_multi(row.get("trusted_intent_resources", ""))
    first_action = actions[0] if actions else ""
    first_resource = resources[0] if resources else ""

    tests = {
        "must_allow": [],
        "must_not_allow": [],
        "notes": "Skeleton request tests derived from structured oracle. These are intended for later provider/local semantic validation.",
    }

    if first_action and first_resource:
        tests["must_allow"].append({
            "action": first_action,
            "resource": first_resource,
            "context": "trusted_required_context",
            "expected": "allow_or_not_explicitly_deny",
        })

    for cond in oracle["conditions"]["must_include_allow"] + oracle["conditions"]["must_preserve"]:
        tests["must_not_allow"].append({
            "action": first_action,
            "resource": first_resource,
            "missing_or_wrong_context": cond,
            "expected": "must_not_allow_without_required_condition",
        })

    for cond in oracle["conditions"]["must_include_deny"]:
        tests["must_not_allow"].append({
            "action": first_action,
            "resource": first_resource,
            "deny_guardrail_context": cond,
            "expected": "explicit_deny_required",
        })

    if oracle["resources"]["forbid_star"]:
        tests["must_not_allow"].append({
            "action": first_action,
            "resource": "*",
            "expected": "must_not_allow_resource_star",
        })

    if oracle["principals"]["forbid_public"]:
        tests["must_not_allow"].append({
            "principal": "*",
            "action": first_action,
            "resource": first_resource,
            "expected": "must_not_allow_public_principal",
        })

    if oracle["passrole"]["forbid_role_wildcard"]:
        tests["must_not_allow"].append({
            "action": "iam:PassRole",
            "resource": "arn:aws:iam::111122223333:role/*",
            "expected": "must_not_allow_role_wildcard",
        })

    return tests

with MASTER.open(newline="", encoding="utf-8-sig") as f:
    rows = [r for r in csv.DictReader(f) if r.get("case_id")]

OUT.parent.mkdir(parents=True, exist_ok=True)

family_counter = Counter()
category_counter = Counter()
unparsed = defaultdict(list)
records = []

with OUT.open("w", encoding="utf-8") as out:
    for r in rows:
        oracle = parse_oracle(r.get("oracle_check", ""))
        families = oracle_families(oracle)

        for fam in families:
            family_counter[fam] += 1

        category_counter[r.get("iam_category", "unknown")] += 1

        if oracle["unparsed_rules"]:
            unparsed[r["case_id"]].extend(oracle["unparsed_rules"])

        rec = {
            "case_id": r["case_id"],
            "split": r.get("split", ""),
            "aws_service": r.get("aws_service", ""),
            "iam_category": r.get("iam_category", ""),
            "security_violation_type": split_multi(r.get("security_violation_type", "")),
            "trusted_intent": {
                "actions": split_multi(r.get("trusted_intent_actions", "")),
                "resources": split_multi(r.get("trusted_intent_resources", "")),
                "conditions_or_guardrails": r.get("trusted_conditions_or_guardrails", ""),
            },
            "structured_oracle": oracle,
            "oracle_families": families,
            "request_test_skeleton": make_request_test_skeleton(r, oracle),
            "raw_oracle_check": r.get("oracle_check", ""),
        }

        records.append(rec)
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")

with TABLE.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["family", "cases"])
    writer.writeheader()
    for fam, n in sorted(family_counter.items()):
        writer.writerow({"family": fam, "cases": n})

summary = []
summary.append("# Structured oracle v1 summary\n")
summary.append(f"- Cases: {len(records)}")
summary.append(f"- Output: `{OUT}`")
summary.append(f"- Coverage table: `{TABLE}`")
summary.append("")
summary.append("## Oracle family coverage")
for fam, n in sorted(family_counter.items()):
    summary.append(f"- {fam}: {n}")
summary.append("")
summary.append("## IAM category coverage")
for cat, n in sorted(category_counter.items()):
    summary.append(f"- {cat}: {n}")

if unparsed:
    summary.append("")
    summary.append("## Unparsed oracle rules to inspect")
    for cid, rules in sorted(unparsed.items()):
        summary.append(f"- {cid}: {rules}")
else:
    summary.append("")
    summary.append("## Unparsed oracle rules")
    summary.append("- none")

SUMMARY.write_text("\n".join(summary) + "\n", encoding="utf-8")

print("Wrote:")
print(f"  {OUT}")
print(f"  {TABLE}")
print(f"  {SUMMARY}")

print("\nOracle family coverage:")
for fam, n in sorted(family_counter.items()):
    print(f"  {fam}: {n}")

print("\nUnparsed rules:")
if not unparsed:
    print("  none")
else:
    for cid, rules in sorted(unparsed.items()):
        print(f"  {cid}: {rules}")

print("\nFirst structured oracle:")
print(json.dumps(records[0], indent=2, ensure_ascii=False)[:3500])
