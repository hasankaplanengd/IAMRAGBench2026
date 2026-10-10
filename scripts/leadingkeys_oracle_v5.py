#!/usr/bin/env python3
import json
from pathlib import Path

LEADINGKEYS = "dynamodb:LeadingKeys"
REQUIRED_OPERATOR = "ForAllValues:StringEquals"


def as_list(value):
    if value is None:
        return []

    return value if isinstance(value, list) else [value]


def statements(policy):
    if not isinstance(policy, dict):
        return []

    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def load_policy_file(path):
    path = Path(path)

    if not path.exists():
        return None, "missing_file"

    try:
        obj = json.loads(
            path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, (
            "repair_wrapper:"
            + str(
                obj.get(
                    "repair",
                    obj.get("error", "unknown"),
                )
            )
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    if not statements(obj):
        return None, "empty_statement_list"

    return obj, ""


def extract_policy_from_text(text):
    decoder = json.JSONDecoder()
    candidates = []

    for index, char in enumerate(text):
        if char != "{":
            continue

        try:
            obj, _ = decoder.raw_decode(
                text[index:]
            )
        except Exception:
            continue

        if isinstance(obj, dict) and "Statement" in obj:
            candidates.append(obj)

    if not candidates:
        return None

    return candidates[-1]


def action_values(policy):
    values = []

    for statement in statements(policy):
        values.extend(
            str(item)
            for item in as_list(
                statement.get("Action")
            )
        )

    return values


def resource_values(policy):
    values = []

    for statement in statements(policy):
        values.extend(
            str(item)
            for item in as_list(
                statement.get("Resource")
            )
        )

    return values


def condition_entries(policy):
    entries = []

    for statement in statements(policy):
        condition = statement.get(
            "Condition",
            {},
        )

        if not isinstance(condition, dict):
            continue

        for operator, key_values in condition.items():
            if not isinstance(key_values, dict):
                continue

            for key, value in key_values.items():
                entries.append({
                    "effect": str(
                        statement.get("Effect", "")
                    ),
                    "operator": str(operator),
                    "key": str(key),
                    "values": [
                        str(item)
                        for item in as_list(value)
                    ],
                })

    return entries


def resource_matches(resource, expected):
    if resource == expected:
        return True

    if expected.startswith("arn:"):
        return False

    return (
        resource.endswith("/" + expected)
        or resource.endswith(":" + expected)
    )


def parse_rules(oracle_check):
    return [
        item.strip()
        for item in str(oracle_check).split(";")
        if item.strip()
    ]


def deduplicate(items):
    output = []
    seen = set()

    for item in items:
        if item not in seen:
            output.append(item)
            seen.add(item)

    return output


def score_policy(policy, oracle_check):
    if not isinstance(policy, dict):
        return ["parse_json"]

    failures = []
    actions = action_values(policy)
    resources = resource_values(policy)
    conditions = condition_entries(policy)

    for rule in parse_rules(oracle_check):
        if rule == "parse_json":
            continue

        if rule.startswith("allow_actions_exact="):
            expected = {
                item
                for item in rule.split("=", 1)[1].split("|")
                if item
            }

            if not actions or set(actions) != expected:
                failures.append(
                    f"actions_not_exact:{actions}"
                )

        elif rule.startswith(
            "allow_actions_subset_of="
        ):
            allowed = {
                item
                for item in rule.split("=", 1)[1].split("|")
                if item
            }

            if (
                not actions
                or not set(actions).issubset(allowed)
            ):
                failures.append(
                    f"actions_not_subset:{actions}"
                )

        elif rule.startswith("resource_exact="):
            expected = rule.split("=", 1)[1]

            if (
                not resources
                or not all(
                    resource_matches(
                        resource,
                        expected,
                    )
                    for resource in resources
                )
            ):
                failures.append(
                    f"resource_not_exact:{resources}"
                )

        elif rule.startswith(
            "resources_subset_of="
        ):
            allowed = {
                item
                for item in rule.split("=", 1)[1].split("|")
                if item
            }

            if (
                not resources
                or not set(resources).issubset(allowed)
            ):
                failures.append(
                    f"resource_not_subset:{resources}"
                )

        elif rule.startswith(
            "must_preserve_condition="
        ):
            expected_key = rule.split("=", 1)[1]

            if not any(
                entry["effect"] == "Allow"
                and entry["key"] == expected_key
                for entry in conditions
            ):
                failures.append(
                    f"missing_condition:{expected_key}"
                )

        elif rule.startswith(
            "must_have_allow_condition="
        ):
            expected = rule.split("=", 1)[1]

            if "=" not in expected:
                failures.append(
                    f"invalid_condition_rule:{expected}"
                )
                continue

            expected_key, expected_value = (
                expected.split("=", 1)
            )

            found = any(
                entry["effect"] == "Allow"
                and entry["key"] == expected_key
                and expected_value
                in entry["values"]
                for entry in conditions
            )

            if not found:
                failures.append(
                    "missing_allow_condition:"
                    f"{expected_key}={expected_value}"
                )

        elif rule.startswith(
            "dynamodb_leadingkeys_forall_exact="
        ):
            expected_value = rule.split("=", 1)[1]

            leadingkeys = [
                entry
                for entry in conditions
                if entry["key"] == LEADINGKEYS
            ]

            valid = (
                len(leadingkeys) == 1
                and leadingkeys[0]["effect"] == "Allow"
                and leadingkeys[0]["operator"]
                == REQUIRED_OPERATOR
                and set(leadingkeys[0]["values"])
                == {expected_value}
            )

            if not valid:
                observed = [
                    {
                        "effect": entry["effect"],
                        "operator": entry["operator"],
                        "values": entry["values"],
                    }
                    for entry in leadingkeys
                ]

                failures.append(
                    "leadingkeys_not_forall_exact:"
                    + json.dumps(
                        observed,
                        sort_keys=True,
                    )
                )

        elif rule == "no_resource_star":
            if any(
                resource == "*"
                for resource in resources
            ):
                failures.append("resource_star")

    return deduplicate(failures)
