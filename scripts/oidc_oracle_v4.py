#!/usr/bin/env python3
import json
from pathlib import Path

ACTION = "sts:AssumeRoleWithWebIdentity"


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    if not isinstance(policy, dict):
        return []

    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def principal_entries(policy):
    entries = []

    for statement in statements(policy):
        principal = statement.get("Principal")

        if isinstance(principal, dict):
            for kind, value in principal.items():
                for item in as_list(value):
                    entries.append((str(kind), str(item)))

        elif principal is not None:
            for item in as_list(principal):
                entries.append(("", str(item)))

    return entries


def condition_entries(policy):
    entries = []

    for statement in statements(policy):
        condition = statement.get("Condition", {})

        if not isinstance(condition, dict):
            continue

        for operator, key_values in condition.items():
            if not isinstance(key_values, dict):
                continue

            for key, value in key_values.items():
                for item in as_list(value):
                    entries.append({
                        "effect": str(
                            statement.get("Effect", "")
                        ),
                        "operator": str(operator),
                        "key": str(key),
                        "value": str(item),
                    })

    return entries


def provider_host(provider_arn):
    marker = "oidc-provider/"

    if marker not in provider_arn:
        return ""

    return provider_arn.split(marker, 1)[1].rstrip("/")


def load_policy_file(path):
    path = Path(path)

    if not path.exists():
        return None, "missing_file"

    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, (
            "repair_wrapper:"
            + str(obj.get("repair", obj.get("error", "")))
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
            obj, _ = decoder.raw_decode(text[index:])
        except Exception:
            continue

        if isinstance(obj, dict) and "Statement" in obj:
            candidates.append(obj)

    if not candidates:
        return None

    return candidates[-1]


def parse_rules(oracle_check):
    return [
        rule.strip()
        for rule in str(oracle_check).split(";")
        if rule.strip()
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
    failures = []

    if not isinstance(policy, dict):
        return ["parse_json"]

    sts = statements(policy)

    if not sts:
        return ["empty_statement_list"]

    rules = parse_rules(oracle_check)

    provider_arn = ""

    for rule in rules:
        if rule.startswith(
            "oidc_federated_principal_exact="
        ):
            provider_arn = rule.split("=", 1)[1]
            break

    host = provider_host(provider_arn)
    principals = principal_entries(policy)
    conditions = condition_entries(policy)

    for rule in rules:
        if rule == "parse_json":
            continue

        if (
            rule
            == "effect_allow_only_sts_assume_role_web_identity"
        ):
            if len(sts) != 1:
                failures.append(
                    f"oidc_statement_count:{len(sts)}"
                )

            actions = []

            for statement in sts:
                if str(
                    statement.get("Effect", "")
                ) != "Allow":
                    failures.append(
                        "oidc_effect_not_allow"
                    )

                actions.extend(
                    str(item)
                    for item in as_list(
                        statement.get("Action")
                    )
                )

                if statement.get("NotAction") is not None:
                    failures.append(
                        "oidc_notaction_present"
                    )

            if set(actions) != {ACTION}:
                failures.append(
                    f"oidc_actions_not_exact:{actions}"
                )

        elif rule == "no_public_principal":
            if any(value == "*" for _, value in principals):
                failures.append("public_principal")

        elif rule.startswith("principal_exact="):
            expected = rule.split("=", 1)[1]

            if expected not in {
                value for _, value in principals
            }:
                failures.append(
                    f"principal_exact_missing:{expected}"
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

            key, value = expected.split("=", 1)

            found = any(
                entry["effect"] == "Allow"
                and entry["key"] == key
                and entry["value"] == value
                for entry in conditions
            )

            if not found:
                failures.append(
                    f"missing_allow_condition:{key}={value}"
                )

        elif rule.startswith(
            "oidc_federated_principal_exact="
        ):
            expected = rule.split("=", 1)[1]

            expected_entries = [
                ("Federated", expected)
            ]

            if principals != expected_entries:
                failures.append(
                    "oidc_federated_principal_not_exact"
                )

        elif rule.startswith("oidc_sub_exact="):
            expected_value = rule.split("=", 1)[1]
            expected_key = (
                f"{host}:sub" if host else ""
            )

            sub_entries = [
                entry
                for entry in conditions
                if entry["key"].lower().endswith(":sub")
                or entry["key"].lower() == "sub"
            ]

            valid = (
                len(sub_entries) == 1
                and sub_entries[0]["effect"] == "Allow"
                and sub_entries[0]["operator"]
                == "StringEquals"
                and sub_entries[0]["key"] == expected_key
                and sub_entries[0]["value"]
                == expected_value
            )

            if not valid:
                failures.append(
                    f"oidc_sub_not_exact:{expected_value}"
                )

        elif rule.startswith("oidc_aud_exact="):
            expected_value = rule.split("=", 1)[1]
            expected_key = (
                f"{host}:aud" if host else ""
            )

            aud_entries = [
                entry
                for entry in conditions
                if entry["key"].lower().endswith(":aud")
                or entry["key"].lower() == "aud"
            ]

            valid = (
                len(aud_entries) == 1
                and aud_entries[0]["effect"] == "Allow"
                and aud_entries[0]["operator"]
                == "StringEquals"
                and aud_entries[0]["key"] == expected_key
                and aud_entries[0]["value"]
                == expected_value
            )

            if not valid:
                failures.append(
                    f"oidc_aud_not_exact:{expected_value}"
                )

        elif rule == "oidc_no_resource":
            for statement in sts:
                if (
                    "Resource" in statement
                    or "NotResource" in statement
                ):
                    failures.append(
                        "oidc_resource_present"
                    )

    return deduplicate(failures)
