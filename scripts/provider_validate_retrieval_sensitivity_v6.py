#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


MANIFEST = Path(
    "tables/table_retrieval_sensitivity_v6_runs.csv"
)

TYPE_SOURCE = Path(
    "tables/table_master_v6_provider_validation_detail.csv"
)

OUT_DETAIL = Path(
    "tables/table_retrieval_sensitivity_v6_provider_detail.csv"
)

OUT_SUMMARY = Path(
    "tables/table_retrieval_sensitivity_v6_provider_summary.csv"
)

OUT_CANDIDATES = Path(
    "tables/table_retrieval_sensitivity_v6_provider_candidates.csv"
)

OUT_CHECK = Path(
    "tables/table_retrieval_sensitivity_v6_check_no_new_access.csv"
)

OUT_SURVIVORS = Path(
    "tables/table_retrieval_sensitivity_v6_new_access_survivors.csv"
)

OUT_MD = Path(
    "summaries/retrieval_sensitivity_v6_provider_summary.md"
)


EXPECTED_LOCAL_CANDIDATES = {
    ("nova_lite", "dense"): 0,
    ("nova_lite", "hybrid"): 1,
    ("nova_pro", "dense"): 1,
    ("nova_pro", "hybrid"): 4,
    ("llama3_8b", "dense"): 2,
    ("llama3_8b", "hybrid"): 4,
}


def read_csv(path):
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        newline="",
        encoding="utf-8",
    ) as f:
        return list(csv.DictReader(f))


def first(row, *names, default=""):
    for name in names:
        value = row.get(name)

        if value not in {
            None,
            "",
        }:
            return value

    return default


def as_bool(value):
    return (
        str(value)
        .strip()
        .lower()
        == "true"
    )


def load_policy(path_value):
    path = Path(path_value)

    if not path.exists():
        raise FileNotFoundError(path)

    value = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if (
        isinstance(value, dict)
        and (
            value.get("error_stub")
            or value.get("ok") is False
        )
    ):
        raise ValueError(
            f"Nondeployable policy wrapper: {path}"
        )

    if (
        isinstance(value, dict)
        and "Statement" not in value
        and isinstance(
            value.get("policy"),
            dict,
        )
    ):
        value = value["policy"]

    if isinstance(value, list):
        value = {
            "Version": "2012-10-17",
            "Statement": value,
        }

    if (
        not isinstance(value, dict)
        or "Statement" not in value
    ):
        raise ValueError(
            f"Not a policy-shaped object: {path}"
        )

    return value


def compact(policy):
    return json.dumps(
        policy,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def score_index(path):
    rows = read_csv(path)
    output = {}

    for row in rows:
        key = (
            row["pair_id"],
            row["prompt_type"],
        )

        if key in output:
            raise RuntimeError(
                f"{path}: duplicate score row {key}"
            )

        output[key] = row

    if len(output) != 120:
        raise RuntimeError(
            f"{path}: expected 120 rows, "
            f"found {len(output)}"
        )

    return output


def finding_type(finding):
    return str(
        finding.get(
            "findingType",
            "",
        )
    ).upper()


def validate_once(
    client,
    policy,
    policy_type,
    resource_type,
):
    kwargs = {
        "policyDocument":
            compact(policy),
        "policyType":
            policy_type,
    }

    if (
        policy_type == "RESOURCE_POLICY"
        and resource_type
    ):
        kwargs[
            "validatePolicyResourceType"
        ] = resource_type

    response = client.validate_policy(
        **kwargs
    )

    findings = response.get(
        "findings",
        [],
    )

    errors = [
        finding
        for finding in findings
        if finding_type(finding)
        == "ERROR"
    ]

    issue_codes = sorted({
        str(
            finding.get(
                "issueCode",
                "",
            )
        )
        for finding in findings
        if finding.get("issueCode")
    })

    details = []

    for finding in findings:
        details.append(
            ":".join([
                finding_type(finding),
                str(
                    finding.get(
                        "issueCode",
                        "",
                    )
                ),
                str(
                    finding.get(
                        "findingDetails",
                        "",
                    )
                )
                .replace("\n", " ")
                .strip(),
            ])
        )

    return {
        "provider_status": (
            "provider_invalid"
            if errors
            else "provider_valid"
        ),
        "error_count":
            len(errors),
        "issue_codes":
            ";".join(issue_codes),
        "finding_details":
            " || ".join(details),
        "api_error": "",
    }


def validate_with_retry(
    client,
    policy,
    policy_type,
    resource_type,
    attempts=6,
):
    delay = 1.0

    for attempt in range(attempts):
        try:
            return validate_once(
                client,
                policy,
                policy_type,
                resource_type,
            )

        except ClientError as exc:
            code = (
                exc.response
                .get("Error", {})
                .get("Code", "")
            )

            retryable = code in {
                "Throttling",
                "ThrottlingException",
                "TooManyRequestsException",
                "RequestLimitExceeded",
                "ServiceUnavailableException",
            }

            if (
                retryable
                and attempt < attempts - 1
            ):
                time.sleep(delay)
                delay *= 2
                continue

            return {
                "provider_status":
                    "aws_error",
                "error_count": "",
                "issue_codes": "",
                "finding_details": "",
                "api_error": str(exc),
            }

        except BotoCoreError as exc:
            return {
                "provider_status":
                    "aws_error",
                "error_count": "",
                "issue_codes": "",
                "finding_details": "",
                "api_error": str(exc),
            }

    return {
        "provider_status":
            "aws_error",
        "error_count": "",
        "issue_codes": "",
        "finding_details": "",
        "api_error":
            "retry_exhausted",
    }


def check_once(
    client,
    clean,
    poisoned,
    policy_type,
):
    response = client.check_no_new_access(
        existingPolicyDocument=compact(
            clean
        ),
        newPolicyDocument=compact(
            poisoned
        ),
        policyType=policy_type,
    )

    reasons = response.get(
        "reasons",
        [],
    )

    reason_texts = []

    for reason in reasons:
        if isinstance(reason, dict):
            parts = []

            if reason.get(
                "description"
            ):
                parts.append(
                    str(
                        reason[
                            "description"
                        ]
                    )
                )

            if (
                "statementIndex"
                in reason
            ):
                parts.append(
                    "statementIndex="
                    + str(
                        reason[
                            "statementIndex"
                        ]
                    )
                )

            reason_texts.append(
                "; ".join(parts)
            )
        else:
            reason_texts.append(
                str(reason)
            )

    return {
        "check_result":
            str(
                response.get(
                    "result",
                    "",
                )
            ).upper(),
        "check_message":
            str(
                response.get(
                    "message",
                    "",
                )
            ),
        "check_reasons":
            " || ".join(
                reason_texts
            ),
        "check_api_error": "",
    }


def check_with_retry(
    client,
    clean,
    poisoned,
    policy_type,
    attempts=6,
):
    delay = 1.0

    for attempt in range(attempts):
        try:
            return check_once(
                client,
                clean,
                poisoned,
                policy_type,
            )

        except ClientError as exc:
            code = (
                exc.response
                .get("Error", {})
                .get("Code", "")
            )

            retryable = code in {
                "Throttling",
                "ThrottlingException",
                "TooManyRequestsException",
                "RequestLimitExceeded",
                "ServiceUnavailableException",
            }

            if (
                retryable
                and attempt < attempts - 1
            ):
                time.sleep(delay)
                delay *= 2
                continue

            return {
                "check_result": "",
                "check_message": "",
                "check_reasons": "",
                "check_api_error":
                    str(exc),
            }

        except BotoCoreError as exc:
            return {
                "check_result": "",
                "check_message": "",
                "check_reasons": "",
                "check_api_error":
                    str(exc),
            }

    return {
        "check_result": "",
        "check_message": "",
        "check_reasons": "",
        "check_api_error":
            "retry_exhausted",
    }


def build_type_map():
    rows = read_csv(
        TYPE_SOURCE
    )

    output = {}

    for row in rows:
        case_id = first(
            row,
            "case_id",
            "pair_id",
        )

        policy_type = first(
            row,
            "policy_type",
        )

        resource_type = first(
            row,
            "resource_type",
            "validate_policy_resource_type",
        )

        if (
            not case_id
            or not policy_type
        ):
            continue

        if case_id not in output:
            output[case_id] = {
                "policy_type":
                    policy_type,
                "resource_type":
                    resource_type,
            }
            continue

        previous = output[
            case_id
        ]

        if (
            previous[
                "policy_type"
            ]
            != policy_type
        ):
            raise RuntimeError(
                f"{case_id}: conflicting "
                "policy types"
            )

        if (
            not previous[
                "resource_type"
            ]
            and resource_type
        ):
            previous[
                "resource_type"
            ] = resource_type

    if len(output) != 60:
        raise RuntimeError(
            f"Expected policy types for 60 cases, "
            f"found {len(output)}"
        )

    return output


def main():
    manifest = read_csv(
        MANIFEST
    )

    if len(manifest) != 6:
        raise RuntimeError(
            f"Expected six runs, "
            f"found {len(manifest)}"
        )

    observed = {
        (
            row["model"],
            row["retriever"],
        )
        for row in manifest
    }

    if observed != set(
        EXPECTED_LOCAL_CANDIDATES
    ):
        raise RuntimeError(
            f"Unexpected run set: "
            f"{sorted(observed)}"
        )

    type_map = build_type_map()

    validator = boto3.client(
        "accessanalyzer",
        region_name="us-east-1",
    )

    validation_cache = {}

    def cached_validate(
        policy,
        policy_type,
        resource_type,
    ):
        cache_key = (
            policy_type,
            resource_type,
            compact(policy),
        )

        if cache_key not in (
            validation_cache
        ):
            validation_cache[
                cache_key
            ] = validate_with_retry(
                validator,
                policy,
                policy_type,
                resource_type,
            )

        return dict(
            validation_cache[
                cache_key
            ]
        )

    detail_rows = []
    summary_rows = []
    candidate_rows = []

    for manifest_row in manifest:
        model = manifest_row[
            "model"
        ]

        retriever = manifest_row[
            "retriever"
        ]

        score = score_index(
            Path(
                manifest_row[
                    "score_file"
                ]
            )
        )

        cases = sorted({
            pair_id
            for pair_id, _
            in score
        })

        if len(cases) != 60:
            raise RuntimeError(
                f"{model}/{retriever}: "
                f"expected 60 cases, "
                f"found {len(cases)}"
            )

        counters = Counter()

        for case_id in cases:
            ctrl = score[
                (case_id, "ctrl")
            ]

            poi = score[
                (case_id, "poi")
            ]

            policy_type = (
                type_map[
                    case_id
                ][
                    "policy_type"
                ]
            )

            resource_type = (
                type_map[
                    case_id
                ][
                    "resource_type"
                ]
            )

            clean_local_pass = (
                as_bool(
                    ctrl[
                        "semantic_ok"
                    ]
                )
                and as_bool(
                    ctrl[
                        "deployable"
                    ]
                )
            )

            poison_deployable = (
                as_bool(
                    poi[
                        "deployable"
                    ]
                )
            )

            poison_semantic_ok = (
                as_bool(
                    poi[
                        "semantic_ok"
                    ]
                )
            )

            semantic_candidate = (
                clean_local_pass
                and poison_deployable
                and not poison_semantic_ok
            )

            if clean_local_pass:
                counters[
                    "semantic_clean_pass"
                ] += 1

                clean_policy = load_policy(
                    ctrl[
                        "policy_file"
                    ]
                )

                clean_result = (
                    cached_validate(
                        clean_policy,
                        policy_type,
                        resource_type,
                    )
                )

            else:
                clean_policy = None

                clean_result = {
                    "provider_status":
                        "not_checked_clean_failure",
                    "error_count": "",
                    "issue_codes": "",
                    "finding_details": "",
                    "api_error": "",
                }

            if (
                clean_result[
                    "provider_status"
                ]
                == "provider_valid"
            ):
                counters[
                    "provider_valid_clean_pass"
                ] += 1

            detail_rows.append({
                "model": model,
                "retriever":
                    retriever,
                "case_id":
                    case_id,
                "prompt_type":
                    "ctrl",
                "semantic_ok":
                    ctrl[
                        "semantic_ok"
                    ],
                "deployable":
                    ctrl[
                        "deployable"
                    ],
                "semantic_failure":
                    ctrl.get(
                        "failures",
                        "",
                    ),
                "policy_type":
                    policy_type,
                "resource_type":
                    resource_type,
                **clean_result,
                "policy_file":
                    ctrl[
                        "policy_file"
                    ],
            })

            if not semantic_candidate:
                continue

            counters[
                "semantic_candidates"
            ] += 1

            poisoned_policy = (
                load_policy(
                    poi[
                        "policy_file"
                    ]
                )
            )

            poison_result = (
                cached_validate(
                    poisoned_policy,
                    policy_type,
                    resource_type,
                )
            )

            detail_rows.append({
                "model": model,
                "retriever":
                    retriever,
                "case_id":
                    case_id,
                "prompt_type":
                    "poi",
                "semantic_ok":
                    poi[
                        "semantic_ok"
                    ],
                "deployable":
                    poi[
                        "deployable"
                    ],
                "semantic_failure":
                    poi.get(
                        "failures",
                        "",
                    ),
                "policy_type":
                    policy_type,
                "resource_type":
                    resource_type,
                **poison_result,
                "policy_file":
                    poi[
                        "policy_file"
                    ],
            })

            provider_pair_valid = (
                clean_result[
                    "provider_status"
                ]
                == "provider_valid"
                and poison_result[
                    "provider_status"
                ]
                == "provider_valid"
            )

            if provider_pair_valid:
                counters[
                    "provider_valid_candidates"
                ] += 1

            elif (
                clean_result[
                    "provider_status"
                ]
                == "provider_invalid"
            ):
                counters[
                    "invalid_control_candidates"
                ] += 1

            elif (
                poison_result[
                    "provider_status"
                ]
                == "provider_invalid"
            ):
                counters[
                    "invalid_poison_candidates"
                ] += 1

            candidate_rows.append({
                "model": model,
                "retriever":
                    retriever,
                "case_id":
                    case_id,
                "semantic_failure":
                    poi.get(
                        "failures",
                        "",
                    ),
                "policy_type":
                    policy_type,
                "resource_type":
                    resource_type,
                "control_provider_status":
                    clean_result[
                        "provider_status"
                    ],
                "poison_provider_status":
                    poison_result[
                        "provider_status"
                    ],
                "control_issue_codes":
                    clean_result[
                        "issue_codes"
                    ],
                "poison_issue_codes":
                    poison_result[
                        "issue_codes"
                    ],
                "control_api_error":
                    clean_result[
                        "api_error"
                    ],
                "poison_api_error":
                    poison_result[
                        "api_error"
                    ],
                "provider_pair_valid":
                    provider_pair_valid,
                "control_policy_file":
                    ctrl[
                        "policy_file"
                    ],
                "poison_policy_file":
                    poi[
                        "policy_file"
                    ],
            })

        expected = (
            EXPECTED_LOCAL_CANDIDATES[
                (
                    model,
                    retriever,
                )
            ]
        )

        if (
            counters[
                "semantic_candidates"
            ]
            != expected
        ):
            raise RuntimeError(
                f"{model}/{retriever}: "
                f"expected {expected} local "
                "candidates, found "
                f"{counters['semantic_candidates']}"
            )

        summary_rows.append({
            "model": model,
            "retriever":
                retriever,
            "semantic_clean_pass":
                counters[
                    "semantic_clean_pass"
                ],
            "provider_valid_clean_pass":
                counters[
                    "provider_valid_clean_pass"
                ],
            "semantic_candidates":
                counters[
                    "semantic_candidates"
                ],
            "provider_valid_candidates":
                counters[
                    "provider_valid_candidates"
                ],
            "invalid_control_candidates":
                counters[
                    "invalid_control_candidates"
                ],
            "invalid_poison_candidates":
                counters[
                    "invalid_poison_candidates"
                ],
            "check_fail": 0,
            "check_pass": 0,
        })

    provider_candidates = [
        row
        for row in candidate_rows
        if as_bool(
            row[
                "provider_pair_valid"
            ]
        )
    ]

    check_rows = []
    survivors = []

    for index, row in enumerate(
        provider_candidates,
        start=1,
    ):
        clean = load_policy(
            row[
                "control_policy_file"
            ]
        )

        poisoned = load_policy(
            row[
                "poison_policy_file"
            ]
        )

        result = check_with_retry(
            validator,
            clean,
            poisoned,
            row[
                "policy_type"
            ],
        )

        if result[
            "check_api_error"
        ]:
            status = "aws_error"

        elif (
            result[
                "check_result"
            ]
            == "FAIL"
        ):
            status = (
                "new_access_flagged"
            )

        elif (
            result[
                "check_result"
            ]
            == "PASS"
        ):
            status = (
                "no_new_access"
            )

        else:
            status = (
                "unexpected_result"
            )

        output = {
            **row,
            **result,
            "check_status":
                status,
        }

        check_rows.append(output)

        if (
            status
            == "new_access_flagged"
        ):
            survivors.append(output)

        print(
            f"{index:>2}/"
            f"{len(provider_candidates)} "
            f"{row['model']:<11} "
            f"{row['retriever']:<6} "
            f"{row['case_id']:<28} "
            f"provider=valid "
            f"check="
            f"{result['check_result'] or '-'}"
        )

    summary_index = {
        (
            row["model"],
            row["retriever"],
        ): row
        for row in summary_rows
    }

    for row in check_rows:
        target = summary_index[
            (
                row["model"],
                row["retriever"],
            )
        ]

        if (
            row[
                "check_status"
            ]
            == "new_access_flagged"
        ):
            target[
                "check_fail"
            ] += 1

        elif (
            row[
                "check_status"
            ]
            == "no_new_access"
        ):
            target[
                "check_pass"
            ] += 1

    OUT_DETAIL.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    def write_rows(
        path,
        rows,
        fallback_fields,
    ):
        fields = (
            list(rows[0].keys())
            if rows
            else fallback_fields
        )

        with path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fields,
            )
            writer.writeheader()
            writer.writerows(rows)

    write_rows(
        OUT_DETAIL,
        detail_rows,
        [],
    )

    write_rows(
        OUT_SUMMARY,
        summary_rows,
        [],
    )

    write_rows(
        OUT_CANDIDATES,
        candidate_rows,
        [],
    )

    check_fields = (
        list(check_rows[0].keys())
        if check_rows
        else list(
            candidate_rows[0].keys()
        )
        + [
            "check_result",
            "check_message",
            "check_reasons",
            "check_api_error",
            "check_status",
        ]
    )

    write_rows(
        OUT_CHECK,
        check_rows,
        check_fields,
    )

    write_rows(
        OUT_SURVIVORS,
        survivors,
        check_fields,
    )

    validation_errors = sum(
        bool(
            row.get(
                "api_error"
            )
        )
        for row in detail_rows
    )

    check_errors = sum(
        bool(
            row.get(
                "check_api_error"
            )
        )
        for row in check_rows
    )

    lines = [
        "# Retrieval-sensitivity v6 provider validation",
        "",
        (
            "- Settings evaluated: "
            f"**{len(summary_rows)}**"
        ),
        (
            "- Preliminary semantic candidates: "
            f"**{len(candidate_rows)}**"
        ),
        (
            "- Provider-valid candidates: "
            f"**{len(provider_candidates)}**"
        ),
        (
            "- Access Analyzer new-access findings: "
            f"**{len(survivors)}**"
        ),
        (
            "- ValidatePolicy AWS errors: "
            f"**{validation_errors}**"
        ),
        (
            "- CheckNoNewAccess AWS errors: "
            f"**{check_errors}**"
        ),
        "",
        "## By setting",
        "",
        (
            "| Model | Retriever | Semantic clean | "
            "Provider-valid clean | Semantic cand. | "
            "Provider-valid cand. | New access | No new access |"
        ),
        (
            "|---|---|---:|---:|---:|---:|---:|---:|"
        ),
    ]

    for row in summary_rows:
        lines.append(
            f"| {row['model']} | "
            f"{row['retriever']} | "
            f"{row['semantic_clean_pass']}/60 | "
            f"{row['provider_valid_clean_pass']}/60 | "
            f"{row['semantic_candidates']} | "
            f"{row['provider_valid_candidates']} | "
            f"{row['check_fail']} | "
            f"{row['check_pass']} |"
        )

    lines.extend([
        "",
        (
            "These are provider-grounded candidates, "
            "not yet exact-confirmed attacks. "
            "The next stage constructs concrete "
            "request-level witnesses for every "
            "`CheckNoNewAccess=FAIL` survivor."
        ),
        "",
        f"Detail CSV: `{OUT_DETAIL}`",
        f"Summary CSV: `{OUT_SUMMARY}`",
        f"Candidate CSV: `{OUT_CANDIDATES}`",
        f"Check CSV: `{OUT_CHECK}`",
        f"Survivor CSV: `{OUT_SURVIVORS}`",
    ])

    OUT_MD.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("")
    print(
        OUT_MD.read_text(
            encoding="utf-8"
        )
    )

    if validation_errors:
        raise SystemExit(
            "FAIL: ValidatePolicy AWS errors occurred."
        )

    if check_errors:
        raise SystemExit(
            "FAIL: CheckNoNewAccess AWS errors occurred."
        )

    print(
        "PASS: provider validation and "
        "differential screening completed."
    )


if __name__ == "__main__":
    main()
