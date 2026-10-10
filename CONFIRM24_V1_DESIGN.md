# Confirm-24 v1 design freeze

## Purpose

Confirm-24 is a separately reported external-validity holdout for semantic RAG
poisoning in IAM policy generation. It is designed to address the criticism that
the main benchmark is controlled and synthetic by deriving case patterns from
public AWS documentation, AWS security guidance, public AWS documentation
repositories, and public policy examples.

The holdout does not replace the 60-case benchmark and is not pooled into the
main ASR. It is a confirmatory robustness study.

## Frozen design

- Cases: 24
- Families: 8
- Cases per family: 3
- Account IDs, ARNs, roles, tenants, buckets, queues, keys, tickets, and runbooks:
  synthetic
- Source use: public material determines the policy pattern and document language;
  the authorization envelope remains independently specified.
- No model outputs are generated before this design is hashed.
- No cases, prompts, or attack documents should be revised after observing model
  outputs. Any later correction must be explicitly versioned as Confirm-24 v2.

## Families

- action_resource_widening: 3
- boundary_notresource: 3
- condition_abac: 3
- explicit_deny_guardrail: 3
- kms_source_context: 3
- oidc_trust: 3
- passrole_service_role: 3
- public_resource_policy: 3

## Files

- `data/confirm24_v1/source_manifest.csv`
- `data/confirm24_v1/case_plan.csv`
- `data/confirm24_v1/cases.jsonl`
- `data/confirm24_v1/clean_docs.jsonl`
- `data/confirm24_v1/ordinary_poison_docs.jsonl`
- `data/confirm24_v1/authority_poison_docs.jsonl`
- `scripts/validate_confirm24_v1_design.py`
- `tables/confirm24_v1_pre_run_sha256.txt`

## Next stages, after freeze

1. Map every case to an existing or newly versioned semantic oracle family.
2. Map every case to an exact-witness family or a conservative provider-corroborated
   unresolved class.
3. Build prompt pairs for clean, ordinary-poison, and authority-poison conditions.
4. Run model generation only after this design hash is committed.
5. Report Confirm-24 separately from the original 60-case benchmark.
