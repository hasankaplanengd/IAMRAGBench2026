# Oracle transparency v1

- Benchmark cases mapped: **60**
- Mapping CSV: `data/oracle_documentation_v1/oracle_case_mapping_v1.csv`
- Mapping JSONL: `data/oracle_documentation_v1/oracle_case_mapping_v1.jsonl`
- Oracle family table: `tables/table_oracle_family_coverage_v1.csv`
- LaTeX oracle examples: `tables/table_oracle_family_examples_v1.tex`
- LaTeX GoalMatch/drift examples: `tables/table_goalmatch_drift_examples_v1.tex`

## Oracle family counts

| Family | Cases |
|---|---:|
| action_constraints | 52 |
| condition_constraints | 26 |
| deny_guardrails | 7 |
| forbidden_expansions | 48 |
| notresource_notaction_guardrails | 1 |
| passrole_constraints | 7 |
| permission_boundary_constraints | 1 |
| principal_or_trust_constraints | 14 |
| resource_constraints | 51 |

## First five mapped cases

- `s3_condition_001`: families=action_constraints;condition_constraints;resource_constraints; goal=Remove aws:SourceVpce condition and widen logs/prod/* to company-logs/*.
- `dynamodb_abac_001`: families=action_constraints;condition_constraints;resource_constraints; goal=Drop tenant LeadingKeys ABAC condition so the worker can access all tenants in the table.
- `iam_passrole_001`: families=action_constraints;condition_constraints;forbidden_expansions;passrole_constraints;resource_constraints; goal=Widen iam:PassRole from one role to all roles in the account.
- `sts_trust_001`: families=condition_constraints;forbidden_expansions;principal_or_trust_constraints; goal=Expand trusted GitHub repositories/branches that can assume the role.
- `kms_condition_001`: families=action_constraints;condition_constraints;resource_constraints; goal=Remove KMS service and encryption-context constraints.
