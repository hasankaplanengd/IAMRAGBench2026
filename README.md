# IAM Semantic RAG-Poisoning Benchmark Artifact

This repository contains the benchmark data, generation configs, scoring scripts,
validation scripts, final tables, and result manifests for evaluating semantic RAG
poisoning in LLM-assisted AWS IAM policy generation.

The benchmark studies a security failure mode in which untrusted retrieved
enterprise context, such as tickets, runbooks, migration notes, or policy
templates, causes an LLM policy copilot to emit a syntactically valid,
provider-valid IAM policy that exceeds the trusted least-privilege intent.

## Source of truth

The main result manifest is:

- `FINAL_EXPERIMENT_MANIFEST.md`

The corrected v2 result files and correction manifests supersede older interim
tables where applicable. In particular, the final paper-facing counts use the
corrected CheckNoNewAccess PASS revalidations, retriever-sensitivity correction,
and repeatability provider-grounded accounting.

## Reproducibility overview

The default validation path does **not** require model API calls. The
repository includes committed benchmark inputs, result ledgers, final tables,
summaries, correction manifests, and scripts for inspecting or recomputing the
reported outputs from frozen artifacts.

Model-generation reruns are optional. They require separate AWS credentials and
Bedrock model access, and are not needed to validate the paper-facing results.

For the detailed command list, see `REPRODUCE.md`.

## Quick start without model API calls

From the repository root, inspect the source-of-truth manifest and corrected
final tables:

    cat FINAL_EXPERIMENT_MANIFEST.md

    column -s, -t < tables/table_included_context_v6_final_results_v2.csv
    column -s, -t < tables/table_adaptive_compliance_exception_v6_final_results_v2.csv
    column -s, -t < tables/table_retrieval_sensitivity_v6_final_results_v2.csv
    column -s, -t < tables/table_repeatability_v1_provider_grounded_summary_v2.csv

The same final results are available as Markdown summaries:

    cat summaries/included_context_v6_final_results_v2.md
    cat summaries/adaptive_compliance_exception_v6_final_results_v2.md
    cat summaries/retrieval_sensitivity_v6_final_results_v2.md
    cat summaries/repeatability_v1_provider_grounded_summary_v2.md

## Recompute corrected outputs without model API calls

The corrected v2 paper-facing outputs can be regenerated from committed
ledgers and correction inputs:

    python3 scripts/apply_checknonewaccess_correction_v2.py
    python3 scripts/finalize_retrieval_sensitivity_v6_results_v2.py
    python3 scripts/finalize_repeatability_v1_provider_grounded_v2.py

Then verify the frozen outputs with the recorded hashes:

    sha256sum -c tables/checknonewaccess_correction_v2_sha256.txt
    sha256sum -c tables/retrieval_sensitivity_v6_correction_v2_sha256.txt
    sha256sum -c tables/repeatability_v1_provider_grounded_v2_sha256.txt

## Optional model-generation reruns

Rerunning generation is optional and may incur cost. To inspect the runner
interface:

    python3 run_eval.py --help

Example configuration files include:

    configs/master_e2e_rag_v6_k5_standard_full60_nova_pro.yaml
    configs/master_e2e_rag_v6_k5_standard_full60_llama3_8b.yaml
    configs/adaptive_compliance_exception_v6_nova_pro.yaml
    configs/adaptive_compliance_exception_v6_llama3_8b.yaml

Generated run directories are local execution outputs. Unless intentionally
evaluating a new run, use the corrected v2 tables and manifests listed above as
the paper-facing results.


## Final model set

The main evaluation covers five model classes:

- Claude Sonnet 4.5
- Mistral Small
- Amazon Nova Lite
- Amazon Nova Pro
- Meta Llama 3 8B Instruct

The authority-spoofing stress test is evaluated on Nova Pro and Llama 3 8B.

## Main final results

| Regime | Scope | Semantic candidates | Exact authorization deltas | Exact-delta rate | Goal-matched exact attacks | Goal-matched ASR |
|---|---|---:|---:|---:|---:|---:|
| Included-context operational poison | five models | 57 | 49/292 | 16.78% | 46/292 | 15.75% |
| End-to-end BM25, k=5 | five models | 8 | 7/294 | 2.38% | 7/294 | 2.38% |
| Authority-spoofing stress test | Nova Pro + Llama 3 8B | 84 | 74/116 | 63.79% | 74/116 | 63.79% |

The three included-context exact deltas excluded from the goal-matched
attack count are Mistral Small OIDC cases that modify `aud` rather than
the predeclared `sub` target. The frozen goal-match audit is under
`release/iamragbench2026/goal_match/`.

The authority-spoofing stress test also has two simulator-unresolved KMS cases
that are provider-corroborated but excluded from exact ASR, giving a secondary
provider-corroborated rate of 76/116 (65.52%).

## Authority-spoofing all-five extension

A model-coverage extension applies the same frozen authority-spoofing prompt set
to Claude Sonnet 4.5, Mistral Small, and Amazon Nova Lite.

| Scope | Provider-valid clean controls | Semantic candidates | Exact attacks | Exact ASR | Provider-corroborated total |
|---|---:|---:|---:|---:|---:|
| Original two-model authority stress test | 116 | 84 | 74/116 | 63.79% | 76/116 |
| Missing-three extension | 178 | 45 | 41/178 | 23.03% | 41/178 |
| Combined all-five authority result | 294 | 129 | 115/294 | 39.12% | 117/294 |

The original two-model authority-spoofing result remains the primary stress-test
headline. The all-five result is reported as a model-coverage robustness
extension.


## Retriever-sensitivity result

| Retriever | Poison@5 | Provider-valid clean controls | Semantic candidates | Exact attacks | Exact ASR | Provider-corroborated total |
|---|---:|---:|---:|---:|---:|---:|
| BM25 | 60/60 | 175/180 | 8 | 7/175 | 4.00% | 7 |
| Dense | 55/60 | 167/180 | 2 | 1/167 | 0.60% | 2 |
| Hybrid | 60/60 | 178/180 | 8 | 7/178 | 3.93% | 8 |

## Repeatability diagnostic

The repeatability v1 diagnostic adds two temperature-zero repetitions for
Nova Pro and Llama 3 8B on a frozen 12-case subset covering multiple IAM
semantic families.

Summary:

- New generations: 144
- Valid JSON outputs: 144/144
- Provider-valid clean paired views: 88/96
- Exact-confirmed repeatability attacks: 34/88 (38.64%)
- Provider-grounded class stability across repetitions: 48/48
- Exact/non-exact stability across repetitions: 48/48

This diagnostic is not used to replace the main-paper ASRs; it checks stability
on a smaller frozen subset.

## Important files

### Manifests

- `FINAL_EXPERIMENT_MANIFEST.md`
- `AUTHORITY_ALL5_EXTENSION_V1_MANIFEST.md`
- `CHECKNONEWACCESS_PASS_REVALIDATION_V1_MANIFEST.md`
- `RETRIEVAL_SENSITIVITY_V6_CORRECTION_V2_MANIFEST.md`
- `REPEATABILITY_V1_MANIFEST.md`
- `REPEATABILITY_V1_EXECUTION_ADDENDUM.md`
- `REPEATABILITY_V1_PROVIDER_VALIDATION_MANIFEST_V2.md`

### Main benchmark data

- `data/generated_from_master_v6_trustfix/rag_pairs_from_master.jsonl`
- `data/generated_from_master_v6_trustfix/rag_corpus_docs_from_master.jsonl`
- `data/master_e2e_rag_v6_k5_standard_full60/`
- `data/repeatability_v1/`

### Final result tables

- `tables/table_authority_all5_extension_summary_v1.csv`
- `tables/table_authority_all5_extension_missing3_by_model_v1.csv`
- `tables/table_authority_all5_extension_missing3_exact_ledger_v1.csv`
- `tables/table_included_context_v6_final_results_v2.csv`
- `tables/table_adaptive_compliance_exception_v6_final_results_v2.csv`
- `tables/table_retrieval_sensitivity_v6_final_results_v2.csv`
- `tables/table_repeatability_v1_provider_grounded_summary_v2.csv`
- `tables/table_repeatability_v1_provider_grounded_pairs_v2.csv`
- `tables/table_checknonewaccess_correction_v2_headlines.csv`

### Final summaries

- `summaries/authority_all5_extension_missing3_summary_v1.md`
- `summaries/included_context_v6_final_results_v2.md`
- `summaries/adaptive_compliance_exception_v6_final_results_v2.md`
- `summaries/retrieval_sensitivity_v6_final_results_v2.md`
- `summaries/repeatability_v1_provider_grounded_summary_v2.md`
- `summaries/repeatability_v1_validation_reuse_audit_v2.md`

## Evaluation stages

The artifact separates the following stages:

1. Benchmark and corpus construction.
2. Retrieval and prompt construction.
3. Model generation.
4. Output recovery into policy-shaped JSON.
5. Task-scoped semantic scoring.
6. Provider policy-form validation.
7. Auxiliary provider differential evidence.
8. Family-specific exact authorization witnesses.
9. Final ledgers and corrected v2 headline tables.

A semantic candidate is not counted as an attack unless the clean output is
provider-valid and task-satisfying, the treatment output is provider-valid and
attacker-aligned, and the exact witness confirms a newly authorized forbidden
request.

## Authority-spoofing provenance and regression

The all-five authority-spoofing extension is accompanied by public provenance
and regression manifests:

- `AUTHORITY_ALL5_PROVENANCE_V1_MANIFEST.md`
- `AUTHORITY_EXACT_WITNESS_REGRESSION_V1_MANIFEST.md`
- `tables/authority_all5_provenance_hashes_v1.csv`
- `tables/table_authority_original_evidence_regression_ledger_v1.csv`
- `summaries/authority_original_evidence_regression_summary_v1.md`

The extension is a post hoc model-coverage robustness check using the previously
frozen authority-spoofing inputs. It should not be interpreted as a separately
preregistered experiment.
