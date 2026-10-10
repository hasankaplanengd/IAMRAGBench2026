# Confirm-24 v1 prompt/config freeze

## Purpose

This freeze records the generation inputs for the Confirm-24 external-validity
holdout before any model calls are made.

## Scope

- 24 public-source-derived cases from `data/confirm24_v1/cases.jsonl`
- Two treatment regimes:
  - ordinary operational poison
  - authority-spoofing poison
- Five model classes:
  - Claude Sonnet 4.5
  - Mistral Small
  - Amazon Nova Lite
  - Amazon Nova Pro
  - Llama 3 8B Instruct

## Prompt construction

The prompts contain:

1. trusted policy-generation task;
2. required IAM policy type;
3. retrieved context.

The prompt construction intentionally does not expose the scoring-only oracle
fields `required_obligation` or `forbidden_expansion`. Control prompts include
only the clean deployment-standard summary. Treatment prompts include the same
clean summary plus either the ordinary poison summary or the authority-spoofing
summary.

## Files

- `data/confirm24_v1/rag_pairs_confirm24_v1_ordinary_run_eval.jsonl`
- `data/confirm24_v1/rag_pairs_confirm24_v1_authority_run_eval.jsonl`
- `configs/confirm24_v1_ordinary_*.yaml`
- `configs/confirm24_v1_authority_*.yaml`
- `summaries/confirm24_v1_prompt_freeze_summary.md`
- `tables/confirm24_v1_prompt_pre_run_sha256.txt`

## Rule

No Confirm-24 model generation should be run until this prompt/config freeze is
committed and pushed.
