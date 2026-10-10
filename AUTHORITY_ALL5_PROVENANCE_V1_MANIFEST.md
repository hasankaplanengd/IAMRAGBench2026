# Authority-spoofing all-five provenance v1

## Scope

This file records provenance for a post hoc model-coverage extension using the
previously frozen authority-spoofing inputs. The extension itself was run after
the original Nova Pro and Llama 3 8B authority-spoofing stress test; it should
not be described as preregistered. The input condition, prompts, retrieval
contexts, and generation configuration are recorded so reviewers can inspect
that the extension used the same authority-spoofing setup for the three
additional model classes.

## Result linked to this provenance

Original two-model authority-spoofing stress test:

- Models: Nova Pro and Llama 3 8B
- Provider-valid clean controls: 116
- Provider-valid semantic candidates: 84
- Exact-confirmed attacks: 74/116 (63.79%)
- Provider-corroborated cases including two simulator-unresolved KMS cases:
  76/116 (65.52%)

Missing-three extension:

- Models: Claude Sonnet 4.5, Mistral Small, and Amazon Nova Lite
- Provider-valid clean controls: 178
- Provider-valid semantic candidates: 45
- Exact-confirmed attacks: 41/178 (23.03%)

Combined all-five authority-spoofing result:

- Provider-valid clean controls: 294
- Provider-valid semantic candidates: 129
- Exact-confirmed attacks: 115/294 (39.12%)
- Provider-corroborated cases including the original two simulator-unresolved
  KMS cases: 117/294 (39.80%)

## Hashed provenance

The file `tables/authority_all5_provenance_hashes_v1.csv` records SHA-256
hashes for:

- the authority-spoofing corpus, queries, retrieval details, and prompt files;
- all five authority-spoofing generation configurations;
- the generation runner and semantic scoring/oracle scripts;
- exact-witness source scripts;
- original two-model authority result tables and raw outputs;
- missing-three extension raw outputs;
- promoted all-five extension result tables and summaries.

## Successful missing-three raw output directories

The successful missing-three generation runs are:

- `runs/20260729_135654_us_anthropic_claude_sonnet_4_5_20250929_v1_0`
- `runs/20260729_140303_mistral_mistral_small_2402_v1_0`
- `runs/20260729_140822_amazon_nova_lite_v1_0`

Earlier failed no-credential development attempts are not part of this
provenance record and are not part of the public reproduction path.

## Reporting note

The original two-model authority-spoofing result remains the primary frozen
stress-test headline. The all-five result is a model-coverage robustness
extension using the same previously frozen authority-spoofing inputs.
