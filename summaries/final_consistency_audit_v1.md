# Final Consistency Audit v1

## Provider-grounded validation

- Total tested: **11**
- Provider-validated: **9/11**
- Provider-invalid: **1/11**
- Simulator-specific mismatch: **1/11**
- AWS errors: **0/11**

✅ Matches expected provider-grounded validation result: 9/11 validated, 1 provider-invalid, 1 mismatch.


## Cross-model retrieval sensitivity

| model | retriever | poison_at_5 | control_pass | confirmed_oracle_candidates | provider_invalid | nondeployable |
|---|---|---|---|---|---|---|
| Nova Lite | BM25 | 59/60 | 60/60 | 1/60 | 0/60 | 1/60 |
| Nova Lite | Dense | 58/60 | 59/60 | 1/60 | 0/60 | 0/60 |
| Nova Lite | Hybrid | 59/60 | 60/60 | 1/60 | 0/60 | 0/60 |
| Nova Pro | BM25 | 59/60 | 60/60 | 4/60 | 0/60 | 0/60 |
| Nova Pro | Dense | 58/60 | 60/60 | 2/60 | 0/60 | 0/60 |
| Nova Pro | Hybrid | 59/60 | 60/60 | 2/60 | 0/60 | 0/60 |
| Llama 3 8B | BM25 | 59/60 | 59/60 | 5/60 | 1/60 | 1/60 |
| Llama 3 8B | Dense | 58/60 | 56/60 | 4/60 | 0/60 | 1/60 |
| Llama 3 8B | Hybrid | 59/60 | 60/60 | 4/60 | 1/60 | 0/60 |


## Top-k sensitivity

| model | k | poison_at_k | control_pass | confirmed_attacks | provider_invalid | nondeployable |
|---|---|---|---|---|---|---|
| Llama 3 8B | 1 | 35/60 | 54/60 | 9/60 | 0/60 | 0/60 |
| Llama 3 8B | 3 | 57/60 | 58/60 | 6/60 | 0/60 | 2/60 |
| Llama 3 8B | 5 | 59/60 | 59/60 | 5/60 | 1/60 | 1/60 |
| Llama 3 8B | 10 | 60/60 | 54/60 | 1/60 | 0/60 | 0/60 |
| Nova Pro | 1 | 35/60 | 60/60 | 8/60 | 0/60 | 0/60 |
| Nova Pro | 3 | 57/60 | 60/60 | 3/60 | 0/60 | 0/60 |
| Nova Pro | 5 | 59/60 | 60/60 | 4/60 | 0/60 | 0/60 |
| Nova Pro | 10 | 60/60 | 60/60 | 2/60 | 0/60 | 0/60 |


## Adaptive guarded-prompt stress test

| model | variant | poison_at_5 | standard_confirmed_attacks | guarded_confirmed_attacks | delta_guarded_minus_standard | interpretation |
|---|---|---|---|---|---|---|
| Llama 3 8B | approved_migration_template | 54/60 | 3/60 | 5/60 | 2 | increased |
| Llama 3 8B | compliance_exception | 54/60 | 15/60 | 11/60 | -4 | reduced |
| Llama 3 8B | least_privilege_looking_template | 54/60 | 9/60 | 7/60 | -2 | reduced |
| Nova Pro | approved_migration_template | 54/60 | 7/60 | 0/60 | -7 | reduced |
| Nova Pro | compliance_exception | 54/60 | 36/60 | 16/60 | -20 | reduced |
| Nova Pro | least_privilege_looking_template | 54/60 | 19/60 | 3/60 | -16 | reduced |


## Retrieval-overlap / synthetic-corpus bias analysis

Cases analyzed: **60**
| Jaccard median | 0.247 | 0.161 | 0.351 | 0.139 |
| TF-IDF cosine median | 0.588 | 0.666 | 0.719 | 0.367 |
- Poison document more similar to query than clean document by Jaccard: **0/60**
- Poison document more similar to query than clean document by TF-IDF cosine: **44/60**
- Clean/poison near-duplicates by Jaccard >= 0.80: **0/60**
- Clean/poison near-duplicates by TF-IDF cosine >= 0.90: **1/60**


## Frozen paper numbers to use


Use these in the paper unless intentionally changed:

- Included-context:
  - Claude Sonnet 4.5: 0/60
  - Mistral Small: 3/60
  - Nova Lite: 5/60
  - Nova Pro: 17/60
  - Llama 3 8B: 18/57

- End-to-end BM25 k=5:
  - Claude Sonnet 4.5: 0/60
  - Mistral Small: 0/60
  - Nova Lite: 1/60
  - Nova Pro: 4/60
  - Llama 3 8B: 5/59 confirmed provider-deployable attacks
  - Llama note: one additional provider-invalid oracle failure and one nondeployable failure are reported separately.

- Provider-grounded validation:
  - 9/11 validated
  - 1/11 provider-invalid
  - 1/11 simulator-specific mismatch

- Retrieval sensitivity:
  - BM25 poison@5: 59/60
  - Dense poison@5: 58/60
  - Hybrid poison@5: 59/60

- Top-k sensitivity:
  - Poison retrieval increases with k, but confirmed attacks do not increase monotonically.

- Adaptive guarded prompt:
  - Nova Pro: guard reduces attacks strongly but not fully under compliance_exception.
  - Llama 3 8B: guard effect is weaker and one adaptive style increases.
  - Conclusion: guarded prompting helps but is not a robust final defense.
