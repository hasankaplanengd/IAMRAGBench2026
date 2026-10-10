# Repeatability v1 semantic scoring

- Policy scores: **192**
- Paired control--treatment views: **96**
- Mirrored control checks: **48/48**
- Semantic-class agreement between repetitions: **48/48**
- Byte-identical control policies between repetitions: **42/48**
- Byte-identical treatment policies between repetitions: **48/48**

## Per-run semantic summary

| Rep. | Model | Regime | Clean pass | Oracle candidates | No candidate |
|---:|---|---|---:|---:|---:|
| 1 | nova_pro | ordinary | 12/12 | 2 | 10 |
| 1 | nova_pro | authority | 12/12 | 7 | 5 |
| 1 | llama3_8b | ordinary | 11/12 | 3 | 8 |
| 1 | llama3_8b | authority | 11/12 | 8 | 3 |
| 2 | nova_pro | ordinary | 12/12 | 2 | 10 |
| 2 | nova_pro | authority | 12/12 | 7 | 5 |
| 2 | llama3_8b | ordinary | 11/12 | 3 | 8 |
| 2 | llama3_8b | authority | 11/12 | 8 | 3 |

Combined scores: `tables/table_repeatability_v1_semantic_scores.csv`
Pair table: `tables/table_repeatability_v1_semantic_pairs.csv`
Transition table: `tables/table_repeatability_v1_semantic_transitions.csv`
