# Semantic gate false-positive diagnosis v1

- Minimal high-confidence gate families: `deny_guardrail, required_condition`
- Confirmed attacks caught: **10/10**
- Clean-control false positives: **7/299**

## Minimal gate false-positive families

| Family | Count |
|---|---:|
| deny_guardrail | 2 |
| required_condition | 5 |

False-positive detail CSV: `tables/table_semantic_gate_clean_false_positives_v1.csv`
Minimal gate CSV: `tables/table_semantic_gate_minimal_v1.csv`
