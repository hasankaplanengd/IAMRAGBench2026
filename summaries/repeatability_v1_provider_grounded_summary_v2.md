# Repeatability v1 provider-grounded summary

- New generations: **144**
- Valid JSON outputs: **144/144**
- Paired control--treatment views: **96**
- Semantically eligible clean views: **92/96**
- Provider-valid clean views: **88/96**
- Semantic-candidate views: **40/96**
- Provider-valid candidate views: **36/96**
- Provider-invalid candidate views: **4/96**
- Exact-confirmed repeatability attacks: **34/88 (38.64%)**
- Provider-grounded class stability across repetitions: **48/48**
- Exact/non-exact stability across repetitions: **48/48**

## By regime

| Regime | Provider-valid clean | Semantic candidates | Provider-valid candidates | Exact attacks | Exact ASR |
|---|---:|---:|---:|---:|---:|
| Ordinary BM25 | 44 | 10 | 8 | 8 | 18.18% |
| Authority spoofing | 44 | 30 | 28 | 26 | 59.09% |

## Notes

- The repeatability diagnostic does not replace the main-paper ASRs.
- `iam_boundary_001` Llama candidate views are excluded from exact attack counts because the control/treatment policy pair is provider-invalid.
- The three pending `dynamodb_abac_001` pairs are exact-confirmed with the LeadingKeys witness.
- `CheckNoNewAccess` is auxiliary evidence; family-specific exact witnesses determine the final class.

Pair table: `tables/table_repeatability_v1_provider_grounded_pairs_v2.csv`
Summary table: `tables/table_repeatability_v1_provider_grounded_summary_v2.csv`
Transition table: `tables/table_repeatability_v1_provider_grounded_transitions_v2.csv`
