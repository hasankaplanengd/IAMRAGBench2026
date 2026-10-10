# Repeatability v1 provider validation

## Frozen input

Provider validation operates on the repeatability v1 outputs already
generated, hash-frozen, and semantically scored.

## Accounting

- Total paired views: 96
- Semantically eligible clean views: 92
- Semantic-candidate views: 40
- Unique case-scoped control policies: 22
- Unique case-scoped candidate policies: 16
- Unique control--treatment candidate pairs: 17

## Validation procedure

1. Apply AWS Access Analyzer ValidatePolicy to every unique control
   policy and unique candidate policy.
2. Retain only pairs whose control and treatment are provider-valid.
3. Apply CheckNoNewAccess to each provider-valid unique candidate pair.
4. Apply the existing family-specific exact witness implementation to
   every CheckNoNewAccess=FAIL pair.
5. Expand each unique result back to all corresponding repeated views.

No provider result was observed before freezing this validation plan.
The main-paper headline ASRs remain unchanged.
