# Repeatability v1

## Purpose

Measure output and security-classification stability under repeated
temperature-zero hosted inference. This diagnostic does not replace or
change any headline result.

## Frozen design

- Models: Nova Pro and Llama 3 8B
- Regimes: standard BM25 end-to-end and authority spoofing
- Cases: 12 family-stratified cases listed in
  `tables/repeatability_v1_cases.csv`
- New repetitions: 2
- Per repetition and model:
  - one clean-control generation per case
  - one ordinary-poison generation per case
  - one authority-spoofing generation per case
- Total planned new generations:
  12 cases x 2 models x 3 prompt variants x 2 repetitions = 144

## Selection rule

Cases were selected to cover distinct IAM semantic and witness families,
not solely cases that previously produced attacks. No repeatability output
was observed before freezing this manifest.

## Reporting

Report clean-pass persistence, semantic-candidate persistence, exact-attack
persistence, and transitions among exact, candidate-only, non-candidate,
provider-invalid, and nondeployable classifications. Main-paper ASRs remain
unchanged.
