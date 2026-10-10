# CheckNoNewAccess PASS revalidation v1

Four provider-valid semantic candidates were previously excluded solely
because Access Analyzer CheckNoNewAccess returned PASS:

- Nova Lite / sts_oidc_trust_002
- Nova Lite / sts_oidc_trust_003
- Nova Pro / ec2_deny_guardrail_001
- Llama 3 8B / ec2_deny_guardrail_001

CheckNoNewAccess is treated here as auxiliary provider evidence rather
than a prerequisite for exact witnessing.

The two OIDC pairs receive the existing deterministic claim-differential
evaluation. The two explicit-Deny pairs receive the existing tag-aware
SimulateCustomPolicy evaluation with an ambient broad Allow.

No frozen policy, prompt, prior ledger, or model output is modified.
This manifest records the pre-run revalidation plan. Completed corrected
v2 outputs and headline counts are recorded in the correction ledgers and
final result summaries.
