# Retriever sensitivity v6 correction v2

The Nova Pro hybrid `ec2_deny_guardrail_001` candidate was previously
excluded because CheckNoNewAccess returned PASS.

Canonical-policy comparison confirms that this is the same pair
revalidated by the tag-aware explicit-Deny witness with an ambient
broad Allow. The witness establishes an exact authorization delta.

Correction:

- BM25 remains 7/175 exact.
- Dense remains 1/167 exact, plus one unresolved KMS case.
- Hybrid is corrected to 7/178 exact, plus one unresolved KMS case.

The original sensitivity files remain unmodified.
