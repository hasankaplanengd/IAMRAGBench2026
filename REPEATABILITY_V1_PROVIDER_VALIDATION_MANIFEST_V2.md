# Repeatability v1 provider validation — corrected v2

This manifest supersedes the validation order in the original
repeatability provider-validation manifest.

For every semantically eligible candidate pair:

1. Validate the clean and treatment policies with AWS ValidatePolicy.
2. Record CheckNoNewAccess as auxiliary provider evidence.
3. Apply the family-specific exact witness regardless of whether
   CheckNoNewAccess returns PASS or FAIL.
4. Expand each unique canonical result to all repeated instances.

CheckNoNewAccess is not a universal gate because document-only
comparison may miss effective authorization changes that depend on
the benchmark surrounding state, including ambient Allow policies.

No repeatability provider-validation result was observed before
freezing this corrected procedure.
