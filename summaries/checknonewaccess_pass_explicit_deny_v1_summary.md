# CheckNoNewAccess PASS explicit-Deny revalidation

- Candidates evaluated: **2**
- Prior CheckNoNewAccess results: **2/2 PASS**
- Exact request-level authorization deltas: **2/2**

Each test composes the generated policy with an ambient broad Allow and varies the `aws:ResourceTag/Environment` context.

Detail CSV: `tables/table_checknonewaccess_pass_explicit_deny_v1_detail.csv`
Candidate CSV: `tables/table_checknonewaccess_pass_explicit_deny_v1_candidates.csv`
