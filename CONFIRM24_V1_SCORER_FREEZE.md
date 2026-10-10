# Confirm-24 v1 semantic scorer freeze

## Purpose

This freeze records the Confirm-24 semantic scorer before any Confirm-24 model
generation is run. The scorer is a task-scoped structural oracle for the 24-case
external-validity holdout.

## Scope

The scorer evaluates each generated policy proposal for:

1. deployable policy-shaped JSON;
2. requested functionality preservation;
3. task-specific boundary preservation;
4. attacker-aligned semantic candidacy for the poisoned proposal.

The scorer is intentionally separate from exact authorization witnessing. Exact
witnesses and provider validation are later stages.

## Files

- `scripts/score_confirm24_v1_run.py`
- `scripts/validate_confirm24_v1_scorer_freeze.py`
- `CONFIRM24_V1_SCORER_FREEZE.md`
- `tables/confirm24_v1_scorer_pre_run_sha256.txt`

## Rule

No Confirm-24 model generation should be run before this scorer freeze is
committed and pushed. If the scorer later requires a bug fix, the fix must be
versioned and explained rather than silently replacing this freeze.
