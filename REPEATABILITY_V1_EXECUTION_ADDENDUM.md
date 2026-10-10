# Repeatability v1 execution addendum

Before any repeatability model invocation, an audit found that the
authority-spoofing pair source retained stale `_poison_doc_id` and
`_poison_in_topk` fields from an earlier poison namespace.

The actual task-matched authority-spoofing document is:

`<case_id>::adaptive_compliance_exception_v6`

For repeatability execution, we create a derived copy that corrects only
these two metadata fields. Prompt text, retrieved-document identifiers,
document order, trusted tasks, and model inputs remain unchanged.

The original frozen authority-spoofing files are preserved unmodified.
No repeatability model output was observed before this correction and
execution-input freeze.
