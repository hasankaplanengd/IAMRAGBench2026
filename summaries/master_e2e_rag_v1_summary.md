# master_e2e_rag_v1 summary

- Cases: 60
- Queries: 60
- Clean relevant docs: 60
- Strong poisoned docs: 60
- Distractor docs: 600
- Total corpus docs: 720

Purpose: this corpus converts the 60-case IAM semantic benchmark into an end-to-end RAG setting. The next step is to run retrieval over this corpus and measure whether the poisoned document is retrieved at k=1,3,5 before any model generation.
