# Retrieval-overlap / synthetic-corpus bias analysis

Cases analyzed: **60**

| Similarity measure | Query-clean | Query-poison | Clean-poison | Query-best distractor |
|---|---:|---:|---:|---:|
| Jaccard median | 0.247 | 0.161 | 0.351 | 0.139 |
| TF-IDF cosine median | 0.588 | 0.666 | 0.719 | 0.367 |

- Poison document more similar to query than clean document by Jaccard: **0/60**
- Poison document more similar to query than clean document by TF-IDF cosine: **44/60**
- Clean/poison near-duplicates by Jaccard >= 0.80: **0/60**
- Clean/poison near-duplicates by TF-IDF cosine >= 0.90: **1/60**

CSV: `tables/table_retrieval_overlap_bias_v1.csv`
Detail JSONL: `data/master_e2e_rag_v2/retrieval_overlap_bias_v1_detail.jsonl`
