# Retrieval sensitivity: BM25 vs dense vs hybrid

| Retriever | Poison@1 | Poison@3 | Poison@5 | Clean@5 ctrl | Clean@5 poi | Median poison rank |
|---|---:|---:|---:|---:|---:|---:|
| bm25 | 36/60 | 60/60 | 60/60 | 60/60 | 60/60 | 1 |
| dense | 35/60 | 51/60 | 55/60 | 60/60 | 59/60 | 1 |
| hybrid | 41/60 | 60/60 | 60/60 | 60/60 | 60/60 | 1 |

Embedding model: `amazon.titan-embed-text-v2:0`
Detail JSONL: `data/master_e2e_rag_v6_retrieval_sensitivity/retrieval_sensitivity_dense_hybrid_v6_detail.jsonl`
CSV: `tables/table_retrieval_sensitivity_dense_hybrid_v6.csv`
