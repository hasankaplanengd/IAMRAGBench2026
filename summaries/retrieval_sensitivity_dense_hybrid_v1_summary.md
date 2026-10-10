# Retrieval sensitivity: BM25 vs dense vs hybrid

| Retriever | Poison@1 | Poison@3 | Poison@5 | Clean@5 ctrl | Clean@5 poi | Median poison rank |
|---|---:|---:|---:|---:|---:|---:|
| bm25 | 38/60 | 57/60 | 59/60 | 59/60 | 54/60 | 1 |
| dense | 40/60 | 56/60 | 58/60 | 58/60 | 53/60 | 1 |
| hybrid | 43/60 | 57/60 | 59/60 | 59/60 | 54/60 | 1 |

Embedding model: `amazon.titan-embed-text-v2:0`
Detail JSONL: `data/master_e2e_rag_v2/retrieval_sensitivity_dense_hybrid_v1_detail.jsonl`
CSV: `tables/table_retrieval_sensitivity_dense_hybrid_v1.csv`
