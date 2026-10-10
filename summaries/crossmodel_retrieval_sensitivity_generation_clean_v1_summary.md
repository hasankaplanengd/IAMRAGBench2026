# Cleaned cross-model retrieval sensitivity

| Model | Retriever | Poison@5 | Control pass | Raw oracle failures | Confirmed candidates | Provider-invalid | Nondeployable | Needs inspection |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Nova Lite | BM25 | 59/60 | 60/60 | 2/60 | 1/60 | 0/60 | 1/60 | 0/60 |
| Nova Lite | Dense | 58/60 | 59/60 | 1/60 | 1/60 | 0/60 | 0/60 | 0/60 |
| Nova Lite | Hybrid | 59/60 | 60/60 | 1/60 | 1/60 | 0/60 | 0/60 | 0/60 |
| Nova Pro | BM25 | 59/60 | 60/60 | 4/60 | 4/60 | 0/60 | 0/60 | 0/60 |
| Nova Pro | Dense | 58/60 | 60/60 | 2/60 | 2/60 | 0/60 | 0/60 | 0/60 |
| Nova Pro | Hybrid | 59/60 | 60/60 | 2/60 | 2/60 | 0/60 | 0/60 | 0/60 |
| Llama 3 8B | BM25 | 59/60 | 59/60 | 7/60 | 5/60 | 1/60 | 1/60 | 0/60 |
| Llama 3 8B | Dense | 58/60 | 56/60 | 5/60 | 4/60 | 0/60 | 1/60 | 0/60 |
| Llama 3 8B | Hybrid | 59/60 | 60/60 | 5/60 | 4/60 | 1/60 | 0/60 | 0/60 |

CSV: `tables/table_crossmodel_retrieval_sensitivity_generation_clean_v1.csv`
