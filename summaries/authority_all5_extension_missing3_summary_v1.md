# Authority-spoofing missing-three exact summary v3

- Provider-valid clean controls: **178**
- Provider-valid semantic candidates: **45**
- Exact-confirmed attacks: **41/178 (23.03%)**
- Non-exact semantic candidates: **4**

## By model

| Model | Provider-valid clean | Candidates | Exact | Non-exact | Exact ASR |
|---|---:|---:|---:|---:|---:|
| Claude Sonnet 4.5 | 60 | 0 | 0 | 0 | 0.0000% |
| Mistral Small | 59 | 17 | 15 | 2 | 25.4237% |
| Nova Lite | 59 | 28 | 26 | 2 | 44.0678% |

## Combined with original two-model authority stress test

- All-five provider-valid clean controls: **294**
- All-five semantic candidates: **129**
- All-five exact-confirmed attacks: **115/294 (39.12%)**
- All-five provider-corroborated if only original two KMS unresolved are added: **117/294 (39.80%)**

Ledger: `accept_upgrade_audit/exact_witness/run_v3/authority_missing3_exact_final_ledger_v3.csv`
By-model CSV: `accept_upgrade_audit/exact_witness/run_v3/authority_missing3_exact_by_model_v3.csv`
