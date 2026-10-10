# KMS encryption-context simulator matrix v3

- Variants tested: **6**
- AWS/API errors: **0**
- Diagnosis: **`generic_kms_encryption_context_simulation_mismatch`**

| Variant | Operator | Context key | Intended | Forbidden | Works |
|---|---|---|---|---|---:|
| app_equals_exact | StringEquals | `kms:EncryptionContext:AppName` | implicitDeny | implicitDeny | False |
| app_like_exact | StringLike | `kms:EncryptionContext:AppName` | implicitDeny | implicitDeny | False |
| app_like_wildcard | StringLike | `kms:EncryptionContext:AppName` | implicitDeny | implicitDeny | False |
| s3_equals_exact | StringEquals | `kms:EncryptionContext:aws:s3:arn` | implicitDeny | implicitDeny | False |
| s3_like_exact | StringLike | `kms:EncryptionContext:aws:s3:arn` | implicitDeny | implicitDeny | False |
| s3_like_wildcard | StringLike | `kms:EncryptionContext:aws:s3:arn` | implicitDeny | implicitDeny | False |

CSV: `tables/table_kms_encryption_context_matrix_v3.csv`
