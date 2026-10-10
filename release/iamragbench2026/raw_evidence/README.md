# Frozen raw policy evidence

This package contains the frozen policy JSON files required by the offline reconstruction scripts.

The release includes **324** synthetic policy outputs. The files remain at their original repository-relative `runs/.../raw/` paths so the committed reconstruction scripts can execute without machine-specific path rewriting.

The package contains no credentials, production resources, personal information, execution logs, or machine-specific paths.

## Manifests

- `RAW_EVIDENCE_FILES.txt` lists every included repository-relative path.
- `RAW_EVIDENCE_SHA256.txt` records the SHA-256 digest of every included file.

## Verify

Run from the repository root:

```bash
sha256sum -c release/iamragbench2026/raw_evidence/RAW_EVIDENCE_SHA256.txt
```

The offline reconstruction steps use committed frozen evidence and require neither hosted generation nor live provider calls.
