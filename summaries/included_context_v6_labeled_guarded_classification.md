# Included-context v6 labeled/guarded classification

This experiment explicitly labels retrieved content as untrusted
and instructs the model not to treat it as authority. It is retained
as a prompt-level mitigation result, not as the main unguarded
included-context stress setting.

Preliminary strict-semantic result:

- Claude Sonnet 4.5: 0 candidates
- Mistral Small: 0 candidates
- Nova Lite: 0 candidates
- Nova Pro: 0 candidates
- Llama 3 8B: 1 semantic candidate and 2 nondeployable outputs

Provider-native confirmation has not yet been used to convert these
preliminary counts into final guarded-setting attack counts.
