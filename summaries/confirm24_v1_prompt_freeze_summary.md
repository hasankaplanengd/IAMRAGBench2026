# Confirm-24 v1 prompt/config freeze

- Model calls: **not run in this step**
- Cases: **24**
- Families: **8**
- Ordinary-poison prompt pairs: **24**
- Authority-spoofing prompt pairs: **24**
- Generation configs: **10**

## Models

- `claude` / Claude Sonnet 4.5: `us.anthropic.claude-sonnet-4-5-20250929-v1:0`
- `mistral_small` / Mistral Small: `mistral.mistral-small-2402-v1:0`
- `nova_lite` / Nova Lite: `amazon.nova-lite-v1:0`
- `nova_pro` / Nova Pro: `amazon.nova-pro-v1:0`
- `llama3_8b` / Llama 3 8B: `meta.llama3-8b-instruct-v1:0`

## Family counts

- `action_resource_widening`: 3
- `boundary_notresource`: 3
- `condition_abac`: 3
- `explicit_deny_guardrail`: 3
- `kms_source_context`: 3
- `oidc_trust`: 3
- `passrole_service_role`: 3
- `public_resource_policy`: 3

## Prompt construction

The generation prompt includes the trusted task, required policy type, and retrieved context.
The prompt does not include the oracle fields `required_obligation` or `forbidden_expansion`.
The clean retrieved context uses `clean_doc_summary`; treatment prompts add either
`ordinary_poison_summary` or `authority_poison_summary`.
