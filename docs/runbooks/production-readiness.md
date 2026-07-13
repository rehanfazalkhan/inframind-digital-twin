# InfraMind production readiness

## Identity boundary

InfraMind discovery is read-only by design. Create a dedicated workload identity; do not reuse an operator or deployment role.

- AWS: permit Resource Explorer search, AWS Config advanced-query reads, and Bedrock model invocation. Deny resource mutation APIs, IAM changes, Secrets Manager reads, and destructive actions.
- Azure: assign Reader and Azure Resource Graph query access at the selected subscription scope. Use workload identity or managed identity; do not embed client secrets.
- OIDC: configure a trusted issuer and audience. Map `inframind_approver` or `inframind_admin` only to users who may approve a proposed Terraform change.

## Discovery safety

1. Start with one AWS Region or a non-production Azure subscription.
2. Confirm Resource Explorer views and AWS Config recorder coverage before trusting completeness of an AWS graph.
3. Treat inferred edges as evidence-backed but not authoritative until reviewed; each edge exposes confidence and source evidence.
4. Terraform HCL import parses source only. It does not run `terraform init`, providers, plans, or applies.

## Agent and remediation control

- Configure either a Bedrock model ID or Azure OpenAI deployment. PydanticAI rejects model output that does not satisfy the typed specialist report contract.
- Deterministic findings and raw inventory remain separate from model summaries. A model cannot erase an evidence-backed finding.
- The proposal endpoint only generates a file set. Approval records an authenticated principal. Pull-request creation occurs only after approval and an explicit GitHub credential/repository configuration.
- Never grant the GitHub token cloud permissions. It should be limited to the target infrastructure repository.

## Operational checks

- `/readyz` must be ready before external exposure.
- Run the golden data set after any graph-extraction, model, or policy change.
- Alert on discovery failures, model-schema failures, approval actions, and pull-request creation.
- Review IAM, Azure role assignments, GitHub token scope, and MCP tool allowlists quarterly.
