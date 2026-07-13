# InfraMind Digital Twin

InfraMind builds a read-only, evidence-backed digital twin of AWS, Azure, or Terraform infrastructure. It maps dependencies, runs security/FinOps/reliability analysis, calculates change blast radius, and produces a reviewable Terraform remediation proposal.

The product is deliberately opinionated: discovery identities are read-only; models may recommend a change but cannot mutate cloud resources; and a human approval is required before a GitHub pull request can be created.

## Product capabilities

- AWS inventory through Resource Explorer and AWS Config relationship records.
- Azure inventory through Azure Resource Graph with managed identity authentication.
- Terraform ingestion using an HCL parser, with dependency extraction from resource references.
- Interactive topology graph, risk heatmap, cost exposure, and blast-radius timeline.
- Four typed PydanticAI specialists: cloud architect, security engineer, FinOps analyst, and reliability engineer.
- MCP gateway that exposes bounded, read-only topology and impact tools to approved agent hosts.
- JWT/OIDC validation, structured audit events, approval-gated remediation, and Kubernetes deployment artifacts.

## Architecture

```text
AWS Resource Explorer + AWS Config ─┐
Azure Resource Graph ───────────────┼──► normalized resource inventory
Terraform HCL ──────────────────────┘                │
                                            dependency graph / digital twin
                                                        │
                  PydanticAI specialist team ◄─────────┤
                 security · FinOps · SRE · architect   │
                                                        │
  interactive topology ◄──── evidence & findings ──────┴──── approval-gated Terraform PR
                                                        │
                                    read-only MCP cloud gateway
```

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload
```

Development provides deterministic contract inventory only to enable local verification. Production refuses discovery or model analysis until the selected cloud configuration, OIDC issuer/audience, and explicit read-only identity boundaries are present. Check `/readyz` before deployment.

## Production operating model

1. AWS: assume a dedicated read-only role that permits Resource Explorer search and AWS Config advanced queries. Do not grant mutation permissions.
2. Azure: assign Reader and Resource Graph query permissions to the workload managed identity.
3. Enable PydanticAI with a Bedrock model or Azure OpenAI deployment. The model must produce a schema-valid finding contract.
4. Store the GitHub credential outside source control. A pull request is created only after an authenticated approval of a Terraform proposal.
5. Deploy the Kubernetes manifests after setting the OIDC and cloud identity bindings appropriate to your platform.

The repository contains no cloud credentials and does not claim a deployed environment.
