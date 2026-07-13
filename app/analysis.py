from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections import defaultdict

from .config import Settings
from .models import ArchitectureAssessment, DependencyEdge, Finding, ResourceNode, Severity, SpecialistReport, TerraformProposal

SPECIALISTS = ("cloud_architect", "security_engineer", "finops_analyst", "reliability_engineer")


def _risk_score(findings: list[Finding]) -> int:
    weights = {Severity.CRITICAL: 35, Severity.HIGH: 22, Severity.MEDIUM: 10, Severity.LOW: 3}
    return min(100, sum(weights[finding.severity] for finding in findings))


class AnalysisTeam(ABC):
    @abstractmethod
    async def assess(self, nodes: list[ResourceNode], edges: list[DependencyEdge], findings: list[Finding]) -> ArchitectureAssessment: ...


class DevelopmentAnalysisTeam(AnalysisTeam):
    async def assess(self, nodes: list[ResourceNode], edges: list[DependencyEdge], findings: list[Finding]) -> ArchitectureAssessment:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.category].append(finding)
        reports = [
            SpecialistReport(
                specialist="cloud_architect",
                summary=f"Mapped {len(nodes)} resources and {len(edges)} dependency edges; prioritize changes with the widest blast radius.",
                findings=groups["architecture"],
            ),
            SpecialistReport(
                specialist="security_engineer",
                summary=f"Identified {len(groups['security'])} security issue(s); public exposure must be remediated before feature work.",
                findings=groups["security"],
            ),
            SpecialistReport(
                specialist="finops_analyst",
                summary=f"Identified {len(groups['finops'])} cost concentration issue(s); validate utilization with actual billing data before changing capacity.",
                findings=groups["finops"],
            ),
            SpecialistReport(
                specialist="reliability_engineer",
                summary=f"Identified {len(groups['reliability'])} resilience concern(s); validate recovery objectives and dependency failure modes.",
                findings=groups["reliability"],
            ),
        ]
        score = _risk_score(findings)
        summary = f"Digital twin contains {len(nodes)} resources, {len(edges)} relationships, and {len(findings)} governed findings."
        return ArchitectureAssessment(
            executive_summary=summary,
            risk_score=score,
            reports=reports,
            agent_trace=[{"agent": specialist, "status": "completed", "finding_count": len(next(report for report in reports if report.specialist == specialist).findings)} for specialist in SPECIALISTS],
        )


class PydanticAIAnalysisTeam(AnalysisTeam):
    """Production team using PydanticAI structured outputs with Bedrock or Azure OpenAI."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _model(self):
        if self.settings.aws_bedrock_model_id:
            from pydantic_ai.models.bedrock import BedrockConverseModel

            return BedrockConverseModel(self.settings.aws_bedrock_model_id)
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        from openai import AsyncAzureOpenAI
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        token_provider = get_bearer_token_provider(DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default")
        client = AsyncAzureOpenAI(
            azure_endpoint=self.settings.azure_openai_endpoint,
            api_version=self.settings.azure_openai_api_version,
            azure_ad_token_provider=token_provider,
        )
        return OpenAIChatModel(self.settings.azure_openai_model, provider=OpenAIProvider(openai_client=client))

    async def _specialist(self, role: str, context: str) -> SpecialistReport:
        from pydantic_ai import Agent

        instructions = (
            f"You are InfraMind's {role}. Return a schema-valid SpecialistReport with specialist='{role}'. "
            "Use only the supplied inventory and deterministic evidence. Do not claim a resource change happened. "
            "Every recommendation must be reviewable and require approval."
        )
        agent = Agent(self._model(), output_type=SpecialistReport, instructions=instructions)
        result = await agent.run(context)
        report = result.output
        report.specialist = role  # Schema validates the contract; assignment pins the orchestrated responsibility.
        return report

    async def assess(self, nodes: list[ResourceNode], edges: list[DependencyEdge], findings: list[Finding]) -> ArchitectureAssessment:
        inventory = {
            "nodes": [node.model_dump(mode="json", include={"id", "provider", "resource_type", "name", "region", "estimated_monthly_cost"}) for node in nodes[:500]],
            "edges": [edge.model_dump() for edge in edges[:800]],
            "deterministic_findings": [finding.model_dump(mode="json") for finding in findings],
        }
        context = json.dumps(inventory, default=str)
        reports = [await self._specialist(role, context) for role in SPECIALISTS]
        all_findings = [finding for report in reports for finding in report.findings] or findings
        return ArchitectureAssessment(
            executive_summary=f"Multi-agent review completed against {len(nodes)} resources and {len(edges)} dependencies.",
            risk_score=_risk_score(all_findings),
            reports=reports,
            agent_trace=[{"agent": report.specialist, "status": "completed", "finding_count": len(report.findings)} for report in reports],
        )


def build_analysis_team(settings: Settings) -> AnalysisTeam:
    return PydanticAIAnalysisTeam(settings) if settings.is_production else DevelopmentAnalysisTeam()


def build_terraform_proposal(findings: list[Finding]) -> TerraformProposal:
    eligible = [finding for finding in findings if finding.severity in {Severity.CRITICAL, Severity.HIGH}]
    snippets: list[str] = ["# InfraMind review-gated remediation proposal", "# Validate module ownership and run terraform plan before merge."]
    for finding in eligible:
        if finding.category == "security" and "storage" in finding.title.lower():
            snippets.extend(["", "resource \"aws_s3_bucket_public_access_block\" \"inframind_guardrail\" {", "  bucket = var.bucket_id", "  block_public_acls       = true", "  block_public_policy     = true", "  ignore_public_acls      = true", "  restrict_public_buckets = true", "}"])
        elif finding.category == "security":
            snippets.extend(["", "# Replace broad ingress with an approved CIDR variable in the owning security module.", "# cidr_blocks = var.approved_admin_cidrs"])
        elif finding.category == "reliability":
            snippets.extend(["", "# In the database module, validate the platform HA flag:", "# multi_az = true"])
    if len(snippets) == 2:
        snippets.extend(["", "# No critical or high-confidence automatic Terraform fragment was generated.", "# Review the attached evidence before drafting a targeted change."])
    return TerraformProposal(
        title="InfraMind governed cloud hardening proposal",
        rationale="Targets the highest-severity evidence-backed findings. No mutation occurs until an approver creates a pull request.",
        files={"inframind.generated.tf": "\n".join(snippets) + "\n"},
        finding_ids=[finding.id for finding in eligible],
    )
