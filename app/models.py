from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    TERRAFORM = "terraform"
    SAMPLE = "sample"


class ScanStatus(str, Enum):
    READY = "ready"
    ANALYZED = "analyzed"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProposalStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    PULL_REQUEST_CREATED = "pull_request_created"


class Principal(BaseModel):
    subject: str
    roles: set[str] = Field(default_factory=set)


class ResourceNode(BaseModel):
    id: str
    provider: Provider
    resource_type: str
    name: str
    region: str | None = None
    resource_group: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    estimated_monthly_cost: float | None = Field(default=None, ge=0)


class DependencyEdge(BaseModel):
    source: str
    target: str
    relationship: Literal["depends_on", "network_path", "identity_access", "data_flow"] = "depends_on"
    confidence: float = Field(ge=0, le=1)
    evidence: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    category: Literal["security", "finops", "reliability", "architecture"]
    severity: Severity
    title: str
    description: str
    affected_resource_ids: list[str]
    evidence: list[str]
    remediation: str
    requires_approval: bool = True


class SpecialistReport(BaseModel):
    specialist: Literal["cloud_architect", "security_engineer", "finops_analyst", "reliability_engineer"]
    summary: str
    findings: list[Finding] = Field(default_factory=list)


class ArchitectureAssessment(BaseModel):
    executive_summary: str
    risk_score: int = Field(ge=0, le=100)
    reports: list[SpecialistReport]
    agent_trace: list[dict[str, object]] = Field(default_factory=list)


class BlastRadius(BaseModel):
    target_resource_id: str
    impacted_resource_ids: list[str]
    depth: int
    service_impact: str
    evidence_path: list[str]


class TerraformProposal(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    rationale: str
    files: dict[str, str]
    finding_ids: list[str]
    status: ProposalStatus = ProposalStatus.DRAFT
    approved_by: str | None = None
    pull_request_url: str | None = None


class ScanRequest(BaseModel):
    provider: Provider
    scope: str = Field(min_length=1, max_length=120)
    terraform_source: str | None = Field(default=None, max_length=1_000_000)


class VoiceQuery(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class DigitalTwin(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ScanStatus = ScanStatus.READY
    provider: Provider
    scope: str
    nodes: list[ResourceNode]
    edges: list[DependencyEdge]
    findings: list[Finding] = Field(default_factory=list)
    assessment: ArchitectureAssessment | None = None
    proposals: list[TerraformProposal] = Field(default_factory=list)
    audit_events: list[dict[str, object]] = Field(default_factory=list)


def now() -> datetime:
    return datetime.now(timezone.utc)
