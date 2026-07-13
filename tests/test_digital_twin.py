from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.discovery import TerraformDiscoveryGateway
from app.graph import deterministic_findings, reference_topology
from app.models import Principal, ProposalStatus, Provider, ScanRequest, Severity
from app.service import InfraMindService


def test_reference_topology_has_dependency_graph_and_governed_findings():
    nodes, edges = reference_topology()
    findings = deterministic_findings(nodes)
    assert len(nodes) == 6
    assert {(edge.source, edge.target) for edge in edges} >= {("aws:ecs:orders", "aws:rds:orders"), ("aws:ecs:orders", "aws:alb:edge")}
    assert any(finding.severity == Severity.CRITICAL and finding.category == "security" for finding in findings)
    assert {"security", "reliability", "finops"}.issubset({finding.category for finding in findings})


@pytest.mark.asyncio
async def test_service_maps_impact_and_requires_approval_for_proposal():
    service = InfraMindService(settings=Settings.from_environment())
    operator = Principal(subject="operator-1", roles={"inframind_operator"})
    twin = await service.create_twin(ScanRequest(provider=Provider.SAMPLE, scope="test-estate"), operator)
    analyzed = await service.analyze(twin.id, operator)
    assert analyzed.assessment and analyzed.assessment.risk_score > 0
    impact = service.blast_radius(twin.id, "aws:rds:orders")
    assert "aws:ecs:orders" in impact.impacted_resource_ids
    proposal = service.create_proposal(twin.id, operator)
    assert proposal.status == ProposalStatus.DRAFT
    approved = service.approve_proposal(twin.id, proposal.id, Principal(subject="approver-1", roles={"inframind_approver"}))
    assert approved.status == ProposalStatus.APPROVED
    assert approved.approved_by == "approver-1"


def test_terraform_hcl_import_extracts_resource_reference():
    pytest.importorskip("hcl2")
    source = '''
resource "aws_vpc" "core" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "app" { vpc_id = aws_vpc.core.id }
'''
    nodes, edges = TerraformDiscoveryGateway().discover(ScanRequest(provider=Provider.TERRAFORM, scope="terraform", terraform_source=source))
    assert {node.id for node in nodes} == {"tf:aws_vpc.core", "tf:aws_subnet.app"}
    assert any(edge.source == "tf:aws_subnet.app" and edge.target == "tf:aws_vpc.core" for edge in edges)


def test_api_scans_analyzes_and_returns_blast_radius():
    from app.main import app

    client = TestClient(app)
    created = client.post("/api/twins", json={"provider": "sample", "scope": "console-estate"})
    assert created.status_code == 201
    twin = created.json()
    analyzed = client.post(f"/api/twins/{twin['id']}/analyze")
    assert analyzed.status_code == 200
    impact = client.get(f"/api/twins/{twin['id']}/impact", params={"resource_id": "aws:rds:orders"})
    assert impact.status_code == 200
    assert "aws:ecs:orders" in impact.json()["impacted_resource_ids"]
