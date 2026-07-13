from __future__ import annotations

import asyncio

from .analysis import AnalysisTeam, build_analysis_team, build_terraform_proposal
from .config import Settings
from .discovery import DiscoveryGateway, build_discovery_gateway
from .github_pr import GitHubPullRequestGateway
from .graph import calculate_blast_radius, deterministic_findings
from .models import BlastRadius, DigitalTwin, Principal, ProposalStatus, ScanRequest, ScanStatus, TerraformProposal, now
from .policy import PolicyViolation, assert_approval_allowed, assert_pull_request_allowed, assert_read_only_discovery
from .repository import TwinRepository, build_repository
from .telemetry import audit


class InfraMindService:
    def __init__(
        self,
        settings: Settings | None = None,
        repository: TwinRepository | None = None,
        discovery: DiscoveryGateway | None = None,
        analysis_team: AnalysisTeam | None = None,
    ) -> None:
        self.settings = settings or Settings.from_environment()
        self.repository = repository or build_repository(self.settings)
        self.discovery = discovery or build_discovery_gateway(self.settings)
        self.analysis_team = analysis_team or build_analysis_team(self.settings)

    async def create_twin(self, request: ScanRequest, principal: Principal) -> DigitalTwin:
        assert_read_only_discovery(request.provider.value)
        if self.settings.is_production:
            self.settings.assert_production_ready()
        nodes, edges = await asyncio.to_thread(self.discovery.discover, request)
        findings = deterministic_findings(nodes)
        twin = DigitalTwin(provider=request.provider, scope=request.scope, nodes=nodes, edges=edges, findings=findings)
        twin.audit_events.append(audit("read_only_discovery_completed", twin.id, actor=principal.subject, provider=request.provider, resource_count=len(nodes), edge_count=len(edges)))
        self.repository.save(twin)
        return twin

    async def analyze(self, twin_id: str, principal: Principal) -> DigitalTwin:
        if self.settings.is_production:
            self.settings.assert_production_ready()
        twin = self._get(twin_id)
        twin.assessment = await self.analysis_team.assess(twin.nodes, twin.edges, twin.findings)
        twin.status = ScanStatus.ANALYZED
        twin.updated_at = now()
        twin.audit_events.append(audit("multi_agent_analysis_completed", twin.id, actor=principal.subject, risk_score=twin.assessment.risk_score))
        self.repository.save(twin)
        return twin

    def blast_radius(self, twin_id: str, resource_id: str) -> BlastRadius:
        twin = self._get(twin_id)
        if resource_id not in {node.id for node in twin.nodes}:
            raise KeyError(resource_id)
        return calculate_blast_radius(resource_id, twin.edges)

    def create_proposal(self, twin_id: str, principal: Principal) -> TerraformProposal:
        twin = self._get(twin_id)
        proposal = build_terraform_proposal(twin.findings)
        twin.proposals.append(proposal)
        twin.updated_at = now()
        twin.audit_events.append(audit("terraform_proposal_created", twin.id, actor=principal.subject, proposal_id=proposal.id, finding_count=len(proposal.finding_ids)))
        self.repository.save(twin)
        return proposal

    def approve_proposal(self, twin_id: str, proposal_id: str, principal: Principal) -> TerraformProposal:
        assert_approval_allowed(principal)
        twin, proposal = self._proposal(twin_id, proposal_id)
        if proposal.status != ProposalStatus.DRAFT:
            raise PolicyViolation("Only a draft remediation proposal can be approved.")
        proposal.status = ProposalStatus.APPROVED
        proposal.approved_by = principal.subject
        twin.updated_at = now()
        twin.audit_events.append(audit("terraform_proposal_approved", twin.id, actor=principal.subject, proposal_id=proposal.id))
        self.repository.save(twin)
        return proposal

    async def create_pull_request(self, twin_id: str, proposal_id: str, principal: Principal) -> TerraformProposal:
        assert_pull_request_allowed(principal)
        twin, proposal = self._proposal(twin_id, proposal_id)
        if proposal.status != ProposalStatus.APPROVED:
            raise PolicyViolation("A proposal must be explicitly approved before a pull request can be created.")
        url = await asyncio.to_thread(GitHubPullRequestGateway(self.settings).create, proposal)
        proposal.status = ProposalStatus.PULL_REQUEST_CREATED
        proposal.pull_request_url = url
        twin.updated_at = now()
        twin.audit_events.append(audit("remediation_pull_request_created", twin.id, actor=principal.subject, proposal_id=proposal.id, pull_request_url=url))
        self.repository.save(twin)
        return proposal

    def answer_topology_question(self, twin_id: str, question: str) -> dict[str, object]:
        twin = self._get(twin_id)
        matching = [node for node in twin.nodes if node.name.lower() in question.lower() or node.id.lower() in question.lower()]
        if matching:
            impact = calculate_blast_radius(matching[0].id, twin.edges)
            return {"answer": f"{matching[0].name} has {len(impact.impacted_resource_ids)} discovered downstream dependent resource(s).", "blast_radius": impact}
        return {"answer": f"The twin currently maps {len(twin.nodes)} resources and {len(twin.edges)} dependency edges. Select a resource to calculate a specific blast radius."}

    def _get(self, twin_id: str) -> DigitalTwin:
        twin = self.repository.get(twin_id)
        if not twin:
            raise KeyError(twin_id)
        return twin

    def _proposal(self, twin_id: str, proposal_id: str) -> tuple[DigitalTwin, TerraformProposal]:
        twin = self._get(twin_id)
        proposal = next((item for item in twin.proposals if item.id == proposal_id), None)
        if not proposal:
            raise KeyError(proposal_id)
        return twin, proposal
