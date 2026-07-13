from __future__ import annotations

import json
import re
from collections import defaultdict, deque

from .models import BlastRadius, DependencyEdge, Finding, Provider, ResourceNode, Severity

REFERENCE_PATTERN = re.compile(r"(?:arn:aws:[^\s\"']+|/subscriptions/[\w-]+/resourceGroups/[^\s\"']+)", re.IGNORECASE)


def infer_edges(nodes: list[ResourceNode]) -> list[DependencyEdge]:
    ids = {node.id.lower(): node.id for node in nodes}
    edges: dict[tuple[str, str], DependencyEdge] = {}
    for node in nodes:
        payload = json.dumps(node.metadata, default=str)
        explicit = node.tags.get("inframind:depends_on", "") or str(node.metadata.get("depends_on", ""))
        references = set(REFERENCE_PATTERN.findall(payload)) | {item.strip() for item in explicit.split(",") if item.strip()}
        for reference in references:
            target = ids.get(reference.lower())
            if target and target != node.id:
                key = (node.id, target)
                edges[key] = DependencyEdge(
                    source=node.id,
                    target=target,
                    relationship="depends_on",
                    confidence=0.92 if reference in explicit else 0.76,
                    evidence=f"Reference discovered in {node.name} configuration or dependency tag.",
                )
    return list(edges.values())


def deterministic_findings(nodes: list[ResourceNode]) -> list[Finding]:
    findings: list[Finding] = []
    for node in nodes:
        metadata = json.dumps(node.metadata, default=str).lower()
        resource_type = node.resource_type.lower()
        if "0.0.0.0/0" in metadata and any(token in resource_type for token in ("securitygroup", "security_group", "networksecuritygroup", "network_security_group", "firewall")):
            findings.append(
                Finding(
                    category="security",
                    severity=Severity.CRITICAL,
                    title="Internet-wide administrative ingress",
                    description=f"{node.name} includes a 0.0.0.0/0 network rule and needs a scoped source policy.",
                    affected_resource_ids=[node.id],
                    evidence=["A public CIDR was found in the discovered resource configuration."],
                    remediation="Restrict ingress to approved CIDRs, private connectivity, or an identity-aware access proxy.",
                )
            )
        if any(token in resource_type for token in ("s3", "storageaccount")) and ("public" in metadata or "allusers" in metadata):
            findings.append(
                Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title="Potentially public object storage",
                    description=f"{node.name} appears to permit public object access.",
                    affected_resource_ids=[node.id],
                    evidence=["Storage access configuration contains a public access indicator."],
                    remediation="Disable public access and explicitly grant only workload identities that require access.",
                )
            )
        high_availability_enabled = any(marker in metadata for marker in ('"multi_az": true', '"multiaz": true', '"zone_redundant": true', '"zoneredundant": true'))
        if any(token in resource_type for token in ("rds", "db_instance", "database", "sql")) and not high_availability_enabled:
            findings.append(
                Finding(
                    category="reliability",
                    severity=Severity.HIGH,
                    title="Database availability configuration needs review",
                    description=f"{node.name} has no discovered multi-zone or replica evidence.",
                    affected_resource_ids=[node.id],
                    evidence=["The inventory record did not contain a high-availability marker."],
                    remediation="Validate recovery objectives and enable the platform-appropriate high-availability option.",
                )
            )
        if (node.estimated_monthly_cost or 0) >= 1500:
            findings.append(
                Finding(
                    category="finops",
                    severity=Severity.MEDIUM,
                    title="High monthly cost concentration",
                    description=f"{node.name} represents significant estimated monthly exposure.",
                    affected_resource_ids=[node.id],
                    evidence=[f"Estimated monthly cost: ${node.estimated_monthly_cost:,.0f}."],
                    remediation="Validate utilization, reservation coverage, autoscaling, and lifecycle policies.",
                )
            )
    return findings


def calculate_blast_radius(target_resource_id: str, edges: list[DependencyEdge]) -> BlastRadius:
    reverse: dict[str, list[DependencyEdge]] = defaultdict(list)
    for edge in edges:
        reverse[edge.target].append(edge)
    queue: deque[tuple[str, int, list[str]]] = deque([(target_resource_id, 0, [target_resource_id])])
    seen = {target_resource_id}
    impacted: list[str] = []
    longest_path = [target_resource_id]
    while queue:
        current, depth, path = queue.popleft()
        for edge in reverse[current]:
            dependent = edge.source
            if dependent in seen:
                continue
            seen.add(dependent)
            next_path = [*path, dependent]
            impacted.append(dependent)
            longest_path = next_path if len(next_path) > len(longest_path) else longest_path
            queue.append((dependent, depth + 1, next_path))
    impact = "No dependent resources were discovered." if not impacted else f"{len(impacted)} dependent resource(s) may be affected by an outage or unsafe change."
    return BlastRadius(
        target_resource_id=target_resource_id,
        impacted_resource_ids=impacted,
        depth=max(0, len(longest_path) - 1),
        service_impact=impact,
        evidence_path=longest_path,
    )


def reference_topology() -> tuple[list[ResourceNode], list[DependencyEdge]]:
    nodes = [
        ResourceNode(id="aws:vpc:core", provider=Provider.SAMPLE, resource_type="aws_vpc", name="core-network", region="us-east-1", metadata={"cidr": "10.20.0.0/16"}),
        ResourceNode(id="aws:alb:edge", provider=Provider.SAMPLE, resource_type="aws_lb", name="public-api", region="us-east-1", metadata={"depends_on": "aws:vpc:core"}, estimated_monthly_cost=320),
        ResourceNode(id="aws:ecs:orders", provider=Provider.SAMPLE, resource_type="aws_ecs_service", name="orders-service", region="us-east-1", metadata={"depends_on": "aws:alb:edge,aws:rds:orders"}, estimated_monthly_cost=1840),
        ResourceNode(id="aws:rds:orders", provider=Provider.SAMPLE, resource_type="aws_db_instance", name="orders-primary", region="us-east-1", metadata={"publicly_accessible": False, "multi_az": False}, estimated_monthly_cost=2430),
        ResourceNode(id="aws:sg:admin", provider=Provider.SAMPLE, resource_type="aws_security_group", name="admin-ingress", region="us-east-1", metadata={"ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}),
        ResourceNode(id="azure:storage:analytics", provider=Provider.SAMPLE, resource_type="Microsoft.Storage/storageAccounts", name="analyticsstore", region="eastus2", metadata={"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True}, estimated_monthly_cost=720),
    ]
    return nodes, infer_edges(nodes)
