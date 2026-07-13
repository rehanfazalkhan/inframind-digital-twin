from __future__ import annotations

import io
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .graph import infer_edges, reference_topology
from .models import DependencyEdge, Provider, ResourceNode, ScanRequest


class DiscoveryGateway(ABC):
    @abstractmethod
    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]: ...


class DevelopmentDiscoveryGateway(DiscoveryGateway):
    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]:
        if request.provider == Provider.TERRAFORM and request.terraform_source:
            return TerraformDiscoveryGateway().discover(request)
        return reference_topology()


class AwsDiscoveryGateway(DiscoveryGateway):
    """Reads Resource Explorer and AWS Config; it never invokes a mutation API."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]:
        import boto3

        explorer = boto3.client("resource-explorer-2", region_name=self.settings.aws_region)
        resources: list[dict[str, Any]] = []
        token: str | None = None
        for _ in range(20):
            arguments: dict[str, Any] = {"QueryString": "*", "MaxResults": 1000}
            if token:
                arguments["NextToken"] = token
            response = explorer.search(**arguments)
            resources.extend(response.get("Resources", []))
            token = response.get("NextToken")
            if not token:
                break
        nodes = [self._resource_node(item) for item in resources]
        config_records = self._config_records(boto3.client("config", region_name=self.settings.aws_region))
        by_id = {node.id: node for node in nodes}
        for record in config_records:
            node_id = record.get("arn") or record.get("resourceId")
            if not node_id:
                continue
            node = by_id.get(node_id)
            if not node:
                node = ResourceNode(
                    id=node_id,
                    provider=Provider.AWS,
                    resource_type=record.get("resourceType", "AWS::Unknown"),
                    name=record.get("resourceName") or record.get("resourceId", "unknown"),
                    region=record.get("awsRegion"),
                )
                nodes.append(node)
                by_id[node_id] = node
            node.metadata["config_relationships"] = [relation.get("resourceId") for relation in record.get("relationships", []) if relation.get("resourceId")]
            node.metadata["configuration"] = record.get("configuration", {})
        return nodes, infer_edges(nodes)

    @staticmethod
    def _resource_node(item: dict[str, Any]) -> ResourceNode:
        arn = item["Arn"]
        properties = item.get("Properties", [])
        return ResourceNode(
            id=arn,
            provider=Provider.AWS,
            resource_type=item.get("ResourceType", "AWS::Unknown"),
            name=arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1],
            region=item.get("Region"),
            metadata={"service": item.get("Service"), "properties": properties, "last_reported_at": str(item.get("LastReportedAt", ""))},
        )

    @staticmethod
    def _config_records(client: Any) -> list[dict[str, Any]]:
        token: str | None = None
        records: list[dict[str, Any]] = []
        query = "SELECT resourceId, resourceName, resourceType, arn, awsRegion, configuration, relationships"
        for _ in range(20):
            arguments: dict[str, Any] = {"Expression": query}
            if token:
                arguments["NextToken"] = token
            response = client.select_resource_config(**arguments)
            records.extend(json.loads(raw) for raw in response.get("Results", []))
            token = response.get("NextToken")
            if not token:
                break
        return records


class AzureDiscoveryGateway(DiscoveryGateway):
    """Uses Azure Resource Graph with DefaultAzureCredential and Reader-level inventory access."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        client = ResourceGraphClient(DefaultAzureCredential())
        query = "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags, properties"
        result = client.resources(QueryRequest(subscriptions=list(self.settings.azure_subscription_ids), query=query))
        rows = result.data if isinstance(result.data, list) else []
        nodes = [
            ResourceNode(
                id=row["id"],
                provider=Provider.AZURE,
                resource_type=row["type"],
                name=row["name"],
                region=row.get("location"),
                resource_group=row.get("resourceGroup"),
                tags=row.get("tags") or {},
                metadata={"subscription_id": row.get("subscriptionId"), "properties": row.get("properties") or {}},
            )
            for row in rows
        ]
        return nodes, infer_edges(nodes)


class TerraformDiscoveryGateway(DiscoveryGateway):
    """Parses provided HCL into a graph without executing Terraform or contacting a provider."""

    REFERENCE = re.compile(r"(?:\$\{)?([A-Za-z0-9_]+\.[A-Za-z0-9_-]+)\b")

    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]:
        if not request.terraform_source:
            raise ValueError("terraform_source is required for Terraform discovery.")
        import hcl2

        document = hcl2.load(io.StringIO(request.terraform_source))
        blocks = document.get("resource", [])
        if isinstance(blocks, dict):
            blocks = [blocks]
        nodes: list[ResourceNode] = []
        references: dict[str, set[str]] = {}
        aliases: dict[str, str] = {}
        for block in blocks:
            for raw_resource_type, instances in block.items():
                # python-hcl2 v8 retains the quotes around HCL block labels.
                # Normalize them so IDs are stable across parser versions.
                resource_type = str(raw_resource_type).strip('"')
                for raw_name, configuration in instances.items():
                    name = str(raw_name).strip('"')
                    node_id = f"tf:{resource_type}.{name}"
                    aliases[f"{resource_type}.{name}"] = node_id
                    nodes.append(
                        ResourceNode(
                            id=node_id,
                            provider=Provider.TERRAFORM,
                            resource_type=resource_type,
                            name=name,
                            metadata={"configuration": configuration},
                        )
                    )
                    references[node_id] = set(self.REFERENCE.findall(json.dumps(configuration, default=str)))
        edges = [
            DependencyEdge(source=node_id, target=aliases[reference], relationship="depends_on", confidence=0.98, evidence=f"Terraform reference {reference}.")
            for node_id, values in references.items()
            for reference in values
            if reference in aliases and aliases[reference] != node_id
        ]
        return nodes, edges


def build_discovery_gateway(settings: Settings) -> DiscoveryGateway:
    if not settings.is_production:
        return DevelopmentDiscoveryGateway()
    return ProductionDiscoveryGateway(settings)


@dataclass
class ProductionDiscoveryGateway(DiscoveryGateway):
    settings: Settings

    def discover(self, request: ScanRequest) -> tuple[list[ResourceNode], list[DependencyEdge]]:
        if request.provider == Provider.AWS:
            return AwsDiscoveryGateway(self.settings).discover(request)
        if request.provider == Provider.AZURE:
            return AzureDiscoveryGateway(self.settings).discover(request)
        if request.provider == Provider.TERRAFORM:
            return TerraformDiscoveryGateway().discover(request)
        raise ValueError("Sample discovery is disabled in production.")
