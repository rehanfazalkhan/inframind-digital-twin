import json
from pathlib import Path

from app.graph import deterministic_findings, reference_topology


def test_golden_finding_dataset():
    nodes, _ = reference_topology()
    findings = deterministic_findings(nodes)
    scenarios = [json.loads(line) for line in Path("evaluations/golden_dataset.jsonl").read_text().splitlines()]
    for scenario in scenarios:
        match = next((finding for finding in findings if finding.title == scenario["expected_title"]), None)
        assert match is not None, scenario["id"]
        assert match.severity.value == scenario["expected_severity"]
        assert match.category == scenario["expected_category"]
