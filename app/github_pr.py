from __future__ import annotations

import base64
from datetime import datetime, timezone

import httpx

from .config import Settings
from .models import TerraformProposal


class GitHubPullRequestGateway:
    """Creates a branch, commit, and pull request only after service-level approval."""

    def __init__(self, settings: Settings) -> None:
        if not settings.github_token or not settings.github_repository:
            raise RuntimeError("GITHUB_TOKEN and GITHUB_REPOSITORY are required to create a remediation pull request.")
        self.settings = settings
        self.client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {settings.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=20,
        )

    def create(self, proposal: TerraformProposal) -> str:
        repository = self.settings.github_repository
        repo = self.client.get(f"/repos/{repository}").raise_for_status().json()
        base = repo["default_branch"]
        base_ref = self.client.get(f"/repos/{repository}/git/ref/heads/{base}").raise_for_status().json()["object"]["sha"]
        base_commit = self.client.get(f"/repos/{repository}/git/commits/{base_ref}").raise_for_status().json()
        branch = f"inframind/remediation-{proposal.id[:8]}"
        self.client.post(f"/repos/{repository}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": base_ref}).raise_for_status()
        tree = self.client.post(
            f"/repos/{repository}/git/trees",
            json={
                "base_tree": base_commit["tree"]["sha"],
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
                    for path, content in proposal.files.items()
                ],
            },
        ).raise_for_status().json()
        commit = self.client.post(
            f"/repos/{repository}/git/commits",
            json={"message": proposal.title, "tree": tree["sha"], "parents": [base_ref]},
        ).raise_for_status().json()
        self.client.patch(f"/repos/{repository}/git/refs/heads/{branch}", json={"sha": commit["sha"]}).raise_for_status()
        pull = self.client.post(
            f"/repos/{repository}/pulls",
            json={"title": proposal.title, "head": branch, "base": base, "body": f"{proposal.rationale}\n\nGenerated at {datetime.now(timezone.utc).isoformat()}."},
        ).raise_for_status().json()
        return pull["html_url"]
