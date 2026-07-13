from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str
    ddb_table_name: str | None
    aws_region: str | None
    aws_bedrock_model_id: str | None
    azure_subscription_ids: tuple[str, ...]
    azure_openai_endpoint: str | None
    azure_openai_model: str | None
    azure_openai_api_version: str | None
    issuer: str | None
    audience: str | None
    github_token: str | None
    github_repository: str | None

    @classmethod
    def from_environment(cls) -> "Settings":
        subscriptions = tuple(item.strip() for item in os.getenv("AZURE_SUBSCRIPTION_IDS", "").split(",") if item.strip())
        return cls(
            environment=os.getenv("INFRAMIND_ENVIRONMENT", "development").lower(),
            ddb_table_name=os.getenv("INFRAMIND_DDB_TABLE"),
            aws_region=os.getenv("AWS_REGION"),
            aws_bedrock_model_id=os.getenv("AWS_BEDROCK_MODEL_ID"),
            azure_subscription_ids=subscriptions,
            azure_openai_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            azure_openai_model=os.getenv("AZURE_OPENAI_MODEL"),
            azure_openai_api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
            issuer=os.getenv("INFRAMIND_ISSUER"),
            audience=os.getenv("INFRAMIND_AUDIENCE"),
            github_token=os.getenv("GITHUB_TOKEN"),
            github_repository=os.getenv("GITHUB_REPOSITORY"),
        )

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def production_gaps(self) -> list[str]:
        required = {
            "INFRAMIND_ISSUER": self.issuer,
            "INFRAMIND_AUDIENCE": self.audience,
            "INFRAMIND_DDB_TABLE": self.ddb_table_name,
            "AWS_REGION or AZURE_SUBSCRIPTION_IDS": self.aws_region or self.azure_subscription_ids,
            "AWS_BEDROCK_MODEL_ID or Azure OpenAI settings": self.aws_bedrock_model_id or (self.azure_openai_endpoint and self.azure_openai_model and self.azure_openai_api_version),
        }
        return [name for name, value in required.items() if not value]

    def assert_production_ready(self) -> None:
        gaps = self.production_gaps()
        if gaps:
            raise RuntimeError(f"Production configuration incomplete: {', '.join(gaps)}")
