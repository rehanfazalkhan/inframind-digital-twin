from __future__ import annotations

from abc import ABC, abstractmethod

from .config import Settings
from .models import DigitalTwin


class TwinRepository(ABC):
    @abstractmethod
    def save(self, twin: DigitalTwin) -> None: ...

    @abstractmethod
    def get(self, twin_id: str) -> DigitalTwin | None: ...

    @abstractmethod
    def recent(self) -> list[DigitalTwin]: ...


class InMemoryTwinRepository(TwinRepository):
    def __init__(self) -> None:
        self.twins: dict[str, DigitalTwin] = {}

    def save(self, twin: DigitalTwin) -> None:
        self.twins[twin.id] = twin.model_copy(deep=True)

    def get(self, twin_id: str) -> DigitalTwin | None:
        twin = self.twins.get(twin_id)
        return twin.model_copy(deep=True) if twin else None

    def recent(self) -> list[DigitalTwin]:
        return sorted((twin.model_copy(deep=True) for twin in self.twins.values()), key=lambda twin: twin.updated_at, reverse=True)


class DynamoTwinRepository(TwinRepository):
    def __init__(self, settings: Settings) -> None:
        import boto3

        self.table = boto3.resource("dynamodb", region_name=settings.aws_region).Table(settings.ddb_table_name)

    def save(self, twin: DigitalTwin) -> None:
        self.table.put_item(Item=twin.model_dump(mode="json"))

    def get(self, twin_id: str) -> DigitalTwin | None:
        item = self.table.get_item(Key={"id": twin_id}).get("Item")
        return DigitalTwin.model_validate(item) if item else None

    def recent(self) -> list[DigitalTwin]:
        items = self.table.scan(Limit=50).get("Items", [])
        return sorted((DigitalTwin.model_validate(item) for item in items), key=lambda twin: twin.updated_at, reverse=True)


def build_repository(settings: Settings) -> TwinRepository:
    return DynamoTwinRepository(settings) if settings.is_production else InMemoryTwinRepository()
