from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("inframind.audit")


def audit(event: str, twin_id: str, **fields: Any) -> dict[str, object]:
    record: dict[str, object] = {"event": event, "twin_id": twin_id, "at": datetime.now(timezone.utc).isoformat(), **fields}
    logger.info(json.dumps(record, default=str, sort_keys=True))
    return record
