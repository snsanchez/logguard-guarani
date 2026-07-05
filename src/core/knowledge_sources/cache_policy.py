# cache incremental

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

CACHE_TTL_HOURS = 24


def is_cache_fresh(file: Path) -> bool:
    if not file.exists():
        return False

    try:
        data = json.loads(file.read_text(encoding="utf-8"))
        synced_at = data.get("synced_at")
        if not synced_at:
            return False

        ts = datetime.fromisoformat(synced_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) - ts < timedelta(hours=CACHE_TTL_HOURS)

    except Exception:
        return False
