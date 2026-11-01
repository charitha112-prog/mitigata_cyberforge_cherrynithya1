from collections import defaultdict
from datetime import timedelta

def correlate_records(records):
    # Deterministic only: require at least one shared concrete identifier (IP, user, host/device)
    groups = defaultdict(list)
    for r in records:
        keys = r.get("correlation_keys") or {}
        for key in ("user", "ip", "host", "device_id", "resource"):
            value = keys.get(key)
            if value:
                groups[(key, str(value).lower())].append(r)
    incidents, seen = [], set()
    for (key, value), items in groups.items():
        ids = tuple(sorted(str(x.get("id")) for x in items))
        if len(items) < 2 or ids in seen:
            continue
        seen.add(ids)
        incidents.append({
            "title": f"Related observations sharing {key}: {value}",
            "confidence": "evidence-linked",
            "rationale": f"{len(items)} records share the same {key} value. This is a correlation lead, not proof of a single attack.",
            "evidence": [{"record_id": str(x.get("id")), "source": x.get("source"),
                          "title": x.get("title"), "event_time": str(x.get("event_time"))} for x in items]
        })
    return incidents
