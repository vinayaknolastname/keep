import copy
import json
from typing import Any

from keep.api.models.alert import AlertDto

KEEP_RAW_PAYLOAD_ATTR = "keep_raw_payload"
MAX_LOG_PAYLOAD_CHARS = 8000


def serialize_for_log(value: Any, max_chars: int = MAX_LOG_PAYLOAD_CHARS) -> str | None:
    if value is None:
        return None
    try:
        serialized = json.dumps(value, default=str)
    except TypeError:
        serialized = str(value)
    if len(serialized) > max_chars:
        return (
            f"{serialized[:max_chars]}... [truncated, total {len(serialized)} chars]"
        )
    return serialized


def tokenize_path(path: str) -> list[str | int]:
    """Parse dotted paths with bracket indices, e.g. alerts[0].labels.monitor."""
    tokens: list[str | int] = []
    for part in path.split("."):
        part = part.strip()
        if not part:
            continue
        while part:
            bracket_start = part.find("[")
            if bracket_start == -1:
                tokens.append(part)
                break
            if bracket_start > 0:
                tokens.append(part[:bracket_start])
            bracket_end = part.find("]", bracket_start)
            if bracket_end == -1:
                tokens.append(part)
                break
            index_part = part[bracket_start + 1 : bracket_end]
            if index_part.isdigit():
                tokens.append(int(index_part))
            else:
                tokens.append(index_part)
            part = part[bracket_end + 1 :]
    return tokens


def resolve_path_in_data(data: Any, tokens: list[str | int]) -> Any:
    current = data
    for token in tokens:
        if current is None:
            return None
        if isinstance(token, int):
            if isinstance(current, list) and 0 <= token < len(current):
                current = current[token]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(token)
        else:
            return None
    return current


def resolve_template_variable(
    alert: AlertDto,
    var: str,
    *,
    store_raw_alerts: bool = False,
) -> str | None:
    """
    Resolve {{ var }} placeholders for correlation templates.

    - alert.labels.host -> normalized AlertDto
    - raw.alerts[0].condition -> provider raw webhook (requires KEEP_STORE_RAW_ALERTS)
    - alerts[0].condition -> raw payload fallback when not on AlertDto
    """
    var = var.strip()
    if not var:
        return None

    if var.startswith("alert."):
        value = resolve_path_in_data(alert.dict(), tokenize_path(var[len("alert.") :]))
        return str(value) if value is not None else None

    if var.startswith("raw."):
        if not store_raw_alerts:
            return None
        raw_payload = get_raw_payload_from_alert(alert)
        if not raw_payload:
            return None
        value = resolve_path_in_data(raw_payload, tokenize_path(var[len("raw.") :]))
        return str(value) if value is not None else None

    value = resolve_path_in_data(alert.dict(), tokenize_path(var))
    if value is not None:
        return str(value)

    if store_raw_alerts:
        raw_payload = get_raw_payload_from_alert(alert)
        if raw_payload:
            value = resolve_path_in_data(raw_payload, tokenize_path(var))
            if value is not None:
                return str(value)

    return None


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _stringify_scalar(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def attach_raw_payloads_to_alerts(
    raw_events: list[dict], formatted_events: list[AlertDto]
) -> None:
    """Attach provider raw webhook payloads to AlertDto for correlation enrichments."""
    if not raw_events or not formatted_events:
        return

    if len(raw_events) == len(formatted_events):
        for raw_event, alert in zip(raw_events, formatted_events):
            if isinstance(raw_event, dict):
                setattr(alert, KEEP_RAW_PAYLOAD_ATTR, copy.deepcopy(raw_event))
        return

    if len(raw_events) == 1 and isinstance(raw_events[0], dict):
        raw_event = copy.deepcopy(raw_events[0])
        for alert in formatted_events:
            setattr(alert, KEEP_RAW_PAYLOAD_ATTR, raw_event)


def get_raw_payload_from_alert(alert: AlertDto) -> dict | None:
    raw_payload = getattr(alert, KEEP_RAW_PAYLOAD_ATTR, None)
    if isinstance(raw_payload, dict):
        return raw_payload

    alert_dict = alert.dict()
    raw_payload = alert_dict.get(KEEP_RAW_PAYLOAD_ATTR)
    if isinstance(raw_payload, dict):
        return raw_payload

    return None


def _match_raw_alert_item(raw_payload: dict, alert: AlertDto) -> dict | None:
    alert_items = raw_payload.get("alerts")
    if not isinstance(alert_items, list) or not alert_items:
        return None

    if alert.fingerprint:
        for item in alert_items:
            if isinstance(item, dict) and item.get("fingerprint") == alert.fingerprint:
                return item

    first_item = alert_items[0]
    return first_item if isinstance(first_item, dict) else None


def extract_raw_enrichments(raw_payload: dict | None, alert: AlertDto) -> dict[str, str]:
    """
    Build incident enrichment key/values from a provider raw payload.
    User-defined enrichments should be merged on top of these defaults.
    """
    if not raw_payload or not isinstance(raw_payload, dict):
        return {}

    enrichments: dict[str, str] = {}

    for key, value in raw_payload.items():
        if key == "alerts":
            continue
        if _is_scalar(value):
            enrichments[f"raw_{key}"] = _stringify_scalar(value)

    matched_item = _match_raw_alert_item(raw_payload, alert)
    if not matched_item:
        return enrichments

    for key, value in matched_item.items():
        if key in ("labels", "annotations") and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if _is_scalar(sub_value):
                    enrichments[sub_key] = _stringify_scalar(sub_value)
            continue

        if _is_scalar(value):
            enrichments[key] = _stringify_scalar(value)

    return enrichments
