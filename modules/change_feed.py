"""Entity-scoped Atom feeds for public incident and ledger changes."""

from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET


ATOM = "http://www.w3.org/2005/Atom"
ET.register_namespace("", ATOM)


def _timestamp(value: Any) -> str:
    text = str(value or "").strip()
    return text or datetime.now(timezone.utc).isoformat()


def build_change_feed(
    record: dict[str, Any],
    *,
    kind: str,
    site_url: str,
) -> bytes:
    """Build a bounded Atom feed from one public record and its history."""
    record_id = str(record.get("id") or "unknown")
    title = str(record.get("title") or record.get("entity_name") or record_id)
    web_path = f"/{'ledger' if kind == 'ledger' else 'incidents'}/{record_id}"
    feed_path = (
        f"/api/v1/ledger/{record_id}/feed.xml"
        if kind == "ledger"
        else f"/api/v2/incidents/{record_id}/feed.xml"
    )
    root = ET.Element(f"{{{ATOM}}}feed")
    ET.SubElement(root, f"{{{ATOM}}}id").text = f"{site_url}{feed_path}"
    ET.SubElement(root, f"{{{ATOM}}}title").text = f"ThreatWatch changes: {title}"
    ET.SubElement(root, f"{{{ATOM}}}updated").text = _timestamp(record.get("last_changed"))
    ET.SubElement(root, f"{{{ATOM}}}link", {"href": f"{site_url}{web_path}", "rel": "alternate"})
    ET.SubElement(root, f"{{{ATOM}}}link", {"href": f"{site_url}{feed_path}", "rel": "self"})
    for change in list(record.get("changes") or [])[:30]:
        if not isinstance(change, dict):
            continue
        entry = ET.SubElement(root, f"{{{ATOM}}}entry")
        change_id = str(change.get("id") or f"{record_id}-{change.get('changed_at', '')}")
        summary = str(change.get("summary") or "ThreatWatch assessment changed.")
        ET.SubElement(entry, f"{{{ATOM}}}id").text = f"urn:threatwatch:{change_id}"
        ET.SubElement(entry, f"{{{ATOM}}}title").text = summary
        ET.SubElement(entry, f"{{{ATOM}}}updated").text = _timestamp(change.get("changed_at"))
        ET.SubElement(entry, f"{{{ATOM}}}summary").text = summary
        ET.SubElement(entry, f"{{{ATOM}}}link", {"href": f"{site_url}{web_path}"})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
