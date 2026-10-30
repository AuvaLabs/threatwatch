"""Build versioned, evidence-linked records for major non-CVE incidents."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from modules.config import OUTPUT_DIR
from modules.date_utils import parse_datetime
from modules.ioc_quality import publisher_name
from modules.utils import write_json_atomic

INCIDENTS_PATH = OUTPUT_DIR / "incidents-v2.json"
SCHEMA_VERSION = 1
TODAY_THRESHOLD = 60
MAX_RECORDS = 500
MAX_CLAIMS = 40
MAX_CHANGES = 30
CORRELATION_WINDOW = timedelta(hours=72)

_CLAIM_STATES = frozenset({"confirmed", "reported", "assessed", "disputed", "unknown"})
_CONFIDENCE = frozenset({"high", "medium", "low"})
_NATIONALITY_ADJECTIVES = frozenset({
    "american", "australian", "british", "chinese", "french", "german", "indian",
    "iranian", "israeli", "japanese", "korean", "russian", "ukrainian",
})
_NAME_VERBS = frozenset({
    "confirms", "discloses", "investigate", "investigates", "probes", "reports", "says", "warns",
})
_GENERIC_ORGS = frozenset({
    "ai", "attackers", "company", "customers", "cyber", "cyberattack", "cyberattacks",
    "cybersecurity", "data", "hackers", "massive", "new", "ransomware", "researchers",
    "security", "service", "threat actors", "users",
})
_TITLE_STOP = frozenset({
    "after", "against", "attack", "attacks", "breach", "cyber", "cyberattack",
    "data", "exploited", "flaw", "from", "hack", "hacked", "incident", "into",
    "largest", "more", "over", "possible", "potential", "report", "reports",
    "security", "suspected", "that", "their", "this", "vulnerabilities", "with", "world",
})
_INCIDENT_SIGNAL = re.compile(
    r"\b(?:attack|breach|compromis|cyberattack|data leak|ddos|disrupt|encrypt|exfiltrat|"
    r"hack|incident|intrusion|malware|outage|ransomware|stolen|theft|unauthori[sz]ed)\w*\b",
    re.IGNORECASE,
)
_SUBJECT_ORG = re.compile(
    r"^(?:breaking:\s*)?([A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,3})\s+"
    r"(?i:faces?|freezes?|halts?|hit|pauses?|responds?|restores?|suffers?|suspends?|under)\b",
)
_PREFIX_ORG = re.compile(
    r"^(?:breaking:\s*)?([A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,3}?)(?:['’]s)?\s+"
    r"(?i:(?:data|security)\s+breach|breach|cyberattack|hack|incident|intrusion|outage|theft)\b",
)
_OBJECT_ORG = re.compile(
    r"\b(?:attack|breach|hack|incident|intrusion|outage|theft)\s+"
    r"(?:at|against|from|hits?|on)\s+([A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,3})",
)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _article_id(article: dict[str, Any]) -> str:
    existing = _text(article.get("hash"))
    if existing:
        return existing
    identity = f"{article.get('title', '')}|{article.get('link', '')}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _published(article: dict[str, Any]) -> datetime | None:
    return parse_datetime(
        article.get("published_at") or article.get("published") or article.get("timestamp")
    )


def _headline(article: dict[str, Any]) -> str:
    title = _text(article.get("translated_title") or article.get("title"))
    if " - " not in title:
        return title
    headline, suffix = title.rsplit(" - ", 1)
    return headline if 0 < len(suffix) <= 80 else title


def _normalized_name(value: Any) -> str:
    name = re.sub(r"\s+", " ", _text(value)).strip(" .,:;-'\"")
    words = set(re.findall(r"[a-z-]+", name.casefold()))
    invalid = (
        len(name) < 2 or name.casefold() in _GENERIC_ORGS
        or name.casefold() in _NATIONALITY_ADJECTIVES or name.casefold().endswith("-linked")
        or bool(words & _NAME_VERBS)
    )
    return "" if invalid else name[:120]


def _organizations(article: dict[str, Any]) -> list[str]:
    structured = [
        *_list(article.get("victim_organizations")),
        *_list(article.get("affected_organizations")),
    ]
    names = {_normalized_name(value) for value in structured}
    title = _headline(article)
    text = f"{title} {_text(article.get('summary'))} {_text(article.get('category'))}"
    if _INCIDENT_SIGNAL.search(text):
        subject = _SUBJECT_ORG.search(title)
        prefix = _PREFIX_ORG.search(title) if subject is None else None
        object_match = _OBJECT_ORG.search(title)
        for match in (subject, prefix, object_match):
            if match is not None:
                names.add(_normalized_name(match.group(1)))
        names.update(_normalized_name(value) for value in _list(article.get("brand_tags")))
    return sorted((name for name in names if name), key=str.casefold)[:5]


def _event_type(article: dict[str, Any]) -> str | None:
    narrative = f"{_headline(article)} {_text(article.get('summary'))}".casefold()
    category = _text(article.get("category")).casefold()
    text = f"{category} {narrative}"
    historical = any(term in narrative for term in ("lawsuit", "payment dates", "settlement", "who will receive"))
    if historical and not any(term in narrative for term in ("new breach", "new incident", "currently investigating")):
        return None
    if "ransomware" in text or "encrypted" in text:
        return "ransomware"
    if any(term in narrative for term in (
        "customer data", "data breach", "data leak", "exfiltrat", "personal data", "records exposed",
    )):
        return "data_breach"
    if any(term in text for term in ("ddos", "denial of service", "service outage")):
        return "disruption"
    if _INCIDENT_SIGNAL.search(text):
        return "intrusion"
    return None


def _event_family(event_type: str) -> str:
    return "intrusion" if event_type in {"data_breach", "intrusion", "ransomware"} else event_type


def _group_event_type(members: list[dict[str, Any]]) -> str:
    event_types = {_event_type(member) for member in members}
    for candidate in ("ransomware", "data_breach", "intrusion", "disruption"):
        if candidate in event_types:
            return candidate
    return "intrusion"


def _source(article: dict[str, Any]) -> dict[str, Any]:
    url = _text(article.get("canonical_url") or article.get("link"))
    return {
        "article_id": _article_id(article),
        "title": _text(article.get("translated_title") or article.get("title")) or "Untitled report",
        "publisher": publisher_name(article),
        "published": (_published(article).isoformat() if _published(article) else None),
        "url": url,
    }


def _headline_signature(title: str) -> str:
    words = re.findall(r"[a-z0-9]+", title.casefold())
    return " ".join(word for word in words if word not in {"a", "an", "the"})


def _publisher_key(source: dict[str, Any]) -> str:
    publisher = re.sub(r"[^a-z0-9]+", "", _text(source.get("publisher")).casefold())
    if publisher and publisher not in {"google", "googlenews", "bing", "unknownpublisher"}:
        return publisher
    try:
        return (urlparse(_text(source.get("url"))).hostname or publisher).removeprefix("www.")
    except ValueError:
        return publisher or "unknown"


def _sources(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    base = [_source(member) for member in members]
    signatures: dict[str, int] = defaultdict(int)
    for source in base:
        signatures[_headline_signature(source["title"])] += 1
    rendered = []
    for source in base:
        signature = _headline_signature(source["title"])
        family = f"headline:{hashlib.sha256(signature.encode()).hexdigest()[:12]}" \
            if signatures[signature] > 1 else f"publisher:{_publisher_key(source)}"
        rendered.append({**source, "source_family": family})
    return rendered


def _candidate_groups(articles: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    parsed = [
        (article, _event_type(article), _organizations(article))
        for article in articles
    ]
    known = sorted(
        {organization for _, event_type, organizations in parsed if event_type for organization in organizations},
        key=len,
        reverse=True,
    )
    for article, event_type, organizations in parsed:
        if not event_type:
            continue
        if not organizations:
            organizations = _alias_organizations(_headline(article), known, article)
        for organization in organizations:
            candidates[(organization, _event_family(event_type))].append(article)
    groups: list[tuple[str, str, list[dict[str, Any]]]] = []
    for (organization, _), members in candidates.items():
        dated = sorted(members, key=lambda item: _published(item) or datetime.max.replace(tzinfo=timezone.utc))
        for window in _time_windows(dated):
            related_groups = _merge_signal_groups(_signal_groups(window, organization), organization)
            groups.extend(
                (organization, _group_event_type(related), related)
                for related in related_groups
            )
    return groups


def _alias_organizations(title: str, known: list[str], article: dict[str, Any]) -> list[str]:
    signals = [match.span() for match in _INCIDENT_SIGNAL.finditer(title)]
    if not signals:
        return []
    candidates: list[tuple[int, int, str]] = []
    asset_tags = {_text(value).casefold() for value in _list(article.get("asset_tags"))}
    for name in known:
        if name.casefold() in asset_tags or _geographic_name(name):
            continue
        match = re.search(rf"(?<!\w){re.escape(name)}(?!\w)", title, re.IGNORECASE)
        if match is None:
            continue
        distance = min(
            abs((match.start() + match.end()) - (start + end))
            for start, end in signals
        )
        candidates.append((distance, -len(name), name))
    return [min(candidates)[2]] if candidates else []


@lru_cache(maxsize=512)
def _geographic_name(name: str) -> bool:
    from modules.region_inferrer import _COUNTRY_PATTERNS
    return any(pattern.fullmatch(name) for pattern, _ in _COUNTRY_PATTERNS)


def _time_windows(members: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    windows: list[list[dict[str, Any]]] = []
    for member in members:
        published = _published(member)
        previous = _published(windows[-1][-1]) if windows else None
        if windows and published and previous and published - previous <= CORRELATION_WINDOW:
            windows[-1].append(member)
        elif windows and published is None and previous is None:
            windows[-1].append(member)
        else:
            windows.append([member])
    return windows


def _title_tokens(article: dict[str, Any], organization: str) -> set[str]:
    title = _headline(article)
    tokens = {token for token in re.findall(r"[a-z0-9]{4,}", title.casefold()) if token not in _TITLE_STOP}
    return tokens - set(re.findall(r"[a-z0-9]{4,}", organization.casefold()))


def _structured_org(article: dict[str, Any], organization: str) -> bool:
    values = [*_list(article.get("victim_organizations")), *_list(article.get("affected_organizations"))]
    return any(_text(value).casefold() == organization.casefold() for value in values)


def _shared_structured_signal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    for field in ("affected_products",):
        left_values = {_text(value).casefold() for value in _list(left.get(field)) if _text(value)}
        right_values = {_text(value).casefold() for value in _list(right.get(field)) if _text(value)}
        if left_values & right_values:
            return True
    left_techniques = {_text(value.get("technique_id") or value.get("id")) for value in _list(left.get("attack_techniques")) if isinstance(value, dict)}
    right_techniques = {_text(value.get("technique_id") or value.get("id")) for value in _list(right.get("attack_techniques")) if isinstance(value, dict)}
    return len((left_techniques - {""}) & (right_techniques - {""})) >= 2


def _related(left: dict[str, Any], right: dict[str, Any], organization: str) -> bool:
    if _structured_org(left, organization) and _structured_org(right, organization):
        return True
    if _shared_structured_signal(left, right):
        return True
    overlap = _title_tokens(left, organization) & _title_tokens(right, organization)
    if len(overlap) >= 2:
        return True
    return False


def _signal_groups(members: list[dict[str, Any]], organization: str) -> list[list[dict[str, Any]]]:
    parents = list(range(len(members)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for left in range(len(members)):
        for right in range(left + 1, len(members)):
            if _related(members[left], members[right], organization):
                parents[find(right)] = find(left)
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, member in enumerate(members):
        grouped[find(index)].append(member)
    return list(grouped.values())


def _component_related(left: list[dict[str, Any]], right: list[dict[str, Any]], organization: str) -> bool:
    if len(left) < 2 or len(right) < 2:
        return False
    left_dates = [value for item in left if (value := _published(item))]
    right_dates = [value for item in right if (value := _published(item))]
    if not left_dates or not right_dates:
        return False
    gap = max(min(right_dates) - max(left_dates), min(left_dates) - max(right_dates), timedelta())
    if gap > timedelta(hours=24):
        return False
    left_tokens = set().union(*(_title_tokens(item, organization) for item in left))
    right_tokens = set().union(*(_title_tokens(item, organization) for item in right))
    return bool(left_tokens & right_tokens)


def _merge_signal_groups(groups: list[list[dict[str, Any]]], organization: str) -> list[list[dict[str, Any]]]:
    merged = [list(group) for group in groups]
    changed = True
    while changed:
        changed = False
        for left in range(len(merged)):
            match = next(
                (right for right in range(left + 1, len(merged)) if _component_related(merged[left], merged[right], organization)),
                None,
            )
            if match is None:
                continue
            merged[left] = [*merged[left], *merged.pop(match)]
            changed = True
            break
    return merged


def _structured_claims(member: dict[str, Any]) -> list[dict[str, Any]]:
    article_id = _article_id(member)
    claims = []
    for raw in _list(member.get("incident_claims")):
        if not isinstance(raw, dict) or not _text(raw.get("statement")):
            continue
        source_ids = [_text(value) for value in _list(raw.get("source_ids"))] or [article_id]
        state = _text(raw.get("state")).casefold() or "reported"
        authoritative = member.get("authoritative_source") is True or raw.get("authoritative") is True
        claims.append({
            "subject": _text(raw.get("subject")) or "finding",
            "statement": _text(raw.get("statement"))[:500],
            "state": "reported" if state == "confirmed" and not authoritative else state,
            "confidence": _text(raw.get("confidence")).casefold() or "medium",
            "source_ids": source_ids,
        })
    return claims


def _tactical_claims(member: dict[str, Any]) -> list[dict[str, Any]]:
    tactical = member.get("tactical_analysis")
    if not isinstance(tactical, dict):
        return []
    confidence = _text(tactical.get("confidence")).casefold()
    confidence = confidence if confidence in _CONFIDENCE else "low"
    claims = []
    fields = {
        "summary": "intrusion_path", "ttps": "technique", "persistence": "persistence",
        "lateral_movement": "lateral_movement", "impact": "impact",
    }
    for field, subject in fields.items():
        values = [tactical.get(field)] if field == "summary" else _list(tactical.get(field))
        for value in values:
            if _text(value):
                claims.append({
                    "subject": subject,
                    "statement": _text(value)[:500],
                    "state": "assessed",
                    "confidence": confidence,
                    "source_ids": [_article_id(member)],
                })
    return claims


def _claims(organization: str, event_type: str, members: list[dict[str, Any]], sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    source_ids = [source["article_id"] for source in sources]
    base = [{
        "subject": "event",
        "statement": f"{len(sources)} source{'s' if len(sources) != 1 else ''} report {event_type.replace('_', ' ')} affecting {organization}.",
        "state": "reported",
        "confidence": "high" if len({s["source_family"] for s in sources}) >= 3 else "medium",
        "source_ids": source_ids,
    }]
    candidates = [*base]
    for member in members:
        candidates.extend(_structured_claims(member))
        candidates.extend(_tactical_claims(member))
    valid = _valid_claims(candidates, set(source_ids))
    return _mark_disputes(_merge_claims(valid))[:MAX_CLAIMS]


def _valid_claims(claims: list[dict[str, Any]], valid_ids: set[str]) -> list[dict[str, Any]]:
    valid = []
    for claim in claims:
        ids = [value for value in claim.get("source_ids", []) if value in valid_ids]
        state = claim.get("state") if claim.get("state") in _CLAIM_STATES else "reported"
        confidence = claim.get("confidence") if claim.get("confidence") in _CONFIDENCE else "low"
        if ids and _text(claim.get("statement")):
            valid.append({**claim, "state": state, "confidence": confidence, "source_ids": ids})
    return valid


def _merge_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for claim in claims:
        key = (_text(claim.get("subject")), _text(claim.get("statement")).casefold())
        if key not in merged:
            merged[key] = claim
            continue
        ids = list(dict.fromkeys([*merged[key]["source_ids"], *claim["source_ids"]]))
        merged[key] = {**merged[key], "source_ids": ids}
    return list(merged.values())


def _mark_disputes(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_subject: dict[str, set[str]] = defaultdict(set)
    for claim in claims:
        if claim["subject"] not in {"event", "finding", "impact", "technique"}:
            by_subject[claim["subject"]].add(claim["statement"].casefold())
    disputed = {subject for subject, values in by_subject.items() if len(values) > 1}
    return [{**claim, "state": "disputed"} if claim["subject"] in disputed else claim for claim in claims]


def _techniques(members: list[dict[str, Any]]) -> list[dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for member in members:
        for raw in _list(member.get("attack_techniques")):
            if isinstance(raw, dict):
                technique_id = _text(raw.get("technique_id") or raw.get("id")).upper()
                name = _text(raw.get("technique_name") or raw.get("name"))
                tactic = _text(raw.get("tactic"))
            else:
                rendered = _text(raw)
                technique_id, name, tactic = rendered.split(" ", 1)[0], rendered, ""
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
                found[technique_id] = {"id": technique_id, "name": name, "tactic": tactic}
    return [found[key] for key in sorted(found)][:20]


def _observables(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found: dict[tuple[str, str], set[str]] = defaultdict(set)
    for member in members:
        raw = member.get("iocs")
        if not isinstance(raw, dict):
            continue
        for kind, values in raw.items():
            for value in _list(values):
                rendered = _text(value.get("value") if isinstance(value, dict) else value)
                if rendered:
                    found[(_text(kind), rendered)].add(_article_id(member))
    return [
        {"type": key[0], "value": key[1], "state": "reported", "source_ids": sorted(ids)}
        for key, ids in list(found.items())[:30]
    ]


def _score(record: dict[str, Any], now: datetime) -> int:
    independent = record["independent_source_count"]
    evidence = 25 if independent >= 3 else 18 if independent == 2 else 5
    impact_text = " ".join(record["impact"] + [record["summary"]]).casefold()
    operational = any(term in impact_text for term in ("halt", "outage", "disrupt", "suspend", "encrypt"))
    impact = 25 if operational and record["event_type"] == "ransomware" else 20 if operational else 15
    assessed = [claim for claim in record["claims"] if claim["state"] in {"assessed", "disputed"}]
    technical = 15 if len(assessed) >= 3 else 10 if assessed else 5 if record["techniques"] else 0
    age = now - (parse_datetime(record["last_updated"]) or now)
    recency = 15 if age <= timedelta(hours=24) else 10 if age <= timedelta(hours=72) else 5 if age <= timedelta(days=7) else 0
    detection = 10 if record["observables"] else 7 if record["techniques"] else 5 if assessed else 0
    critical = {"energy", "finance", "government", "healthcare", "transportation", "critical infrastructure"}
    sector = 10 if any(value.casefold() in critical for value in record["sectors"]) else 5
    score = evidence + impact + technical + recency + detection + sector
    if independent < 2:
        return min(score, 39)
    has_confirmed_claim = any(claim["state"] == "confirmed" for claim in record["claims"])
    return min(score, 100 if has_confirmed_claim else 79)


def _record_id(organization: str, event_type: str, first_seen: str, seed: str) -> str:
    date = (parse_datetime(first_seen) or datetime.now(timezone.utc)).date().isoformat()
    identity = f"{organization.casefold()}|{_event_family(event_type)}|{date}|{seed}"
    digest = hashlib.sha256(identity.encode()).hexdigest()[:18]
    return f"incident-{digest}"


def _matching_previous(
    previous: dict[str, Any], organization: str, event_type: str, first_seen: str,
    source_ids: set[str], excluded_ids: set[str],
) -> dict[str, Any] | None:
    current_first = parse_datetime(first_seen)
    candidates = []
    for record in _list(previous.get("records")):
        if not isinstance(record, dict):
            continue
        if _text(record.get("id")) in excluded_ids:
            continue
        same_org = _text(record.get("organization")).casefold() == organization.casefold()
        same_family = _event_family(_text(record.get("event_type"))) == _event_family(event_type)
        if not same_org or not same_family:
            continue
        old_first = parse_datetime(record.get("first_seen"))
        if not current_first or not old_first or abs(current_first - old_first) <= timedelta(days=7):
            old_ids = {source["article_id"] for source in _list(record.get("sources")) if isinstance(source, dict) and source.get("article_id")}
            overlap = len(source_ids & old_ids)
            distance = abs((current_first - old_first).total_seconds()) if current_first and old_first else 0
            candidates.append((-overlap, distance, record))
    return min(candidates, key=lambda item: (item[0], item[1]))[2] if candidates else None


def _times(members: list[dict[str, Any]], generated_at: str) -> tuple[str, str]:
    dates = [value for member in members if (value := _published(member))]
    if not dates:
        return generated_at, generated_at
    return min(dates).isoformat(), max(dates).isoformat()


def _summary(organization: str, event_type: str, claims: list[dict[str, Any]]) -> str:
    tactical = next((claim["statement"] for claim in claims if claim["subject"] == "intrusion_path"), "")
    if tactical:
        return tactical[:500]
    return f"Independent reporting describes a {event_type.replace('_', ' ')} affecting {organization}."


def _base_record(organization: str, event_type: str, members: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    sources = _sources(members)
    claims = _claims(organization, event_type, members, sources)
    first_seen, last_updated = _times(members, generated_at)
    techniques = _techniques(members)
    observables = _observables(members)
    impact = [claim["statement"] for claim in claims if claim["subject"] == "impact"]
    sectors = sorted({str(value) for member in members for value in _list(member.get("victim_sectors"))})
    independent = len({source["source_family"] for source in sources})
    state = "corroborated" if independent >= 2 else "developing"
    record = {
        "organization": organization, "event_type": event_type, "state": state,
        "title": f"{organization} {event_type.replace('_', ' ')}",
        "summary": _summary(organization, event_type, claims),
        "first_seen": first_seen, "last_updated": last_updated,
        "source_count": len(sources), "independent_source_count": independent,
        "confidence": "high" if independent >= 3 and techniques else "medium" if independent >= 2 else "low",
        "sources": sources, "claims": claims, "impact": impact,
        "techniques": techniques, "observables": observables, "sectors": sectors,
        "affected_assets": sorted({str(value) for member in members for value in _list(member.get("affected_products"))}),
    }
    score = _score(record, parse_datetime(generated_at) or datetime.now(timezone.utc))
    priority = "critical" if score >= 80 else "high" if score >= TODAY_THRESHOLD else "monitored" if score >= 40 else "developing"
    action = "Hunt the published observables and preserve matching telemetry." if observables else "Validate exposure and inspect telemetry for the reported techniques." if techniques else "Monitor corroborating evidence and validate whether the incident affects your environment."
    questions = []
    if not any(claim["subject"] == "initial_access" for claim in claims):
        questions.append("The initial access path is not confirmed")
    if not observables:
        questions.append("No source-bound observables are available")
    return {**record, "score": score, "priority": priority, "recommended_action": action, "open_questions": questions}


def _tracked(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": record["state"], "priority": record["priority"],
        "source_count": record["source_count"],
        "independent_source_count": record["independent_source_count"],
        "observable_count": len(record["observables"]),
        "claim_states": sorted((claim["subject"], claim["state"], claim["statement"]) for claim in record["claims"]),
    }


def _change(record_id: str, field: str, before: Any, after: Any, changed_at: str) -> dict[str, Any]:
    identity = f"{record_id}|{field}|{after}|{changed_at}"
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:20],
        "record_id": record_id, "field": field, "previous": before, "current": after,
        "changed_at": changed_at,
        "summary": "ThreatWatch began tracking this incident." if field == "record" else f"Incident {field.replace('_', ' ')} changed.",
    }


def _versioned(record: dict[str, Any], previous: dict[str, Any] | None, generated_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    seed = _text(record["sources"][0].get("article_id")) if record.get("sources") else record["summary"]
    record_id = previous.get("id") if previous else _record_id(record["organization"], record["event_type"], record["first_seen"], seed)
    if previous is None:
        events = [_change(record_id, "record", None, "active", generated_at)]
        return {**record, "id": record_id, "version": 1, "last_changed": generated_at, "changes": events}, events
    events = []
    before, after = _tracked(previous), _tracked(record)
    for field, value in after.items():
        if before.get(field) != value:
            events.append(_change(record_id, field, before.get(field), value, generated_at))
    history = [*events, *[value for value in _list(previous.get("changes")) if isinstance(value, dict)]][:MAX_CHANGES]
    version = int(previous.get("version") or 1) + (1 if events else 0)
    last_changed = generated_at if events else previous.get("last_changed") or generated_at
    return {**record, "id": record_id, "version": version, "last_changed": last_changed, "changes": history}, events


def _empty() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION, "generated_at": None,
        "summary": {"total_records": 0, "high_priority": 0, "developing": 0},
        "run_change_count": 0, "changes": [], "records": [],
    }


def build_incident_records(
    articles: list[dict[str, Any]], previous: dict[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Correlate articles into bounded records without requiring model output."""
    now = _now(generated_at)
    generated = now.isoformat()
    previous_data = previous if isinstance(previous, dict) else _empty()
    records, changes = [], []
    used_previous_ids: set[str] = set()
    for organization, event_type, members in _candidate_groups(articles):
        base = _base_record(organization, event_type, members, generated)
        source_ids = {source["article_id"] for source in base["sources"]}
        old = _matching_previous(
            previous_data, organization, event_type, base["first_seen"], source_ids, used_previous_ids,
        )
        if old and old.get("id"):
            used_previous_ids.add(str(old["id"]))
        record, events = _versioned(base, old, generated)
        records.append(record)
        changes.extend(events)
    records.sort(key=lambda item: (-item["score"], item["title"].casefold()))
    records = records[:MAX_RECORDS]
    return {
        "schema_version": SCHEMA_VERSION, "generated_at": generated,
        "summary": {
            "total_records": len(records),
            "high_priority": sum(record["score"] >= TODAY_THRESHOLD for record in records),
            "developing": sum(record["state"] == "developing" for record in records),
        },
        "run_change_count": len(changes), "changes": changes[:200], "records": records,
    }


def write_incident_records(articles: list[dict[str, Any]]) -> dict[str, Any]:
    payload = build_incident_records(articles, previous=load_incident_records())
    write_json_atomic(INCIDENTS_PATH, payload, ensure_ascii=False)
    return payload


def load_incident_records() -> dict[str, Any]:
    if not INCIDENTS_PATH.exists():
        return _empty()
    try:
        with open(INCIDENTS_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
            return _empty()
        return payload
    except (OSError, json.JSONDecodeError):
        return _empty()
