"""QRadar REST and Ariel access.

Auth is handled by the framework: qpylib.REST injects the authorised service token
that was bound to the app at install time, so the app's visibility equals the
permissions of the service account an admin selected in the Application Assistant.
"""

import json

from qpylib import qpylib
from qpylib.ariel import ArielError, ArielSearch

from . import config

OFFENSE_FIELDS = (
    "id,description,status,magnitude,severity,credibility,relevance,"
    "start_time,last_updated_time,first_persisted_time,last_persisted_time,"
    "offense_type,offense_source,event_count,flow_count,device_count,"
    "source_count,username_count,domain_id,inactive,protected,"
    "source_address_ids,local_destination_address_ids,rules,log_sources"
)


class QRadarError(Exception):
    pass


def _get(url: str, params: dict = None):
    response = qpylib.REST(
        "GET", url, version=config.QRADAR_API_VERSION, params=params or {}
    )
    if response.status_code >= 300:
        raise QRadarError(
            "GET {} -> {} {}".format(url, response.status_code, response.text[:400])
        )
    return response.json()


def _get_paged(url: str, params: dict, start: int, end: int):
    response = qpylib.REST(
        "GET",
        url,
        version=config.QRADAR_API_VERSION,
        params=params,
        headers={"Range": "items={}-{}".format(start, end)},
    )
    if response.status_code >= 300:
        raise QRadarError(
            "GET {} -> {} {}".format(url, response.status_code, response.text[:400])
        )
    return response.json()


def fetch_offenses_since(watermark_ms: int) -> list:
    """All offenses created after the watermark, oldest first.

    Watermarks on first_persisted_time rather than last_persisted_time: we
    investigate on creation only, and first_persisted_time never moves once set.
    """
    collected = []
    start = 0
    while True:
        page = _get_paged(
            "api/siem/offenses",
            {
                "filter": "first_persisted_time > {}".format(int(watermark_ms)),
                "sort": "+first_persisted_time",
                "fields": OFFENSE_FIELDS,
            },
            start,
            start + config.OFFENSE_PAGE_SIZE - 1,
        )
        collected.extend(page)
        if len(page) < config.OFFENSE_PAGE_SIZE:
            return collected
        start += config.OFFENSE_PAGE_SIZE


def resolve_source_addresses(address_ids: list) -> list:
    """The offense object carries address IDs, not IPs. Without this the model
    sees an offense with no addresses in it at all."""
    if not address_ids:
        return []
    ids = ",".join(str(i) for i in address_ids[:100])
    rows = _get(
        "api/siem/source_addresses",
        {"filter": "id in ({})".format(ids), "fields": "id,source_ip,domain_id"},
    )
    return [row.get("source_ip") for row in rows if row.get("source_ip")]


def resolve_destination_addresses(address_ids: list) -> list:
    if not address_ids:
        return []
    ids = ",".join(str(i) for i in address_ids[:100])
    rows = _get(
        "api/siem/local_destination_addresses",
        {"filter": "id in ({})".format(ids), "fields": "id,local_destination_ip,domain_id"},
    )
    return [row.get("local_destination_ip") for row in rows if row.get("local_destination_ip")]


_rule_cache = {}


def resolve_rule_names(rules: list) -> list:
    """Turn {id, type} into {id, type, name}. A small set of rules generates most
    offenses, so the cache collapses this to near-zero calls in steady state."""
    resolved = []
    for rule in rules or []:
        rule_id = rule.get("id")
        name = _rule_cache.get(rule_id)
        if name is None:
            try:
                detail = _get("api/analytics/rules/{}".format(rule_id), {"fields": "id,name"})
                name = detail.get("name") or "rule {}".format(rule_id)
            except QRadarError as error:
                qpylib.log("socai: rule {} lookup failed: {}".format(rule_id, error),
                           level="WARNING")
                name = "rule {}".format(rule_id)
            _rule_cache[rule_id] = name
        resolved.append({"id": rule_id, "type": rule.get("type"), "name": name})
    return resolved


def fetch_offense_events(offense_id: int, start_ms: int, stop_ms: int,
                         limit: int, timeout_seconds: int) -> list:
    """The first `limit` events of an offense, chronologically.

    The time window is always explicit: AQL's default range is short and an
    offense can span days, so omitting START/STOP silently returns nothing.
    """
    query = (
        "SELECT starttime, QIDNAME(qid) AS event_name, "
        "LOGSOURCENAME(logsourceid) AS log_source, CATEGORYNAME(category) AS category, "
        "sourceip, sourceport, destinationip, destinationport, username, "
        "magnitude, severity, credibility, relevance, eventcount, "
        "UTF8(payload) AS payload "
        "FROM events WHERE INOFFENSE({offense_id}) "
        "ORDER BY starttime ASC LIMIT {limit} "
        "START {start} STOP {stop}"
    ).format(offense_id=int(offense_id), limit=int(limit),
             start=int(start_ms), stop=int(stop_ms))

    search = ArielSearch()
    try:
        search_id, _ = search.search_sync(
            query, timeout=timeout_seconds, sleep_interval=5
        )
        payload = search.results(search_id, 0, max(int(limit) - 1, 0))
    except ArielError as error:
        # An offense with no events is still worth a verdict -- metadata and rules
        # alone often suffice to call an obvious false positive.
        raise QRadarError("ariel search failed: {}".format(error))

    if isinstance(payload, str):
        payload = json.loads(payload)
    return payload.get("events", []) if isinstance(payload, dict) else []
