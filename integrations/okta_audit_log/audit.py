"""
Okta Audit Log → Confluence

Polls the Okta System Log for new groups, new apps, and new group→app
assignments, then appends rows to a monthly Confluence page. A parent index
page links to each month and tracks running counts.

Designed to be run on a schedule (every ~15 minutes) by a GitHub Actions
workflow. State is persisted in a hidden HTML comment on the index page, so
no external storage is required.
"""

from __future__ import annotations

import html
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("okta_audit")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

OKTA_DOMAIN = os.environ["OKTA_DOMAIN"].rstrip("/").replace("https://", "")
OKTA_API_TOKEN = os.environ["OKTA_API_TOKEN"]
OKTA_ADMIN_URL = os.environ.get(
    "OKTA_ADMIN_URL",
    f"https://{OKTA_DOMAIN.replace('.okta.com', '-admin.okta.com')}",
).rstrip("/")

CONFLUENCE_BASE_URL = os.environ["CONFLUENCE_BASE_URL"].rstrip("/")
CONFLUENCE_EMAIL = os.environ["CONFLUENCE_EMAIL"]
CONFLUENCE_API_TOKEN = os.environ["CONFLUENCE_API_TOKEN"]
CONFLUENCE_SPACE_KEY = os.environ["CONFLUENCE_SPACE_KEY"]
CONFLUENCE_INDEX_PAGE_ID = os.environ["CONFLUENCE_INDEX_PAGE_ID"]

EVENT_TYPES = (
    "group.lifecycle.create",
    "application.lifecycle.create",
    "group.application_assignment.add",
)

STATE_MARKER = "okta_audit_last_seen"
STATE_RE = re.compile(rf"<!--\s*{STATE_MARKER}:\s*([^\s]+?)\s*-->")
BOOTSTRAP_LOOKBACK = timedelta(minutes=15)


# --------------------------------------------------------------------------- #
# Okta
# --------------------------------------------------------------------------- #

def okta_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
    })
    return s


def fetch_events(since: datetime) -> list[dict]:
    """Fetch every matching System Log event published at or after ``since``."""
    s = okta_session()
    url = f"https://{OKTA_DOMAIN}/api/v1/logs"
    params = {
        "since": since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "filter": " or ".join(f'eventType eq "{et}"' for et in EVENT_TYPES),
        "limit": "200",
        "sortOrder": "ASCENDING",
    }
    events: list[dict] = []
    while True:
        r = s.get(url, params=params, timeout=30)
        r.raise_for_status()
        batch = r.json()
        events.extend(batch)
        next_url = _next_link(r.headers.get("Link", ""))
        if not next_url or not batch:
            break
        url, params = next_url, None
    log.info("Fetched %d Okta events since %s", len(events), since.isoformat())
    return events


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Confluence
# --------------------------------------------------------------------------- #

def confluence_session() -> requests.Session:
    s = requests.Session()
    s.auth = (CONFLUENCE_EMAIL, CONFLUENCE_API_TOKEN)
    s.headers.update({"Accept": "application/json"})
    return s


def get_page(page_id: str) -> dict:
    s = confluence_session()
    r = s.get(
        f"{CONFLUENCE_BASE_URL}/rest/api/content/{page_id}",
        params={"expand": "body.storage,version,ancestors"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def find_page_by_title(title: str) -> dict | None:
    s = confluence_session()
    r = s.get(
        f"{CONFLUENCE_BASE_URL}/rest/api/content",
        params={
            "spaceKey": CONFLUENCE_SPACE_KEY,
            "title": title,
            "expand": "body.storage,version",
        },
        timeout=30,
    )
    r.raise_for_status()
    results = r.json().get("results", [])
    return results[0] if results else None


def create_page(title: str, body: str, parent_id: str) -> dict:
    s = confluence_session()
    r = s.post(
        f"{CONFLUENCE_BASE_URL}/rest/api/content",
        json={
            "type": "page",
            "title": title,
            "space": {"key": CONFLUENCE_SPACE_KEY},
            "ancestors": [{"id": parent_id}],
            "body": {"storage": {"value": body, "representation": "storage"}},
        },
        timeout=30,
    )
    r.raise_for_status()
    log.info("Created Confluence page %r", title)
    return r.json()


def update_page(page: dict, new_body: str) -> dict:
    s = confluence_session()
    r = s.put(
        f"{CONFLUENCE_BASE_URL}/rest/api/content/{page['id']}",
        json={
            "id": page["id"],
            "type": "page",
            "title": page["title"],
            "version": {"number": page["version"]["number"] + 1},
            "body": {"storage": {"value": new_body, "representation": "storage"}},
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #

@dataclass
class Counts:
    groups: int = 0
    apps: int = 0
    assignments: int = 0


def _link(kind: str, target: dict) -> str:
    name = html.escape(target.get("displayName") or "?")
    tid = target.get("id")
    if not tid:
        return name
    if kind == "group":
        href = f"{OKTA_ADMIN_URL}/admin/group/{tid}"
    elif kind == "app":
        href = f"{OKTA_ADMIN_URL}/admin/app/{tid}"
    else:
        return name
    return f'<a href="{html.escape(href, quote=True)}">{name}</a>'


def event_to_row(event: dict) -> tuple[str, str]:
    """Return ``(category, row_xhtml)`` where category is one of group/app/assignment."""
    when = event["published"]
    actor = html.escape(event.get("actor", {}).get("displayName") or "Unknown")
    targets = {t.get("type"): t for t in event.get("target") or []}
    etype = event["eventType"]

    if etype == "group.lifecycle.create":
        category = "group"
        label = "Group Created"
        detail = _link("group", targets.get("UserGroup", {}))
    elif etype == "application.lifecycle.create":
        category = "app"
        label = "App Added"
        detail = _link("app", targets.get("AppInstance", {}))
    elif etype == "group.application_assignment.add":
        category = "assignment"
        label = "Group → App Assignment"
        group = _link("group", targets.get("UserGroup", {}))
        app = _link("app", targets.get("AppInstance", {}))
        detail = f"{group} → {app}"
    else:
        category = "other"
        label = html.escape(etype)
        detail = ", ".join(
            html.escape(t.get("displayName") or "?") for t in event.get("target") or []
        )

    row = (
        "<tr>"
        f"<td>{html.escape(when)}</td>"
        f"<td>{actor}</td>"
        f"<td>{label}</td>"
        f"<td>{detail}</td>"
        "</tr>"
    )
    return category, row


# --------------------------------------------------------------------------- #
# Page bodies
# --------------------------------------------------------------------------- #

MONTH_HEADER = (
    "<p>Automatically updated audit log of new Okta groups, apps, and "
    "group→app assignments for {label}. Most recent events at the top.</p>"
)

MONTH_TEMPLATE = (
    "{header}"
    "<table>"
    "<thead><tr>"
    "<th>When (UTC)</th><th>Actor</th><th>Type</th><th>Detail</th>"
    "</tr></thead>"
    "<tbody></tbody>"
    "</table>"
)

INDEX_HEADER = (
    "<p>This page is updated automatically every 15 minutes by the "
    "<code>okta_audit_log</code> integration. Each row links to a monthly "
    "audit page showing every new Okta group, app, and group→app assignment "
    "for that month.</p>"
)

INDEX_TEMPLATE = (
    "{state}"
    "{header}"
    "<table>"
    "<thead><tr>"
    "<th>Month</th><th>Page</th>"
    "<th>Groups Created</th><th>Apps Added</th><th>Assignments</th>"
    "</tr></thead>"
    "<tbody></tbody>"
    "</table>"
)


def month_label(dt: datetime) -> str:
    return dt.strftime("%B %Y")


def month_key(dt: datetime) -> str:
    return dt.strftime("%Y-%m")


def month_title(dt: datetime) -> str:
    return f"Okta Audit — {month_key(dt)}"


def insert_rows_in_tbody(body: str, rows_html: str) -> str:
    """Insert ``rows_html`` immediately after the first ``<tbody>`` tag.

    Falls back to inserting before ``</table>`` if Confluence stripped the
    ``<tbody>`` wrapper.
    """
    if "<tbody>" in body:
        return body.replace("<tbody>", "<tbody>" + rows_html, 1)
    if "</table>" in body:
        return body.replace("</table>", rows_html + "</table>", 1)
    return body + rows_html


# --------------------------------------------------------------------------- #
# State (last-seen timestamp lives in a hidden comment on the index page)
# --------------------------------------------------------------------------- #

def read_last_seen(index_body: str) -> datetime:
    m = STATE_RE.search(index_body)
    if not m:
        return datetime.now(timezone.utc) - BOOTSTRAP_LOOKBACK
    try:
        return datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
    except ValueError:
        log.warning("Could not parse last_seen %r, falling back to lookback", m.group(1))
        return datetime.now(timezone.utc) - BOOTSTRAP_LOOKBACK


def write_last_seen(index_body: str, when: datetime) -> str:
    iso = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    marker = f"<!-- {STATE_MARKER}: {iso} -->"
    if STATE_RE.search(index_body):
        return STATE_RE.sub(marker, index_body, count=1)
    return marker + index_body


# --------------------------------------------------------------------------- #
# Monthly + index updates
# --------------------------------------------------------------------------- #

def ensure_monthly_page(when: datetime) -> dict:
    title = month_title(when)
    existing = find_page_by_title(title)
    if existing:
        return get_page(existing["id"])
    body = MONTH_TEMPLATE.format(header=MONTH_HEADER.format(label=month_label(when)))
    page = create_page(title, body, CONFLUENCE_INDEX_PAGE_ID)
    return get_page(page["id"])


def append_to_monthly_page(page: dict, new_rows: list[str]) -> None:
    if not new_rows:
        return
    body = page["body"]["storage"]["value"]
    new_body = insert_rows_in_tbody(body, "".join(new_rows))
    update_page(page, new_body)


def upsert_index_row(index_body: str, key: str, link_html: str, counts: Counts) -> str:
    """Update the index table row for ``key`` (e.g. ``2026-05``), creating it if missing."""
    pattern = re.compile(
        rf'<tr data-month="{re.escape(key)}">.*?</tr>',
        re.DOTALL,
    )
    new_row = (
        f'<tr data-month="{html.escape(key, quote=True)}">'
        f"<td>{html.escape(key)}</td>"
        f"<td>{link_html}</td>"
        f"<td>{counts.groups}</td>"
        f"<td>{counts.apps}</td>"
        f"<td>{counts.assignments}</td>"
        "</tr>"
    )
    if pattern.search(index_body):
        # Existing row: parse current counts, add deltas, write back.
        existing = pattern.search(index_body).group(0)
        nums = re.findall(r"<td>(\d+)</td>", existing)
        if len(nums) >= 3:
            counts = Counts(
                groups=int(nums[0]) + counts.groups,
                apps=int(nums[1]) + counts.apps,
                assignments=int(nums[2]) + counts.assignments,
            )
            new_row = (
                f'<tr data-month="{html.escape(key, quote=True)}">'
                f"<td>{html.escape(key)}</td>"
                f"<td>{link_html}</td>"
                f"<td>{counts.groups}</td>"
                f"<td>{counts.apps}</td>"
                f"<td>{counts.assignments}</td>"
                "</tr>"
            )
        return pattern.sub(new_row, index_body, count=1)
    # New month: prepend to tbody so most recent month is on top.
    return insert_rows_in_tbody(index_body, new_row)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def ensure_index_initialized(page: dict) -> dict:
    """If the index page has no table yet, install the template once."""
    body = page["body"]["storage"]["value"]
    if "<table>" in body:
        return page
    log.info("Initializing index page with template")
    new_body = INDEX_TEMPLATE.format(state="", header=INDEX_HEADER)
    return update_page(page, new_body)


def run() -> int:
    index = get_page(CONFLUENCE_INDEX_PAGE_ID)
    index = ensure_index_initialized(index)
    index_body = index["body"]["storage"]["value"]

    since = read_last_seen(index_body)
    events = fetch_events(since)
    if not events:
        # Still bump the state so we don't repeatedly refetch the same window.
        new_body = write_last_seen(index_body, datetime.now(timezone.utc))
        if new_body != index_body:
            update_page(index, new_body)
        log.info("No new events.")
        return 0

    # Group events by their month so we can append in batches.
    by_month: dict[str, list[tuple[str, dict]]] = {}
    for ev in events:
        when = datetime.fromisoformat(ev["published"].replace("Z", "+00:00"))
        by_month.setdefault(month_key(when), []).append((ev["published"], ev))

    for mkey in sorted(by_month):
        month_events = by_month[mkey]
        when = datetime.fromisoformat(
            month_events[0][0].replace("Z", "+00:00")
        )
        page = ensure_monthly_page(when)

        rows: list[str] = []
        counts = Counts()
        # Newest first in the table -> reverse the ascending fetch order.
        for _, ev in sorted(month_events, key=lambda x: x[0], reverse=True):
            category, row = event_to_row(ev)
            rows.append(row)
            if category == "group":
                counts.groups += 1
            elif category == "app":
                counts.apps += 1
            elif category == "assignment":
                counts.assignments += 1

        append_to_monthly_page(page, rows)

        link_html = (
            f'<a href="{html.escape(CONFLUENCE_BASE_URL, quote=True)}'
            f'/spaces/{html.escape(CONFLUENCE_SPACE_KEY, quote=True)}'
            f'/pages/{html.escape(page["id"], quote=True)}">'
            f'{html.escape(month_title(when))}</a>'
        )
        index_body = upsert_index_row(index_body, mkey, link_html, counts)

    latest = max(ev["published"] for ev in events)
    latest_dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
    index_body = write_last_seen(index_body, latest_dt + timedelta(milliseconds=1))
    update_page(index, index_body)
    log.info("Wrote %d events across %d month(s).", len(events), len(by_month))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except requests.HTTPError as e:
        log.error("HTTP error: %s — %s", e, getattr(e.response, "text", ""))
        sys.exit(1)
    except Exception:
        log.exception("Audit run failed")
        sys.exit(1)
