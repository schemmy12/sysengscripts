from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
from dataclasses import asdict
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from watcher import (
    APP_DIR,
    DEFAULT_CONFIG_PATH,
    LATEST_SLOTS_PATH,
    TeeTime,
    load_config,
    load_dotenv,
    notify_new_matches,
    read_json,
    slot_matches_preferences,
    write_json,
)


REPO_ROOT = APP_DIR.parent.parent
CAPTURE_JS_PATH = APP_DIR / "capture.js"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DASHBOARD_PATH = "/integrations/tee_time_alerts/tee_time_dashboard.html"


class CaptureState:
    def __init__(self, config: dict[str, Any], send_sms: bool, dry_run: bool) -> None:
        self.config = config
        self.send_sms = send_sms
        self.dry_run = dry_run


def normalize_slot(raw: dict[str, Any], config: dict[str, Any]) -> TeeTime | None:
    date = str(raw.get("date") or "").strip()
    time_value = str(raw.get("time") or "").strip()
    if not date or not time_value:
        return None

    course = str(raw.get("course") or raw.get("course_name") or config.get("course_name") or "Golf course")
    booking_url = str(raw.get("booking_url") or raw.get("bookingUrl") or config.get("course_url") or "")
    open_spots = int(raw.get("open_spots") or raw.get("openSpots") or 0)
    holes_value = raw.get("holes")
    holes = int(holes_value) if holes_value not in (None, "", "null") else None

    return TeeTime(
        date=date,
        day=str(raw.get("day") or ""),
        time=time_value,
        course=course,
        open_spots=open_spots,
        holes=holes,
        price=str(raw.get("price") or "") or None,
        tee=str(raw.get("tee") or raw.get("side") or "") or None,
        booking_url=booking_url,
        source_text=str(raw.get("source_text") or raw.get("sourceText") or ""),
    )


def existing_slots() -> list[dict[str, Any]]:
    payload = read_json(LATEST_SLOTS_PATH, {})
    slots = payload.get("slots", []) if isinstance(payload, dict) else []
    return slots if isinstance(slots, list) else []


def merge_captured_slots(captured_slots: list[TeeTime], captured_dates: set[str]) -> list[TeeTime]:
    merged: dict[str, TeeTime] = {}

    for raw in existing_slots():
        if not isinstance(raw, dict):
            continue
        slot = normalize_slot(raw, {"course_name": raw.get("course", "Golf course")})
        if not slot or slot.date in captured_dates:
            continue
        merged[slot.id] = slot

    for slot in captured_slots:
        merged[slot.id] = slot

    return sorted(merged.values(), key=lambda item: (item.date, item.time, item.open_spots))


def write_capture_payload(slots: list[TeeTime], matches: list[TeeTime], config: dict[str, Any]) -> None:
    from datetime import datetime, timezone

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "ezlinks_manual_browser_capture",
        "course_name": config.get("course_name"),
        "course_url": config.get("course_url"),
        "preferences": config.get("preferences", {}),
        "slots": [asdict(slot) | {"id": slot.id} for slot in slots],
        "matches": [asdict(slot) | {"id": slot.id} for slot in matches],
    }
    write_json(LATEST_SLOTS_PATH, payload)


def bookmarklet_url(host: str, port: int) -> str:
    js_url = f"http://{host}:{port}/capture.js"
    return (
        "javascript:(()=>{"
        "const s=document.createElement('script');"
        f"s.src='{js_url}?t='+Date.now();"
        "document.body.appendChild(s);"
        "})()"
    )


def copy_bookmarklet_url(host: str, port: int) -> str:
    endpoint = f"http://{host}:{port}/capture"
    code = f"""
    (() => {{
      const timePattern = /\\b(?:1[0-2]|0?[1-9]):[0-5]\\d\\s*(?:AM|PM)\\b/i;
      const playerPattern = /\\b\\d+\\s*[-\\u2013\\u2014]\\s*\\d+\\s*Players?\\b|\\b\\d+\\s*Players?\\b/i;
      const textOf = (node) => ((node && (node.innerText || node.textContent)) || "").replace(/\\s+/g, " ").trim();
      const dateText = (Array.from(document.querySelectorAll("input")).map((input) => input.value || input.getAttribute("value") || "").join(" ") + " " + textOf(document.body)).match(/\\b\\d{{1,2}}\\/\\d{{1,2}}\\/\\d{{4}}\\b/)?.[0] || prompt("Tee sheet date (MM/DD/YYYY)", "");
      const dateMatch = String(dateText || "").match(/^(\\d{{1,2}})\\/(\\d{{1,2}})\\/(\\d{{4}})$/);
      if (!dateMatch) throw new Error("Could not determine date.");
      const date = `${{dateMatch[3]}}-${{dateMatch[1].padStart(2, "0")}}-${{dateMatch[2].padStart(2, "0")}}`;
      const parsedDate = new Date(Number(dateMatch[3]), Number(dateMatch[1]) - 1, Number(dateMatch[2]));
      const day = parsedDate.toLocaleDateString(undefined, {{ weekday: "long" }});
      const bodyText = textOf(document.body);
      const course = bodyText.match(/Course:\\s*([^0-9$]+?)(?:\\s{{2,}}|$|Players?|Holes?|tee times?)/i)?.[1]?.trim() || document.title || "EZLinks tee sheet";
      const cards = Array.from(document.querySelectorAll("article, li, section, div"))
        .map((el) => {{
          const text = textOf(el);
          const rect = el.getBoundingClientRect();
          return {{ el, text, area: rect.width * rect.height, y: rect.y, width: rect.width, height: rect.height }};
        }})
        .filter((card) => timePattern.test(card.text) && playerPattern.test(card.text) && card.width >= 80 && card.height >= 60 && card.width <= 700 && card.height <= 560 && card.text.length <= 520)
        .sort((a, b) => a.area - b.area)
        .reduce((selected, card) => {{
          if (!selected.some((other) => card.el.contains(other.el) || other.el.contains(card.el))) selected.push(card);
          return selected;
        }}, [])
        .sort((a, b) => a.y - b.y);
      const slots = cards.map((card) => {{
        const text = card.text;
        const range = text.match(/\\b(\\d+)\\s*[-\\u2013\\u2014]\\s*(\\d+)\\s*Players?\\b/i);
        const single = text.match(/\\b(\\d+)\\s*Players?\\b/i);
        const price = text.match(/\\$\\s*\\d+(?:\\.\\d{{2}})?/)?.[0]?.replace(/\\s+/g, "") || "";
        const holes = text.replace(/\\$\\s*\\d+(?:\\.\\d{{2}})?/g, " ").match(/(?:^|\\D)(9|18)(?:\\D|$)/)?.[1] || null;
        return {{
          date,
          day,
          time: text.match(timePattern)?.[0]?.replace(/\\s+/g, " ").toUpperCase() || "",
          course,
          open_spots: range ? Number(range[2]) : (single ? Number(single[1]) : 0),
          holes: holes ? Number(holes) : null,
          price,
          tee: /front/i.test(text) ? "Front nine" : (/back/i.test(text) ? "Back nine" : null),
          booking_url: card.el.querySelector("a[href]")?.href || location.href,
          source_text: text
        }};
      }});
      const payload = {{ page_url: location.href, course_name: course, captured_dates: [date], slots }};
      const json = JSON.stringify(payload);
      navigator.clipboard.writeText(json).then(() => alert(`Copied ${{slots.length}} tee times. Paste them into the capture helper import box.`)).catch(() => prompt("Copy captured tee times JSON", json));
    }})().catch((error) => alert(`Capture failed: ${{error.message}}`));
    """
    compact = " ".join(line.strip() for line in code.strip().splitlines())
    return "javascript:" + compact


def capture_home(host: str, port: int) -> str:
    bookmarklet = bookmarklet_url(host, port)
    copy_bookmarklet = copy_bookmarklet_url(host, port)
    dashboard = f"http://{host}:{port}{DASHBOARD_PATH}"
    bookmarklet_attr = escape(bookmarklet, quote=True)
    copy_bookmarklet_attr = escape(copy_bookmarklet, quote=True)
    dashboard_attr = escape(dashboard, quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tee Time Radar Capture</title>
<style>
body {{
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #f5f0e7;
  color: #173d33;
}}
main {{
  max-width: 860px;
  margin: 0 auto;
  padding: 42px 22px;
}}
.card {{
  background: #fffdf8;
  border: 1px solid #d9e2dc;
  border-radius: 8px;
  box-shadow: 0 14px 34px rgba(24, 61, 51, .12);
  padding: 24px;
}}
h1 {{
  margin: 0 0 10px;
  font-size: clamp(32px, 5vw, 54px);
  line-height: 1;
}}
p, li {{
  color: #526963;
  font-size: 15px;
  line-height: 1.6;
}}
.bookmark {{
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  padding: 10px 14px;
  border-radius: 7px;
  background: #183d33;
  color: #fff;
  font-weight: 900;
  text-decoration: none;
}}
.actions {{
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 18px 0;
}}
.secondary {{
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  padding: 10px 14px;
  border: 1px solid #d9e2dc;
  border-radius: 7px;
  color: #183d33;
  background: #fff;
  font-weight: 900;
  text-decoration: none;
}}
textarea {{
  width: 100%;
  min-height: 130px;
  border: 1px solid #d9e2dc;
  border-radius: 7px;
  padding: 10px;
  font: 13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
}}
button {{
  display: inline-flex;
  align-items: center;
  min-height: 40px;
  padding: 9px 13px;
  border: 0;
  border-radius: 7px;
  background: #e7b84f;
  color: #2b2412;
  font-weight: 900;
  cursor: pointer;
}}
.status {{
  min-height: 24px;
  margin-top: 10px;
  color: #526963;
  font-weight: 800;
}}
code {{
  background: #eef5f0;
  padding: 2px 5px;
  border-radius: 4px;
}}
</style>
</head>
<body>
<main>
  <div class="card">
    <h1>Tee Time Radar Capture</h1>
    <p>This local helper captures tee times that are already visible in your normal EZLinks browser tab and writes <code>latest_slots.json</code> for the dashboard.</p>
    <div class="actions">
      <a class="bookmark" href="{bookmarklet_attr}">Capture Tee Times</a>
      <a class="secondary" href="{copy_bookmarklet_attr}">Copy Tee Times JSON</a>
      <a class="secondary" href="{dashboard_attr}">Open Dashboard</a>
    </div>
    <ol>
      <li>Drag <strong>Capture Tee Times</strong> to your bookmarks bar.</li>
      <li>Open EZLinks normally, sign in, and search a tee-sheet date.</li>
      <li>When tee-time cards are visible, click the bookmark.</li>
      <li>Repeat on each Saturday/Sunday date you want on the dashboard.</li>
    </ol>
    <p>If dragging a bookmark acts weird, use the backup copy button and paste it as a bookmark URL manually.</p>
    <div class="actions"><button id="copy-bookmarklet" type="button">Copy Backup Bookmarklet</button></div>
    <textarea id="bookmarklet-code" hidden>{copy_bookmarklet_attr}</textarea>
    <p>If the direct capture bookmark does not update the dashboard, use <strong>Copy Tee Times JSON</strong>, then paste here:</p>
    <textarea id="import-json" placeholder="Paste copied tee-time JSON here"></textarea>
    <div class="actions"><button id="import-btn" type="button">Import Captured JSON</button></div>
    <div class="status" id="status"></div>
  </div>
</main>
<script>
document.getElementById("import-btn").addEventListener("click", async () => {{
  const status = document.getElementById("status");
  try {{
    const payload = JSON.parse(document.getElementById("import-json").value);
    const response = await fetch("/capture", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || `HTTP ${{response.status}}`);
    status.textContent = `Imported ${{result.slots}} visible slots. Dashboard matches: ${{result.matches}}.`;
  }} catch (error) {{
    status.textContent = `Import failed: ${{error.message}}`;
  }}
}});
document.getElementById("copy-bookmarklet").addEventListener("click", async () => {{
  const status = document.getElementById("status");
  const value = document.getElementById("bookmarklet-code").value;
  try {{
    await navigator.clipboard.writeText(value);
    status.textContent = "Backup bookmarklet copied. Create a bookmark manually and paste it as the URL.";
  }} catch {{
    window.prompt("Copy backup bookmarklet", value);
  }}
}});
</script>
</body>
</html>"""


class CaptureHandler(BaseHTTPRequestHandler):
    state: CaptureState
    host_name: str
    port_number: int

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.cors()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path in {"/", "/capture"}:
            self.send_text(HTTPStatus.OK, capture_home(self.host_name, self.port_number))
            return
        if path == "/dashboard":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", DASHBOARD_PATH)
            self.end_headers()
            return
        if path == "/capture.js":
            self.serve_file(CAPTURE_JS_PATH, "application/javascript; charset=utf-8")
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/capture":
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown endpoint."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            raw_slots = payload.get("slots", [])
            captured_dates = {str(date) for date in payload.get("captured_dates", []) if str(date)}
            slots = [
                slot
                for slot in (normalize_slot(raw, self.state.config) for raw in raw_slots)
                if slot is not None
            ]
            captured_dates.update(slot.date for slot in slots)
            if not captured_dates:
                raise ValueError("No captured date was provided.")

            merged = merge_captured_slots(slots, captured_dates)
            matches = [slot for slot in merged if slot_matches_preferences(slot, self.state.config)]
            write_capture_payload(merged, matches, self.state.config)

            texted = 0
            if self.state.send_sms:
                texted = notify_new_matches(matches, self.state.config, dry_run=self.state.dry_run)

            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "slots": len(slots),
                    "total_slots": len(merged),
                    "matches": len(matches),
                    "texted": texted,
                    "latest_slots": str(LATEST_SLOTS_PATH),
                },
            )
        except Exception as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})

    def serve_static(self, path: str) -> None:
        relative = path.lstrip("/")
        target = (REPO_ROOT / relative).resolve()
        try:
            target.relative_to(REPO_ROOT)
        except ValueError:
            self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden."})
            return
        if not target.is_file():
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})
            return
        self.serve_file(target)

    def serve_file(self, path: Path, content_type: str | None = None) -> None:
        if content_type is None:
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local browser capture helper for Tee Time Radar.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to config.json.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind.")
    parser.add_argument("--sms", action="store_true", help="Send SMS for newly captured matching slots.")
    parser.add_argument("--dry-run", action="store_true", help="Print SMS instead of sending when --sms is used.")
    return parser.parse_args()


def main() -> int:
    load_dotenv()
    args = parse_args()
    config = load_config(args.config)

    CaptureHandler.state = CaptureState(config=config, send_sms=args.sms, dry_run=args.dry_run)
    CaptureHandler.host_name = args.host
    CaptureHandler.port_number = args.port

    server = ThreadingHTTPServer((args.host, args.port), CaptureHandler)
    print(f"Tee Time Radar capture helper running at http://{args.host}:{args.port}/")
    print(f"Dashboard: http://{args.host}:{args.port}{DASHBOARD_PATH}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping capture helper.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
