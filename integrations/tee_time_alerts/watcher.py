from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from math import ceil
from pathlib import Path
from typing import Any

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - handled at runtime for first install.
    PlaywrightTimeoutError = Exception
    sync_playwright = None


APP_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = APP_DIR / "config.json"
EXAMPLE_CONFIG_PATH = APP_DIR / "config.example.json"
DEFAULT_PROFILE_DIR = APP_DIR / "browser_profile"
LATEST_SLOTS_PATH = APP_DIR / "latest_slots.json"
NOTIFIED_SLOTS_PATH = APP_DIR / "notified_slots.json"
ENV_PATH = APP_DIR / ".env"
DEBUG_DIR = APP_DIR / "debug"

TIME_RE = re.compile(r"\b(1[0-2]|0?[1-9]):([0-5]\d)\s*(AM|PM)\b", re.I)
PLAYER_RANGE_RE = re.compile(r"\b(\d+)\s*[-\u2013\u2014]\s*(\d+)\s*Players?\b", re.I)
PLAYER_SINGLE_RE = re.compile(r"\b(\d+)\s*Players?\b", re.I)
PRICE_RE = re.compile(r"\$\s*\d+(?:\.\d{2})?")
HOLES_RE = re.compile(r"\b(9|18)\b")
TRUE_VALUES = {"1", "true", "yes", "on"}
WEEKDAY_ALIASES = {
    "mon": "monday",
    "monday": "monday",
    "tue": "tuesday",
    "tues": "tuesday",
    "tuesday": "tuesday",
    "wed": "wednesday",
    "wednesday": "wednesday",
    "thu": "thursday",
    "thur": "thursday",
    "thurs": "thursday",
    "thursday": "thursday",
    "fri": "friday",
    "friday": "friday",
    "sat": "saturday",
    "saturday": "saturday",
    "sun": "sunday",
    "sunday": "sunday",
}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(levelname)s: %(message)s")
logger = logging.getLogger("tee_time_alerts")


@dataclass(frozen=True)
class TeeTime:
    date: str
    day: str
    time: str
    course: str
    open_spots: int
    holes: int | None
    price: str | None
    tee: str | None
    booking_url: str
    source_text: str

    @property
    def id(self) -> str:
        key = f"{self.course}|{self.date}|{self.time}|{self.holes}|{self.open_spots}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def load_dotenv(path: Path = ENV_PATH) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        name, value = clean.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(name, value)


def read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_config(path: Path) -> dict[str, Any]:
    if path.exists():
        return read_json(path, {})
    logger.warning("No config.json found. Using config.example.json defaults.")
    return read_json(EXAMPLE_CONFIG_PATH, {})


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def normalize_day(value: str) -> str:
    key = value.strip().lower()
    if key not in WEEKDAY_ALIASES:
        raise ValueError(f"Unsupported day name: {value}")
    return WEEKDAY_ALIASES[key]


def date_label(date_value: dt.date) -> str:
    return date_value.strftime("%m/%d/%Y")


def parse_time_minutes(value: str) -> int:
    match = TIME_RE.search(value.strip())
    if not match:
        raise ValueError(f"Unsupported time: {value}")
    hour = int(match.group(1))
    minute = int(match.group(2))
    suffix = match.group(3).upper()
    if suffix == "PM" and hour != 12:
        hour += 12
    if suffix == "AM" and hour == 12:
        hour = 0
    return hour * 60 + minute


def config_time_to_minutes(value: str) -> int:
    hour, minute = value.split(":", 1)
    return int(hour) * 60 + int(minute)


def now_minutes() -> int:
    now = dt.datetime.now()
    return now.hour * 60 + now.minute


def in_quiet_hours(config: dict[str, Any]) -> bool:
    limits = config.get("limits", {})
    start_value = limits.get("quiet_hours_start")
    end_value = limits.get("quiet_hours_end")
    if not start_value or not end_value:
        return False

    start = config_time_to_minutes(start_value)
    end = config_time_to_minutes(end_value)
    current = now_minutes()
    if start == end:
        return False
    if start < end:
        return start <= current < end
    return current >= start or current < end


def effective_poll_seconds(config: dict[str, Any]) -> int:
    configured = int(config.get("poll_seconds", 60))
    max_scans = int(config.get("limits", {}).get("max_scans_per_hour", 60))
    if max_scans <= 0:
        return configured
    polite_minimum = ceil(3600 / max_scans)
    return max(configured, polite_minimum)


def normalize_time(value: str) -> str:
    match = TIME_RE.search(value)
    if not match:
        return value.strip()
    hour = int(match.group(1))
    minute = int(match.group(2))
    suffix = match.group(3).upper()
    return f"{hour}:{minute:02d} {suffix}"


def human_date(date_value: str) -> str:
    parsed = dt.date.fromisoformat(date_value)
    return parsed.strftime("%a %b %-d") if os.name != "nt" else parsed.strftime("%a %b %#d")


def target_dates(config: dict[str, Any]) -> list[dt.date]:
    preferences = config.get("preferences", {})
    wanted_days = {normalize_day(day) for day in preferences.get("days", ["saturday", "sunday"])}
    booking_window_days = int(config.get("booking_window_days", 15))
    today = dt.date.today()

    dates: list[dt.date] = []
    for offset in range(booking_window_days + 1):
        candidate = today + dt.timedelta(days=offset)
        if candidate.strftime("%A").lower() in wanted_days:
            dates.append(candidate)
    return dates


def launch_context(playwright: Any, config: dict[str, Any], headless: bool) -> Any:
    browser_config = config.get("browser", {})
    profile_dir = Path(browser_config.get("profile_dir") or DEFAULT_PROFILE_DIR)
    if not profile_dir.is_absolute():
        profile_dir = APP_DIR / profile_dir
    profile_dir.mkdir(parents=True, exist_ok=True)

    launch_args: dict[str, Any] = {
        "headless": headless,
        "viewport": {"width": 1365, "height": 900},
    }
    channel = browser_config.get("channel", "").strip()
    if channel:
        launch_args["channel"] = channel

    return playwright.chromium.launch_persistent_context(str(profile_dir), **launch_args)


def require_playwright() -> None:
    if sync_playwright is None:
        raise SystemExit(
            "Playwright is not installed. Run: python -m pip install -r requirements.txt"
        )


def setup_login(config: dict[str, Any]) -> None:
    require_playwright()
    url = config["course_url"]
    print("\nOpening a persistent browser profile for EZLinks.")
    print("Log in as the authorized member, confirm the tee-time page loads, then return here.")
    print("No password is saved in config; the browser profile keeps the member session locally.\n")

    with sync_playwright() as playwright:
        context = launch_context(playwright, config, headless=False)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(url, wait_until="domcontentloaded")
        input("Press Enter after the member login/session is ready...")
        context.close()

    print("Login setup complete.")


def wait_for_page(page: Any) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=8000)
    except PlaywrightTimeoutError:
        page.wait_for_timeout(1200)


def page_has_security_verification(page: Any) -> bool:
    try:
        title = (page.title() or "").lower()
        body_text = page.locator("body").inner_text(timeout=1500).lower()
    except Exception:
        return False

    markers = [
        "just a moment",
        "performing security verification",
        "security service",
        "cf-turnstile-response",
        "cloudflare",
    ]
    return any(marker in title or marker in body_text for marker in markers)


def wait_for_security_clearance(page: Any, timeout_seconds: int = 90) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        wait_for_page(page)
        if not page_has_security_verification(page):
            return True
        page.wait_for_timeout(2500)
    return False


def handle_security_verification(page: Any, headless: bool) -> None:
    if not page_has_security_verification(page):
        return

    save_debug_snapshot(page, "security-verification")
    if headless:
        raise RuntimeError(
            "The site presented a security verification page. Run with --headed "
            "and complete the verification manually."
        )

    print(
        "\nEZLinks is showing a security verification page in the browser.\n"
        "Complete it manually if the page allows it, then return here.\n"
        "Wait until the real tee-time search page is visible before pressing Enter.\n"
        "If it keeps spinning, press Enter anyway and the scan will stop cleanly.\n"
    )
    input("Press Enter after the browser reaches the real tee-time search page...")
    if not wait_for_security_clearance(page):
        save_debug_snapshot(page, "security-verification-still-active")
        raise RuntimeError(
            "Security verification is still active, so the watcher cannot read tee times."
        )


def debug_enabled() -> bool:
    return env_bool("TEE_TIME_DEBUG", True)


def debug_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def save_debug_snapshot(page: Any, label: str) -> None:
    if not debug_enabled():
        return
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")
    base = DEBUG_DIR / f"{debug_stamp()}-{safe_label}"
    try:
        (base.with_suffix(".html")).write_text(page.content(), encoding="utf-8")
    except Exception as exc:
        logger.debug("Could not write debug HTML: %s", exc)
    try:
        page.screenshot(path=str(base.with_suffix(".png")), full_page=True)
    except Exception as exc:
        logger.debug("Could not write debug screenshot: %s", exc)
    try:
        controls = page.evaluate(
            """
            () => Array.from(document.querySelectorAll("input, select, button, [role='button'], [role='combobox']"))
              .slice(0, 120)
              .map((el, index) => {
                const rect = el.getBoundingClientRect();
                return {
                  index,
                  tag: el.tagName,
                  type: el.getAttribute("type"),
                  role: el.getAttribute("role"),
                  id: el.id,
                  name: el.getAttribute("name"),
                  className: String(el.className || ""),
                  text: (el.innerText || el.value || el.getAttribute("aria-label") || "").replace(/\\s+/g, " ").trim().slice(0, 180),
                  value: el.value || "",
                  disabled: Boolean(el.disabled || el.getAttribute("aria-disabled") === "true"),
                  visible: rect.width > 0 && rect.height > 0,
                  rect: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }
                };
              })
            """
        )
        write_json(base.with_name(f"{base.name}-controls.json"), controls)
    except Exception as exc:
        logger.debug("Could not write debug controls JSON: %s", exc)


def safe_count(locator: Any) -> int:
    try:
        return locator.count()
    except Exception:
        return 0


def force_set_input_value(page: Any, index: int, value: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """
                ({ index, value }) => {
                  const input = document.querySelectorAll("input")[index];
                  if (!input) return false;
                  input.removeAttribute("disabled");
                  input.removeAttribute("readonly");
                  const proto = Object.getPrototypeOf(input);
                  const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
                  if (descriptor && descriptor.set) {
                    descriptor.set.call(input, value);
                  } else {
                    input.value = value;
                  }
                  for (const eventName of ["input", "change", "blur"]) {
                    input.dispatchEvent(new Event(eventName, { bubbles: true }));
                  }
                  return true;
                }
                """,
                {"index": index, "value": value},
            )
        )
    except Exception:
        return False


def fill_date_input(page: Any, date_value: dt.date) -> bool:
    mmddyyyy = date_label(date_value)
    iso_date = date_value.isoformat()
    inputs = page.locator("input")
    for index in range(min(safe_count(inputs), 30)):
        field = inputs.nth(index)
        try:
            if not field.is_visible(timeout=500):
                continue
            input_type = (field.get_attribute("type") or "").lower()
            value = field.input_value(timeout=500)
            placeholder = field.get_attribute("placeholder") or ""
            aria_label = field.get_attribute("aria-label") or ""
            name = field.get_attribute("name") or ""
            field_id = field.get_attribute("id") or ""
            class_name = field.get_attribute("class") or ""
            combined = " ".join([placeholder, aria_label, name, field_id, class_name]).lower()
            looks_like_date = (
                input_type in {"date", "text", ""}
                and (
                    "/" in value
                    or "/" in placeholder
                    or "date" in combined
                    or "datepicker" in combined
                    or input_type == "date"
                )
            )
            if not looks_like_date:
                continue
            desired_value = iso_date if input_type == "date" else mmddyyyy
            try:
                field.click(force=True)
                field.fill(desired_value, force=True)
                field.press("Enter")
            except Exception:
                if not force_set_input_value(page, index, desired_value):
                    continue
            wait_for_page(page)
            return True
        except Exception:
            continue
    return False


def force_select_player_value(page: Any, index: int, players: int) -> bool:
    try:
        return bool(
            page.evaluate(
                """
                ({ index, players }) => {
                  const select = document.querySelectorAll("select")[index];
                  if (!select) return false;
                  select.removeAttribute("disabled");
                  const wanted = String(players);
                  const option = Array.from(select.options).find((opt) => {
                    const text = (opt.textContent || "").trim().toLowerCase();
                    return opt.value === wanted || text === wanted || text.includes(`${wanted} player`);
                  });
                  if (!option) return false;
                  select.value = option.value;
                  for (const eventName of ["input", "change", "blur"]) {
                    select.dispatchEvent(new Event(eventName, { bubbles: true }));
                  }
                  return true;
                }
                """,
                {"index": index, "players": players},
            )
        )
    except Exception:
        return False


def select_players(page: Any, players: int) -> bool:
    selects = page.locator("select")
    for index in range(min(safe_count(selects), 20)):
        select = selects.nth(index)
        try:
            if not select.is_visible(timeout=500):
                continue
            labels = [str(players), f"{players} player", f"{players} players"]
            for label in labels:
                try:
                    select.select_option(label=label)
                    wait_for_page(page)
                    return True
                except Exception:
                    pass
            try:
                select.select_option(value=str(players))
                wait_for_page(page)
                return True
            except Exception:
                pass
            if force_select_player_value(page, index, players):
                wait_for_page(page)
                return True
        except Exception:
            continue
    return False


def click_apply_if_present(page: Any) -> None:
    labels = ["Search", "Apply", "Update", "Go", "Find Tee Times"]
    for label in labels:
        try:
            button = page.get_by_role("button", name=re.compile(label, re.I))
            if safe_count(button) and button.first.is_visible(timeout=500):
                button.first.click()
                wait_for_page(page)
                return
        except Exception:
            continue


def set_search_filters(page: Any, date_value: dt.date, players: int) -> bool:
    save_debug_snapshot(page, f"before-filters-{date_value.isoformat()}")
    filled_date = fill_date_input(page, date_value)
    selected_players = select_players(page, players)
    click_apply_if_present(page)
    page.wait_for_timeout(1200)

    if not filled_date:
        logger.warning("Could not find a visible date input for %s.", date_label(date_value))
    if not selected_players:
        logger.warning("Could not find a visible players dropdown for %s players.", players)
    if not filled_date or not selected_players:
        save_debug_snapshot(page, f"filter-miss-{date_value.isoformat()}")
    return filled_date


def extract_card_candidates(page: Any) -> list[dict[str, Any]]:
    script = """
    () => {
      const timePattern = /\\b(?:1[0-2]|0?[1-9]):[0-5]\\d\\s*(?:AM|PM)\\b/i;
      const playerPattern = /\\b\\d+\\s*[-\\u2013\\u2014]\\s*\\d+\\s*Players?\\b|\\b\\d+\\s*Players?\\b/i;
      const elements = Array.from(document.querySelectorAll("article, li, section, div"));
      const candidates = [];

      for (const el of elements) {
        const text = (el.innerText || "").replace(/\\s+/g, " ").trim();
        if (!timePattern.test(text) || !playerPattern.test(text)) continue;

        const rect = el.getBoundingClientRect();
        const area = rect.width * rect.height;
        if (rect.width < 80 || rect.height < 60 || rect.width > 620 || rect.height > 520) continue;
        if (text.length > 500) continue;

        candidates.push({ el, text, area, x: rect.x, y: rect.y, width: rect.width, height: rect.height });
      }

      candidates.sort((a, b) => a.area - b.area);
      const selected = [];
      for (const item of candidates) {
        const overlaps = selected.some((other) => item.el.contains(other.el) || other.el.contains(item.el));
        if (!overlaps) selected.push(item);
      }

      return selected.map((item) => {
        const link = item.el.querySelector("a[href]");
        return {
          text: item.text,
          href: link ? link.href : "",
          x: Math.round(item.x),
          y: Math.round(item.y),
          width: Math.round(item.width),
          height: Math.round(item.height)
        };
      });
    }
    """
    return page.evaluate(script)


def parse_open_spots(text: str) -> int | None:
    range_match = PLAYER_RANGE_RE.search(text)
    if range_match:
        return int(range_match.group(2))
    single_match = PLAYER_SINGLE_RE.search(text)
    if single_match:
        return int(single_match.group(1))
    return None


def parse_holes(text: str) -> int | None:
    for match in HOLES_RE.finditer(text):
        value = int(match.group(1))
        before = text[max(0, match.start() - 2):match.start()]
        after = text[match.end():match.end() + 2]
        if "." in before or "." in after:
            continue
        return value
    return None


def tee_from_text(text: str) -> str | None:
    lowered = text.lower()
    if "front" in lowered:
        return "Front nine"
    if "back" in lowered:
        return "Back nine"
    return None


def parse_slot(
    card: dict[str, Any],
    date_value: dt.date,
    config: dict[str, Any],
) -> TeeTime | None:
    text = card.get("text", "")
    time_match = TIME_RE.search(text)
    if not time_match:
        return None
    open_spots = parse_open_spots(text)
    if open_spots is None:
        return None

    price_match = PRICE_RE.search(text)
    course_name = config.get("course_name", "Golf course")
    booking_url = card.get("href") or config.get("course_url", "")
    return TeeTime(
        date=date_value.isoformat(),
        day=date_value.strftime("%A"),
        time=normalize_time(time_match.group(0)),
        course=course_name,
        open_spots=open_spots,
        holes=parse_holes(text),
        price=price_match.group(0) if price_match else None,
        tee=tee_from_text(text),
        booking_url=booking_url,
        source_text=text,
    )


def slot_matches_preferences(slot: TeeTime, config: dict[str, Any]) -> bool:
    preferences = config.get("preferences", {})
    players = int(preferences.get("players", 4))
    holes = preferences.get("holes")
    start = config_time_to_minutes(preferences.get("time_start", "06:00"))
    end = config_time_to_minutes(preferences.get("time_end", "09:00"))
    slot_time = parse_time_minutes(slot.time)

    if slot.open_spots < players:
        return False
    if holes and slot.holes is not None and int(holes) != slot.holes:
        return False
    return start <= slot_time < end


def scan_with_browser(config: dict[str, Any], headless: bool) -> tuple[list[TeeTime], list[TeeTime]]:
    require_playwright()
    preferences = config.get("preferences", {})
    players = int(preferences.get("players", 4))
    course_url = config["course_url"]
    all_slots: list[TeeTime] = []

    with sync_playwright() as playwright:
        context = launch_context(playwright, config, headless=headless)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(course_url, wait_until="domcontentloaded")
        wait_for_page(page)
        handle_security_verification(page, headless=headless)

        for date_value in target_dates(config):
            logger.info("Scanning %s for %s players...", date_label(date_value), players)
            if not set_search_filters(page, date_value, players):
                logger.warning("Skipping %s because the watcher could not set the date.", date_label(date_value))
                continue
            cards = extract_card_candidates(page)
            logger.info("Found %s candidate cards on %s.", len(cards), date_label(date_value))
            for card in cards:
                slot = parse_slot(card, date_value, config)
                if slot:
                    all_slots.append(slot)

        context.close()

    unique: dict[str, TeeTime] = {}
    for slot in all_slots:
        unique.setdefault(slot.id, slot)

    slots = list(unique.values())
    matches = [slot for slot in slots if slot_matches_preferences(slot, config)]
    matches.sort(key=lambda slot: (slot.date, parse_time_minutes(slot.time)))
    return slots, matches


def format_slot(slot: TeeTime) -> str:
    holes = f", {slot.holes} holes" if slot.holes else ""
    price = f", {slot.price}" if slot.price else ""
    return f"{human_date(slot.date)} {slot.time} ({slot.open_spots} open{holes}{price})"


def format_sms(matches: list[TeeTime], config: dict[str, Any]) -> str:
    course = config.get("course_name", "Tee Time Radar")
    url = config.get("course_url", "")
    if len(matches) == 1:
        return f"{course} tee time match: {format_slot(matches[0])}. Book/check: {url}"

    lines = [f"{course}: {len(matches)} tee time matches"]
    for index, slot in enumerate(matches[:5], start=1):
        lines.append(f"{index}. {format_slot(slot)}")
    lines.append(f"Book/check: {url}")
    return "\n".join(lines)


def config_sms_numbers(config: dict[str, Any]) -> tuple[str, list[str]]:
    sms_config = config.get("notifications", {}).get("sms", {})
    from_number = os.getenv("TWILIO_FROM_NUMBER") or sms_config.get("from_number", "")
    env_numbers = os.getenv("SMS_TO_NUMBERS", "")
    to_numbers = [number.strip() for number in env_numbers.replace(";", ",").split(",") if number.strip()]
    if not to_numbers:
        to_numbers = [str(number).strip() for number in sms_config.get("to_numbers", []) if str(number).strip()]
    return from_number, to_numbers


def send_sms(message: str, config: dict[str, Any], dry_run: bool) -> bool:
    sms_config = config.get("notifications", {}).get("sms", {})
    if not sms_config.get("enabled", True) and not dry_run:
        logger.info("SMS is disabled in config.")
        return False

    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    from_number, to_numbers = config_sms_numbers(config)

    if dry_run:
        print("\n--- SMS DRY RUN ---")
        print(message)
        print("--- END SMS DRY RUN ---\n")
        return True

    if not account_sid or not auth_token or not from_number or not to_numbers:
        logger.warning(
            "SMS not sent. Configure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "
            "TWILIO_FROM_NUMBER, and SMS_TO_NUMBERS."
        )
        return False

    auth = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    sent_any = False

    for to_number in to_numbers:
        payload = urllib.parse.urlencode(
            {
                "To": to_number,
                "From": from_number,
                "Body": message,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response.read()
            logger.info("SMS sent to %s.", to_number)
            sent_any = True
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            logger.error("Twilio rejected SMS to %s: HTTP %s %s", to_number, exc.code, body)
        except urllib.error.URLError as exc:
            logger.error("Could not reach Twilio for %s: %s", to_number, exc)

    return sent_any


def notify_new_matches(matches: list[TeeTime], config: dict[str, Any], dry_run: bool) -> int:
    notified = set(read_json(NOTIFIED_SLOTS_PATH, []))
    new_matches = [slot for slot in matches if slot.id not in notified]
    if not new_matches:
        logger.info("No new matching slots to text.")
        return 0

    message = format_sms(new_matches, config)
    if send_sms(message, config, dry_run=dry_run):
        if dry_run:
            logger.info("Dry run only. Not marking matches as texted.")
        else:
            notified.update(slot.id for slot in new_matches)
            write_json(NOTIFIED_SLOTS_PATH, sorted(notified))
    return len(new_matches)


def write_latest(slots: list[TeeTime], matches: list[TeeTime], config: dict[str, Any]) -> None:
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "ezlinks_playwright",
        "course_name": config.get("course_name"),
        "course_url": config.get("course_url"),
        "preferences": config.get("preferences", {}),
        "slots": [asdict(slot) | {"id": slot.id} for slot in slots],
        "matches": [asdict(slot) | {"id": slot.id} for slot in matches],
    }
    write_json(LATEST_SLOTS_PATH, payload)
    logger.info("Wrote %s slots and %s matches to %s.", len(slots), len(matches), LATEST_SLOTS_PATH)


def scan_once(config: dict[str, Any], headless: bool, dry_run: bool, no_sms: bool) -> None:
    slots, matches = scan_with_browser(config, headless=headless)
    write_latest(slots, matches, config)
    if matches:
        for slot in matches:
            logger.info("MATCH: %s", format_slot(slot))
    else:
        logger.info("No matching slots found.")

    if not no_sms:
        notify_new_matches(matches, config, dry_run=dry_run)


def watch(config: dict[str, Any], headless: bool, dry_run: bool, no_sms: bool) -> None:
    poll_seconds = effective_poll_seconds(config)
    logger.info("Starting watcher. Poll interval: %s seconds.", poll_seconds)
    while True:
        if in_quiet_hours(config):
            logger.info("Quiet hours are active. Sleeping %s seconds.", poll_seconds)
            time.sleep(poll_seconds)
            continue

        started = time.monotonic()
        try:
            scan_once(config, headless=headless, dry_run=dry_run, no_sms=no_sms)
        except KeyboardInterrupt:
            raise
        except Exception:
            logger.exception("Scan failed.")

        elapsed = time.monotonic() - started
        sleep_for = max(5, poll_seconds - elapsed)
        logger.info("Sleeping %.0f seconds.", sleep_for)
        time.sleep(sleep_for)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Alert-only EZLinks tee-time watcher.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to config.json.")
    parser.add_argument("--setup-login", action="store_true", help="Open browser so a member can log in once.")
    parser.add_argument("--once", action="store_true", help="Run one scan and exit.")
    parser.add_argument("--watch", action="store_true", help="Run scans until stopped.")
    parser.add_argument("--headed", action="store_true", help="Show the browser during scans.")
    parser.add_argument("--dry-run", action="store_true", help="Print SMS content instead of sending it.")
    parser.add_argument("--no-sms", action="store_true", help="Scan and write JSON without sending SMS.")
    return parser.parse_args()


def main() -> int:
    load_dotenv()
    args = parse_args()
    config = load_config(args.config)

    if args.setup_login:
        setup_login(config)
        return 0

    if not args.once and not args.watch:
        raise SystemExit("Choose --setup-login, --once, or --watch.")

    headless = not args.headed and not env_bool("TEE_TIME_HEADED", False)
    try:
        if args.once:
            scan_once(config, headless=headless, dry_run=args.dry_run, no_sms=args.no_sms)
            return 0

        watch(config, headless=headless, dry_run=args.dry_run, no_sms=args.no_sms)
        return 0
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
