# Tee Time Alerts

Alert-only assistant for member tee-time availability.

## Current Target

- Course: Wildwood Green Golf Club
- Booking site: `https://wildwoodgreenmem.ezlinksgolf.com/index.html#/login`
- Preference: Saturday and Sunday before 9:00 AM
- Group size: 4 players
- Mode: alert-only, human confirms booking
- Notification: SMS through Twilio

## Setup

From this folder:

```powershell
# Python 3.10+ recommended.
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m playwright install chromium
Copy-Item config.example.json config.json
Copy-Item .env.example .env
```

Edit `config.json` for the tee-time preferences. Edit `.env` for Twilio:

```text
TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=+15551234567
SMS_TO_NUMBERS=+15557654321,+15559876543
```

## First Login

This opens a real browser profile. A member logs in once; the local browser profile keeps the session.

```powershell
.\.venv\Scripts\python watcher.py --setup-login
```

## Test One Scan

Dry run prints the SMS body without texting anyone:

```powershell
.\.venv\Scripts\python watcher.py --once --headed --dry-run
```

When the parser looks right, remove `--dry-run` to text real matches:

```powershell
.\.venv\Scripts\python watcher.py --once --headed
```

## Run The Watcher

```powershell
.\.venv\Scripts\python watcher.py --watch
```

The watcher writes `latest_slots.json` after each scan and tracks already-texted slots in `notified_slots.json`.

## View The Dashboard With Live JSON

Browsers usually block `fetch()` from a plain `file://` HTML page, so serve the repo over local HTTP.

Terminal 1, from the repo root:

```powershell
.\integrations\tee_time_alerts\.venv\Scripts\python -m http.server 8000
```

Or from `integrations\tee_time_alerts`:

```powershell
.\serve_dashboard.ps1
```

Open:

```text
http://localhost:8000/integrations/tee_time_alerts/tee_time_dashboard.html
```

Terminal 2, from `integrations\tee_time_alerts`, run a real scan:

```powershell
.\.venv\Scripts\python watcher.py --once --headed --no-sms
```

After `latest_slots.json` exists, the dashboard will switch from `Demo data` to `Live scan data`. Use the dashboard `Scan` button to refresh the JSON view.

If a scan logs warnings like `Could not find a visible date input`, the watcher writes debug files to `debug/`. The most useful file is the latest `*-controls.json`, which lists the form controls Playwright could see.

If the debug HTML says `Just a moment...` or `Performing security verification`, EZLinks/Cloudflare is blocking automated access before the tee-time page renders. The watcher will not bypass that. Run with `--headed`, complete any verification manually if the browser allows it, and continue only after the real tee-time search page is visible.

## Browser Capture Fallback

Use this when Playwright reaches Cloudflare but your normal browser can reach the real EZLinks tee sheet.

Start the local capture helper:

```powershell
cd C:\Users\adams\OneDrive\Desktop\SysEng\sysengscripts\integrations\tee_time_alerts
.\.venv\Scripts\python capture_server.py
```

Open:

```text
http://127.0.0.1:8765/
```

On that helper page:

- Drag `Capture Tee Times` to your bookmarks bar.
- Also drag `Copy Tee Times JSON` to your bookmarks bar as a backup.
- Open EZLinks normally and sign in.
- Go to a tee-sheet date with visible tee-time cards.
- Click the `Capture Tee Times` bookmark.
- Repeat for each Saturday/Sunday date you want on the dashboard.

If the direct bookmark does not update the dashboard, click `Copy Tee Times JSON` while on the EZLinks tee sheet. It copies the visible slots, then you can paste them into the import box on the helper page and click `Import Captured JSON`.

The helper writes `latest_slots.json`, and the dashboard is available at:

```text
http://127.0.0.1:8765/integrations/tee_time_alerts/tee_time_dashboard.html
```

To text newly captured matching slots, start the helper with:

```powershell
.\.venv\Scripts\python capture_server.py --sms
```

## Chrome Extension Monitor

For the more automated version, install the Chrome extension in `chrome_extension/`.

It watches normal logged-in EZLinks tabs and posts visible tee-time cards to the same local helper. It can poll an existing tab, passively capture when the tee sheet changes, and optionally open a pinned EZLinks search tab. Chrome and `capture_server.py` must stay running.

See:

```text
integrations\tee_time_alerts\chrome_extension\README.md
```

## How It Works

- Uses Playwright with a persistent local browser profile.
- Opens the EZLinks page with the member-approved session.
- Sets the date and player filters when the page exposes visible inputs.
- Reads visible tee-time cards from the page.
- Filters locally for Saturday/Sunday, before 9:00 AM, 4 open spots, and 18 holes.
- Sends one SMS for newly seen matching slots.
- Browser capture fallback reads only the tee times visible in the member's normal browser tab.

## Guardrails

- Do not bypass CAPTCHA, rate limits, account protections, or site access controls.
- Do not auto-book unless the member and the club/platform rules allow it.
- Keep passwords out of config files. Use the saved browser profile or local secret store.
- Poll respectfully and stop if the club/platform asks you not to automate checks.
