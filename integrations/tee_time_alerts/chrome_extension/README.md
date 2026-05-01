# Tee Time Radar Chrome Extension

Member-side Chrome extension for visible EZLinks tee sheets.

## What It Does

- Runs only on `wildwoodgreenmem.ezlinksgolf.com`.
- Reads tee-time cards visible in a normal logged-in Chrome tab.
- Posts captures to the local helper at `http://127.0.0.1:8765/capture`.
- The helper writes `latest_slots.json` and can send SMS for matching slots.

It does not bypass Cloudflare, CAPTCHA, login, or access controls. Chrome must be open, the member must be logged in, and EZLinks must be able to render the tee sheet in that browser session.

## Install

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Turn on `Developer mode`.
4. Click `Load unpacked`.
5. Select this folder:

```text
C:\Users\adams\OneDrive\Desktop\SysEng\sysengscripts\integrations\tee_time_alerts\chrome_extension
```

## Run

Start the local helper:

```powershell
cd C:\Users\adams\OneDrive\Desktop\SysEng\sysengscripts\integrations\tee_time_alerts
.\.venv\Scripts\python capture_server.py
```

Open EZLinks normally in Chrome and sign in. Go to the tee-time search page.

Click the extension icon:

- `Monitor`: enables scheduled capture.
- `Passive capture`: captures when the tee sheet visibly changes.
- `Auto-open tab`: lets the extension open a pinned EZLinks search tab if none exists.
- `Poll`: how often the extension asks an existing EZLinks tab to capture.
- `Capture Now`: forces a capture from the visible/logged-in EZLinks tab.

Open dashboard:

```text
http://127.0.0.1:8765/integrations/tee_time_alerts/tee_time_dashboard.html
```

## SMS Mode

After capture looks correct, start the helper with SMS enabled:

```powershell
.\.venv\Scripts\python capture_server.py --sms
```

Twilio settings live in `.env`.

## Always-On Notes

This can be “always running” on a desktop or small Windows box if:

- Chrome is running.
- The extension is installed.
- The local helper is running.
- The member session remains logged in.
- EZLinks renders the tee sheet normally.

If Chrome is closed, the extension cannot inspect the page. If EZLinks shows security verification, a member must handle it manually.
