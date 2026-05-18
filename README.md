# System Engineering Scripts

Automation, integration, and admin tooling for system engineering work across
Google Workspace, Okta Workflows, Slack, endpoint management, and internal web
utilities.

This repo started as a home for endpoint scripts, but it is growing into a
working toolbox for IT operations: backend services, Google Apps Script
workflows, Cloud Run integrations, Python automation, and small browser/web
tools that make repeatable admin work faster and safer.

## Focus Areas

- Google Workspace administration and reporting
- Slack-integrated admin tools
- Okta Workflows helpers and offboarding actions
- Google Apps Script and internal web widgets
- Python automation services and watchers
- Windows endpoint management scripts
- Security and migration support scripts

## Repository Map

```text
integrations/
  google_workspace_admin_assistant/  FastAPI Cloud Run Slack bot for Workspace admin Q&A
  okta_audit_log/                    Polls Okta and writes a running audit log to Confluence
  okta_profile_sync/                 Backfills Okta profile attributes from Google Workspace
  tee_time_alerts/                   Python/browser helper for availability alerts
  offboard_tasks.js                  Slack modal to route offboarding tasks to Okta Workflows

sophos/
  Remove-SophosALL-MEEC.ps1          Sophos Endpoint removal script
  Test-Migration.ps1                 Sophos migration validation checks
  install_sophos_NP.ps1              Sophos install helper

web_dev/
  index.html                         Internal landing/portal work
  handbook.html                      Handbook-style web content
  calendar.html                      Calendar widget/page
  newsletter_widget.html             Newsletter widget
  birthday_widget.html               Birthday widget
  rise_appscript.js                  Google Apps Script / Rise integration work

windows/
  TaskBar_Pin.ps1                    Windows taskbar management helper
  scripts                            Additional Windows script workspace
```

## Active Projects

### Google Workspace Admin Assistant

Location: `integrations/google_workspace_admin_assistant`

FastAPI backend deployed to Google Cloud Run and connected to Slack. The bot is
designed to answer Workspace admin questions for leadership by combining Slack
events, OpenAI, and read-only Google Workspace Admin APIs.

Current capabilities include:

- Slack event verification and threaded replies
- Google Workspace delegated service account access
- Read-only Workspace lookups and intent routing
- OpenAI-powered response path
- Cloud Run deployment support through `Dockerfile`
- Local intent tests in `test_intents.py`

Important runtime configuration is expected through environment variables and
GCP Secret Manager, not committed files.

### Okta Workflows Offboarding Tasks

Location: `integrations/offboard_tasks.js`

Google Apps Script endpoint for a Slack slash command/modal that routes common
offboarding and mailbox actions into Okta Workflows.

Examples of supported action patterns:

- Set or remove out-of-office state
- Add or remove mailbox delegation
- Add or remove send-as aliases
- Forward mail
- List delegation or group information
- Trigger bundled offboarding actions through Okta Workflows

### Okta Audit Log

Location: `integrations/okta_audit_log`

Python script run on a 15-minute GitHub Actions cron that polls the Okta
System Log for new groups, new app integrations, and new group→app
assignments, then appends rows to a monthly Confluence page. An index page
tracks running counts and links to each month.

State is stored as a hidden HTML comment on the index page, so the
integration needs no external storage beyond GitHub secrets and the
Confluence page itself.

See `integrations/okta_audit_log/README.md` for setup steps.

### Tee Time Alerts

Location: `integrations/tee_time_alerts`

Python and browser-assisted alerting helper for tee-time availability. This
project includes a Playwright watcher, a browser capture fallback, a Chrome
extension monitor, a local dashboard, and Twilio SMS notification support.

See `integrations/tee_time_alerts/README.md` for setup and guardrails.

### Endpoint And Migration Scripts

Locations: `sophos/`, `windows/`

PowerShell scripts used for endpoint operations, migrations, validation, and
Windows desktop management.

## Local Development

Most Python work in this repo expects a local virtual environment at the repo
root:

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r integrations/google_workspace_admin_assistant/requirements.txt
```

For project-specific Python dependencies, install the requirements file from
that project directory. For example:

```bash
.venv/bin/python -m pip install -r integrations/tee_time_alerts/requirements.txt
```

VS Code is configured to use the repo-level `.venv` through
`.vscode/settings.json`.

## Secrets And Configuration

Do not commit credentials, API keys, tokens, service account JSON, or local
runtime state.

Use environment variables, Google Apps Script properties, GCP Secret Manager, or
local `.env` files that are ignored by Git.

Common secret/config names used by current integrations include:

```text
SLACK_BOT_TOKEN
SLACK_SIGNING_SECRET
GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON
GOOGLE_WORKSPACE_ADMIN_EMAIL
OPENAI_API_KEY
OPENAI_MODEL
OW_BEARER_TOKEN
OW_ROUTER_URL
TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN
```

## Git Workflow

Because this repo is worked on from multiple machines, prefer feature branches
and keep the remote branch as the handoff point.

```bash
git fetch --all --prune
git switch main
git pull --ff-only
```

For feature work:

```bash
git switch -c feature-name
git push -u origin feature-name
```

When moving between machines:

```bash
git fetch --all --prune
git switch feature-name
git pull --ff-only
```

Commit and push before leaving one machine, then pull before starting on the
other.

## Roadmap

- Expand Google Workspace assistant tools with more read-only admin lookups
- Add stronger Slack authorization controls for admin-only bot access
- Continue building Okta Workflow-backed Slack actions
- Organize Google Apps Script utilities into clearer integration folders
- Add lightweight tests for critical Python and Apps Script routing logic
- Keep endpoint scripts documented with intended use, risk level, and rollback notes

## Notes

This repo intentionally mixes production-bound automation with active prototypes.
Each project directory should document its own setup, required permissions, and
guardrails as it matures.
