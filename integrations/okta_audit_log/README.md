# Okta Audit Log → Confluence

Polls the Okta System Log every ~15 minutes and appends rows to a Confluence
audit page so the sys engineering team has a running log of:

- New groups created in Okta (`group.lifecycle.create`)
- New apps integrated in Okta (`application.lifecycle.create`)
- New group → app assignments (`group.application_assignment.add`)

A parent **index page** lists every month with running counts and links to the
per-month audit page. State (the last event timestamp we processed) lives in a
hidden HTML comment on the index page, so no external storage is required.

## How it works

```
GitHub Actions cron (every 15 min)
        │
        ▼
  audit.py
        │
        ├──► Okta System Log API   (since=last_seen, filtered to 3 event types)
        │
        └──► Confluence REST API
                 ├──► ensure monthly page exists (creates if first event of the month)
                 ├──► append new rows to that month's table
                 └──► update index page (counts + last_seen comment)
```

If no events fired in the window, the script still bumps the `last_seen`
timestamp so we don't re-scan the same window forever.

## One-time setup

### 1. Create the Confluence index page

In the Confluence space you want this to live in (e.g. `SYSENG`), create an
empty page titled something like **Okta Audit Log**. Grab the page ID from the
URL — it's the number in `/pages/<id>/`. Save it for step 4.

The script will install the index table on this page the first time it runs.

### 2. Generate API tokens

- **Okta**: Admin Console → Security → API → Tokens → *Create Token*. The
  service account that creates the token must have read access to the System
  Log (Read-Only Admin works).
- **Confluence**: <https://id.atlassian.com/manage-profile/security/api-tokens>
  → *Create API token*. Confluence uses HTTP Basic with `<email>:<token>`.

### 3. Add GitHub secrets

In the repository settings → *Secrets and variables* → *Actions*, add:

| Secret name | Example |
| --- | --- |
| `OKTA_DOMAIN` | `hillspire.okta.com` |
| `OKTA_API_TOKEN` | `00abcdef...` |
| `OKTA_ADMIN_URL` | `https://hillspire-admin.okta.com` (optional — derived if absent) |
| `CONFLUENCE_BASE_URL` | `https://hillspire.atlassian.net/wiki` |
| `CONFLUENCE_EMAIL` | `aschembri@hillspire.com` |
| `CONFLUENCE_API_TOKEN` | `ATATT3x...` |
| `CONFLUENCE_SPACE_KEY` | `SYSENG` |
| `CONFLUENCE_INDEX_PAGE_ID` | `123456789` |

### 4. Kick it off

Once the secrets are set, trigger the workflow manually the first time:
*Actions* → **Okta Audit Log** → *Run workflow*. That'll bootstrap the index
page template and start tracking from 15 minutes ago. After that the schedule
takes over.

## Local run

```bash
cp integrations/okta_audit_log/.env.example integrations/okta_audit_log/.env
# Fill in the values, then:
.venv/bin/python -m pip install -r integrations/okta_audit_log/requirements.txt
.venv/bin/python integrations/okta_audit_log/audit.py
```

`python-dotenv` auto-loads `.env` when running locally; in CI the values come
from GitHub secrets.

## What the pages look like

**Index page** (auto-installed on first run):

| Month | Page | Groups Created | Apps Added | Assignments |
| --- | --- | --- | --- | --- |
| 2026-05 | [2026-05 Okta Audit Log](.) | 4 | 2 | 7 |
| 2026-04 | [2026-04 Okta Audit Log](.) | 1 | 0 | 3 |

**Monthly page** (one per calendar month, most recent at top):

| When (UTC) | Actor | Type | Detail |
| --- | --- | --- | --- |
| 2026-05-18T10:42:00Z | Steven Sutton | Group Created | [Engineering](.) |
| 2026-05-18T10:35:00Z | Johnny Espinoza | App Added | [Snowflake](.) |
| 2026-05-18T09:15:00Z | Adam Schembri | Group → App Assignment | [Engineering](.) → [Snowflake](.) |

## Extending

- **More event types**: add to `EVENT_TYPES` and add a branch in
  `event_to_row()` to format the new category.
- **Faster polling**: change the cron in
  `.github/workflows/okta_audit_log.yml`. Sub-15-min schedules use more Actions
  minutes and GitHub may still delay them during high load.
- **Webhooks instead of polling**: Okta supports Event Hooks if you want
  real-time. That requires a public HTTPS endpoint to receive them — meaningfully
  more infra than the polling approach.

## Troubleshooting

- **`401` from Confluence**: token is scoped to the wrong Atlassian account, or
  the email/token pair don't match. Regenerate.
- **`403` from Okta**: the API token's owner doesn't have System Log read
  access. Use a Read-Only Admin (or higher) account.
- **Index page table is missing**: delete the empty page contents (leave the
  page itself) and re-run the workflow — `ensure_index_initialized` installs the
  template only when there's no `<table>` in the page body.
- **Duplicate rows after manual edits**: the script only appends, never
  rewrites existing rows. If you edit the table by hand, you may want to clear
  the `okta_audit_last_seen` comment on the index page to force a re-scan from
  a chosen point.
