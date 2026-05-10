#!/usr/bin/env node
/**
 * backfill-okta-profiles.js
 *
 * One-time backfill of Okta profile attributes for legacy users
 * who predate the TriNet -> Okta integration.
 *
 * Targets: Active Okta users where profile.employeeNumber is empty.
 * Source:  CSV export of the "Active Employees" tab from the HR Google Sheet
 *          ("Schmidt Entities Employee List for Hillspire IT Use").
 *
 * Usage:
 *   npm install
 *   cp .env.example .env   # then fill in OKTA_DOMAIN and OKTA_API_TOKEN
 *   npm run dry-run        # dry run — pulls delta from Okta, joins to CSV, prints payloads
 *   npm run run-live       # writes the partial profile updates to Okta
 */

'use strict';

require('dotenv').config();
const fs    = require('fs');
const https = require('https');

// ─────────────────────────────────────────────────────────────
//  RUNTIME FLAGS
// ─────────────────────────────────────────────────────────────
const DRY_RUN  = process.argv.includes('--dry-run');
const CSV_PATH = (() => {
  const idx = process.argv.indexOf('--csv');
  return idx !== -1 ? process.argv[idx + 1] : null;
})();

const OKTA_DOMAIN    = process.env.OKTA_DOMAIN;    // e.g. hillspire.okta.com
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN;

if (!OKTA_DOMAIN || !OKTA_API_TOKEN) {
  console.error('ERROR: OKTA_DOMAIN and OKTA_API_TOKEN must be set in .env');
  process.exit(1);
}
if (!CSV_PATH) {
  console.error('ERROR: --csv <path> argument is required.');
  console.error('  Example: node backfill-okta-profiles.js --csv ./hr_export.csv --dry-run');
  process.exit(1);
}
if (!fs.existsSync(CSV_PATH)) {
  console.error(`ERROR: CSV file not found at path: ${CSV_PATH}`);
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────
//  COLUMN HEADER MAPPING
//  These exactly match the headers on the "Active Employees" tab
//  of the HR Google Sheet. If the sheet's headers ever change,
//  update this map.
// ─────────────────────────────────────────────────────────────
const COL = {
  ENTITY:          'Entity',
  EMPLOYEE_ID:     'EEID',                  // leading-zero string e.g. "00001092237"
  DISPLAY_NAME:    'Display Name',
  JOB_TITLE:       'Job Title',
  PREF_WORK_EMAIL: 'Preferred Work Email',  // join key against Okta login (case-insensitive)
  MANAGER_NAME:    'Manager Name',
  MANAGER_EMAIL:   'Manager Email',
  DEPARTMENT:      'Department Name',
  OFFICE_LOCATION: 'Office Location',
  WORK_CITY:       'Work City',
  WORK_STATE:      'Work State',
};

// ─────────────────────────────────────────────────────────────
//  OFFICE LOCATION → ADDRESS LOOKUP
//
//  Keys are normalized (lowercased, with trailing "(XX)" state
//  suffix stripped). resolveOffice() does an exact-key match
//  first, then a partial contains match.
//
//  "remote" intentionally has NO countryCode — many Hillspire
//  "Remote XXX" entries are international (GBR, UKR, CAN, ZAF,
//  FRA, DEU, ITA, etc.) and we don't want to overwrite them
//  with US.
// ─────────────────────────────────────────────────────────────
const OFFICE_MAP = {
  'alma station':          { streetAddress: '1010 Alma Street',                 zipCode: '94025', countryCode: 'US' },
  'arlington office':      { streetAddress: '241 18th Street South Suite 1200', zipCode: '22202', countryCode: 'US' },
  'baltimore office':      { streetAddress: '3000 Falls Road Suite 200',        zipCode: '21211', countryCode: 'US' },
  'boston office':         { streetAddress: '110 Chauncy Street First Floor',   zipCode: '02111', countryCode: 'US' },
  'nantucket office':      { streetAddress: '58 Main Street 2nd Floor',         zipCode: '02554', countryCode: 'US' },
  'newport office':        { streetAddress: '100 Bellevue Avenue',              zipCode: '02840', countryCode: 'US' },
  'ocean hour farm':       { streetAddress: '152 Harrison Avenue',              zipCode: '02840', countryCode: 'US' },
  'new york office':       { streetAddress: '100 Fifth Avenue',                 zipCode: '10011', countryCode: 'US' },
  'san francisco office':  { streetAddress: '455 The Embarcadero',              zipCode: '94111', countryCode: 'US' },
  'santa monica office':   { streetAddress: '205 Hill Street 2nd Floor',        zipCode: '90405', countryCode: 'US' },
  'west hollywood office': { streetAddress: '9000 Sunset Boulevard Suite 1000', zipCode: '90069', countryCode: 'US' },
  'woodinville office':    { streetAddress: '20250 144th Avenue NE Suite 310',  zipCode: '98072', countryCode: 'US' },
  'remote':                { streetAddress: 'Remote' },
};

/**
 * Resolves an Office Location string from the HR sheet into an address payload.
 * Strips trailing state/country suffixes in parens (e.g. "Newport Office (RI)").
 * Returns { matched, data, raw }. If unmatched, the caller skips writing address fields.
 */
function resolveOffice(raw) {
  if (!raw || raw.trim() === '' || raw.trim() === '#N/A') return { matched: false, data: null, raw };

  const normalized = raw.trim().toLowerCase().replace(/\s*\([^)]*\)\s*/g, '').trim();

  // 1) Exact match
  if (OFFICE_MAP[normalized]) return { matched: true, data: OFFICE_MAP[normalized], raw };

  // 2) Partial contains match (handles "Remote CA" → "remote", "New York Office on Fifth" → "new york office", etc.)
  for (const key of Object.keys(OFFICE_MAP)) {
    if (normalized.includes(key) || key.includes(normalized)) {
      return { matched: true, data: OFFICE_MAP[key], raw };
    }
  }

  return { matched: false, data: null, raw };
}

// ─────────────────────────────────────────────────────────────
//  CSV PARSER
// ─────────────────────────────────────────────────────────────
function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter(l => l.trim());

  if (lines.length < 2) {
    console.error('ERROR: CSV appears empty or only has a header row.');
    process.exit(1);
  }

  const headers = parseCSVLine(lines[0]).map(h => h.trim());

  // Header sanity check — warn loudly if a required column is missing
  const missing = Object.values(COL).filter(col => !headers.includes(col));
  if (missing.length > 0) {
    console.warn('\n⚠️  WARNING: These expected columns were NOT found in the CSV header:');
    missing.forEach(m => console.warn(`   - "${m}"`));
    console.warn('   Update the COL mapping at the top of the script if your CSV uses different names.\n');
  }

  return lines.slice(1).map((line, idx) => {
    const values = parseCSVLine(line);
    const row = {};
    headers.forEach((h, i) => { row[h] = (values[i] || '').trim(); });
    row._lineNumber = idx + 2;
    return row;
  }).filter(row => {
    // Skip totally-empty rows
    if (!Object.entries(row).some(([k, v]) => k !== '_lineNumber' && v)) return false;

    // Skip the duplicate second-header-row that the HR sheet exports (it repeats
    // "Entity, Entity or Function, EEID, ..." as the first data row with
    // alternate column names).
    if (row[COL.ENTITY] === 'Entity' && row[COL.EMPLOYEE_ID] === 'EEID') return false;

    return true;
  });
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else { inQuotes = !inQuotes; }
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

// ─────────────────────────────────────────────────────────────
//  OKTA API
// ─────────────────────────────────────────────────────────────

/** Generic Okta API request → { status, data, headers } */
function oktaRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : null;
    const options = {
      hostname: OKTA_DOMAIN,
      path,
      method,
      headers: {
        'Authorization': `SSWS ${OKTA_API_TOKEN}`,
        'Content-Type':  'application/json',
        'Accept':        'application/json',
        ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 400) {
            const errMsg = parsed.errorSummary || parsed.message || JSON.stringify(parsed);
            reject(new Error(`HTTP ${res.statusCode}: ${errMsg}`));
          } else {
            resolve({ status: res.statusCode, data: parsed, headers: res.headers });
          }
        } catch (e) {
          reject(new Error(`Failed to parse Okta response (status ${res.statusCode}): ${data.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/** Pull every active Okta user where employeeNumber is empty (paginated). */
async function getDeltaUsers() {
  console.log('\n📡 Phase 1: Fetching active users with empty employeeNumber from Okta...');

  let users = [];
  let apiPath = `/api/v1/users?filter=status+eq+"ACTIVE"+and+profile.employeeNumber+eq+""&limit=200`;

  while (apiPath) {
    const res = await oktaRequest('GET', apiPath);
    users = users.concat(res.data);

    const linkHeader = res.headers['link'] || '';
    const nextMatch  = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
    if (nextMatch) {
      try {
        const nextUrl = new URL(nextMatch[1]);
        apiPath = nextUrl.pathname + nextUrl.search;
      } catch {
        apiPath = null;
      }
    } else {
      apiPath = null;
    }

    await sleep(100);
  }

  console.log(`   ✓ Found ${users.length} delta user(s) in Okta`);
  return users;
}

/** Partial profile update (only the keys in the payload are touched). */
function updateUser(userId, profilePayload) {
  return oktaRequest('POST', `/api/v1/users/${userId}`, { profile: profilePayload });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────────────────────
async function main() {
  const startTime = Date.now();

  console.log('\n┌──────────────────────────────────────────┐');
  console.log('│      Okta Profile Backfill Script        │');
  console.log('└──────────────────────────────────────────┘');
  console.log(`  Mode:        ${DRY_RUN ? '🔍 DRY RUN — no writes' : '🚀 LIVE — changes will be written'}`);
  console.log(`  CSV source:  ${CSV_PATH}`);
  console.log(`  Okta domain: ${OKTA_DOMAIN}`);

  // ── Phase 1: pull the delta from Okta ─────────────────────────
  const deltaUsers = await getDeltaUsers();

  if (deltaUsers.length === 0) {
    console.log('\n✅ No delta users found. Nothing to do.');
    return;
  }

  // ── Phase 2: parse the HR CSV ────────────────────────────────
  console.log('\n📄 Phase 2: Parsing HR CSV...');
  const hrRows = parseCSV(CSV_PATH);
  console.log(`   ✓ Parsed ${hrRows.length} usable row(s) from CSV`);

  const hrByEmail = {};
  for (const row of hrRows) {
    const email = (row[COL.PREF_WORK_EMAIL] || '').toLowerCase().trim();
    if (email) {
      if (hrByEmail[email]) {
        console.warn(`   ⚠️  Duplicate email in CSV (line ${row._lineNumber}): ${email} — last row wins`);
      }
      hrByEmail[email] = row;
    }
  }

  // ── Phase 3: join & build update payloads ────────────────────
  console.log('\n🔗 Phase 3: Joining delta users against HR data...');

  const toUpdate       = [];
  const orphans        = [];
  const unknownOffices = [];

  for (const oktaUser of deltaUsers) {
    const email = (oktaUser.profile.login || '').toLowerCase().trim();
    const hrRow = hrByEmail[email];
    const name  = `${oktaUser.profile.firstName} ${oktaUser.profile.lastName}`.trim();

    if (!hrRow) {
      orphans.push({ name, email, oktaId: oktaUser.id });
      continue;
    }

    // Only include fields with a value, so we never null out something already set
    const payload = {};
    const set = (oktaAttr, val) => {
      if (val && val.trim() !== '' && val.trim() !== '#N/A') payload[oktaAttr] = val.trim();
    };

    set('organization', hrRow[COL.ENTITY]);
    set('displayName',  hrRow[COL.DISPLAY_NAME]);
    set('title',        hrRow[COL.JOB_TITLE]);
    set('manager',      hrRow[COL.MANAGER_NAME]);
    set('managerId',    hrRow[COL.MANAGER_EMAIL]);
    set('department',   hrRow[COL.DEPARTMENT]);
    set('city',         hrRow[COL.WORK_CITY]);
    set('state',        hrRow[COL.WORK_STATE]);

    // employeeNumber: force string to preserve leading zeros (CSV "EEID" column)
    const empId = hrRow[COL.EMPLOYEE_ID];
    if (empId && empId.trim() !== '') {
      payload.employeeNumber = String(empId).trim();
    }

    // Office → street/zip/country lookup
    const officeRaw = hrRow[COL.OFFICE_LOCATION] || '';
    let officeResolved = false;
    if (officeRaw.trim() !== '' && officeRaw.trim() !== '#N/A') {
      const result = resolveOffice(officeRaw);
      if (result.matched) {
        if (result.data.streetAddress) payload.streetAddress = result.data.streetAddress;
        if (result.data.zipCode)       payload.zipCode       = result.data.zipCode;
        if (result.data.countryCode)   payload.countryCode   = result.data.countryCode;
        officeResolved = true;
      } else {
        unknownOffices.push({ name, email, oktaId: oktaUser.id, officeValue: officeRaw });
        // Still queue user — just skip address fields
      }
    }

    toUpdate.push({ oktaUser, hrRow, payload, officeResolved, officeRaw });
  }

  // ── Phase 4: pre-flight summary ──────────────────────────────
  console.log('\n📊 Phase 4: Pre-flight Summary');
  console.log('─'.repeat(48));
  console.log(`  Users queued for update   : ${toUpdate.length}`);
  console.log(`  Orphans (no CSV match)    : ${orphans.length}`);
  console.log(`  Unknown office locations  : ${unknownOffices.length}`);
  console.log('─'.repeat(48));

  if (orphans.length > 0) {
    console.log('\n⚠️  ORPHANS — delta users in Okta with no row in the HR CSV.');
    console.log('   These will NOT be updated. Investigate manually.\n');
    orphans.forEach(u => {
      console.log(`   • ${u.name.padEnd(32)} ${u.email.padEnd(40)} Okta ID: ${u.oktaId}`);
    });
  }

  if (unknownOffices.length > 0) {
    console.log('\n⚠️  UNKNOWN OFFICE LOCATIONS — address fields will be SKIPPED for these users.');
    console.log('   Review the values below and add them to OFFICE_MAP if needed.\n');
    unknownOffices.forEach(u => {
      console.log(`   • ${u.name.padEnd(32)} ${u.email.padEnd(40)} Office: "${u.officeValue}"`);
    });
  }

  // ── Dry run: print payloads and bail ─────────────────────────
  if (DRY_RUN) {
    console.log('\n🔍 DRY RUN — Payloads that WOULD be written to Okta:');
    console.log('─'.repeat(60));

    for (const { oktaUser, payload, officeRaw, officeResolved } of toUpdate) {
      const name  = `${oktaUser.profile.firstName} ${oktaUser.profile.lastName}`;
      const email = oktaUser.profile.login;
      console.log(`\n┌─ ${name} (${email})`);
      console.log(`│  Okta ID : ${oktaUser.id}`);
      if (officeRaw && !officeResolved) {
        console.log(`│  ⚠️  Office "${officeRaw}" not matched — address fields omitted`);
      }
      console.log('│  Payload :');
      Object.entries(payload).forEach(([k, v]) => {
        console.log(`│    ${k.padEnd(18)}: ${v}`);
      });
      console.log('└' + '─'.repeat(58));
    }

    console.log(`\n✅ Dry run complete. ${toUpdate.length} user(s) would be updated.`);
    console.log('   Remove --dry-run (or run `npm run run-live`) to execute.\n');
    return;
  }

  // ── Phase 5: live update ─────────────────────────────────────
  console.log(`\n🚀 Phase 5: Writing updates to Okta (${toUpdate.length} user(s))...`);
  console.log('   Rate-limited to ~150ms between calls.\n');

  const results = { success: [], failed: [] };

  for (const { oktaUser, payload } of toUpdate) {
    const name  = `${oktaUser.profile.firstName} ${oktaUser.profile.lastName}`;
    const email = oktaUser.profile.login;

    try {
      await updateUser(oktaUser.id, payload);
      console.log(`   ✓ ${name.padEnd(32)} ${email}`);
      results.success.push({ name, email, oktaId: oktaUser.id });
    } catch (err) {
      console.log(`   ✗ ${name.padEnd(32)} ${email}`);
      console.log(`      Error: ${err.message}`);
      results.failed.push({ name, email, oktaId: oktaUser.id, error: err.message });
    }

    await sleep(150);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log('\n┌──────────────────────────────────────────┐');
  console.log('│           FINAL SUMMARY                  │');
  console.log('└──────────────────────────────────────────┘');
  console.log(`  ✓ Successfully updated : ${results.success.length}`);
  console.log(`  ✗ Failed               : ${results.failed.length}`);
  console.log(`  ⚠️  Orphans (skipped)   : ${orphans.length}`);
  console.log(`  ⚠️  Unknown offices     : ${unknownOffices.length}`);
  console.log(`  ⏱  Elapsed             : ${elapsed}s`);

  if (results.failed.length > 0) {
    console.log('\n  ─── FAILED USERS ───');
    results.failed.forEach(u => console.log(`  • ${u.name} | ${u.email} | ${u.error}`));
  }

  const log = {
    timestamp:  new Date().toISOString(),
    dryRun:     false,
    oktaDomain: OKTA_DOMAIN,
    csvFile:    CSV_PATH,
    elapsedSec: parseFloat(elapsed),
    summary: {
      updated:        results.success.length,
      failed:         results.failed.length,
      orphans:        orphans.length,
      unknownOffices: unknownOffices.length,
    },
    successful: results.success,
    failed:     results.failed,
    orphans,
    unknownOffices,
  };

  const logFile = `backfill-log-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`;
  fs.writeFileSync(logFile, JSON.stringify(log, null, 2));
  console.log(`\n  📝 Full log saved to: ${logFile}\n`);
}

main().catch(err => {
  console.error('\n💥 Fatal error:', err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
