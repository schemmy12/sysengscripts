// ── Config ────────────────────────────────────────────────────────────
const DIRECTORY_TABLE  = "Fellows";
const CALENDAR_TABLE   = "Fellow Events Calendar & Media";
const ORGANIZATIONS_TABLE = "Organizations";
const BIRTHDAY_VIEW    = "Fellow Birthdays";
const FILTER           = "Rise Fellow";
const HANDBOOK_DOC_ID  = '1xgMa9deWVb2jL8pO9TcqcjUzCuQwoETIO2MrJChej2M';

const DIRECTORY_FIELDS = [
  "Full Name",
  "Selection Year",
  "Fellow Bio",
  "Fellow Photo",
  "Email",
  "Current Location (Country)",
  "Current Location (City/Town)",
  "Pronouns",
  "LinkedIn",
  "Unique Contact ID",
  "Rise Category",
  "Undergraduate Institution",
];

const BIRTHDAY_FIELDS = [
  "Unique Contact ID",
  "Preferred First Name",
  "Family Name",
  "Selection Year",
  "DOB",
  "Rise Category",
];
const BIRTHDAY_MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const BIRTHDAY_MONTH_NAMES = ["January","February","March","April","May","June","July","August","September","October","November","December"];
const BIRTHDAY_CACHE_KEY = 'birthday_data_v1';
const BIRTHDAY_CACHE_TTL_SEC = 6 * 60 * 60;

// ── Router ────────────────────────────────────────────────────────────
function doGet(e) {
  try {
    const type = (e && e.parameter && e.parameter.type) ? e.parameter.type : "directory";
    if (type === "calendar") return calendarResponse();
    if (type === "handbook") return handbookResponse();
    if (type === "birthdays") return birthdaysResponse();
    return directoryResponse();
  } catch (err) {
    return jsonResponse({ error: err.message });
  }
}

// ── Handbook ──────────────────────────────────────────────────────────
const HB_CACHE_KEY      = 'handbook_data_v2';
const HB_CHUNK_SIZE     = 90 * 1024;
const HB_CACHE_TTL_SEC  = 600;
const HB_MAX_CHUNKS     = 50;

function handbookResponse() {
  const cached = readHandbookCache();
  if (cached) return jsonResponse(JSON.parse(cached));
  const categories = parseHandbookDoc(HANDBOOK_DOC_ID);
  const result = { categories };
  const serialised = JSON.stringify(result);
  writeHandbookCache(serialised);
  return jsonResponse(result);
}

function readHandbookCache() {
  const cache = CacheService.getScriptCache();
  const index = cache.get(HB_CACHE_KEY + ':index');
  if (!index) return null;
  const numChunks = parseInt(index, 10);
  if (!numChunks || numChunks > HB_MAX_CHUNKS) return null;
  const keys = [];
  for (let i = 0; i < numChunks; i++) keys.push(HB_CACHE_KEY + ':' + i);
  const chunks = cache.getAll(keys);
  let combined = '';
  for (let i = 0; i < numChunks; i++) {
    const c = chunks[HB_CACHE_KEY + ':' + i];
    if (!c) return null;
    combined += c;
  }
  return combined;
}

function writeHandbookCache(str) {
  try {
    const cache = CacheService.getScriptCache();
    const chunks = {};
    let idx = 0;
    for (let pos = 0; pos < str.length; pos += HB_CHUNK_SIZE) {
      chunks[HB_CACHE_KEY + ':' + idx] = str.slice(pos, pos + HB_CHUNK_SIZE);
      idx++;
      if (idx >= HB_MAX_CHUNKS) {
        Logger.log('writeHandbookCache: exceeded HB_MAX_CHUNKS, aborting cache write');
        return;
      }
    }
    chunks[HB_CACHE_KEY + ':index'] = String(idx);
    cache.putAll(chunks, HB_CACHE_TTL_SEC);
  } catch(e) {
    Logger.log('writeHandbookCache failed: ' + e.message);
  }
}

function clearHandbookCache() {
  const cache = CacheService.getScriptCache();
  cache.remove('handbook_data');
  const indexRaw = cache.get(HB_CACHE_KEY + ':index');
  const keys = [HB_CACHE_KEY + ':index'];
  if (indexRaw) {
    const n = Math.min(parseInt(indexRaw, 10) || 0, HB_MAX_CHUNKS);
    for (let i = 0; i < n; i++) keys.push(HB_CACHE_KEY + ':' + i);
  } else {
    for (let i = 0; i < HB_MAX_CHUNKS; i++) keys.push(HB_CACHE_KEY + ':' + i);
  }
  cache.removeAll(keys);
  Logger.log('Handbook cache cleared (' + keys.length + ' keys)');
}

// ── Handbook: embed URL detection helpers ─────────────────────────────
const EMBED_URL_RE = /(https?:\/\/(?:docs\.google\.com\/(?:presentation|document|spreadsheets|forms)\/(?:d\/e\/[a-zA-Z0-9_-]+\/pub[a-zA-Z0-9_?&=\-]*|d\/[^\s]+)|drive\.google\.com\/file\/d\/[a-zA-Z0-9_-]+[^\s]*|airtable\.com\/(?:embed\/)?(?:app[a-zA-Z0-9]+\/)?shr[a-zA-Z0-9]+[^\s]*|(?:www\.)?youtube\.com\/watch\?v=[^\s&]+|youtu\.be\/[^\s]+|(?:www\.)?vimeo\.com\/\d+|(?:www\.)?loom\.com\/share\/[a-f0-9]+))/i;

function extractInlineEmbedUrl(para) {
  try {
    const n = para.getNumChildren();
    for (let i = 0; i < n; i++) {
      const el = para.getChild(i);
      const t = el.getType();
      if (t === DocumentApp.ElementType.INLINE_DRAWING) {
        try {
          const drawing = el.asInlineDrawing();
          const alt = drawing.getAltTitle() || drawing.getAltDescription() || '';
          const m = alt.match(EMBED_URL_RE);
          if (m) return m[1];
        } catch(e) {}
      }
    }
  } catch(e) {}
  return null;
}

function toEmbedSrc(url) {
  if (!url) return '';
  if (/docs\.google\.com\/[^/]+\/d\/e\/[a-zA-Z0-9_-]+\/pub/.test(url)) {
    return url;
  }
  // Airtable: if already in embed format, pass through with viewControls
  if (/airtable\.com\/embed\//.test(url)) {
    return url.includes('viewControls') ? url : url + (url.includes('?') ? '&' : '?') + 'viewControls=on';
  }
  let m = url.match(/docs\.google\.com\/presentation\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return `https://docs.google.com/presentation/d/${m[1]}/embed?start=false&loop=false&delayms=3000`;
  m = url.match(/docs\.google\.com\/document\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return `https://docs.google.com/document/d/${m[1]}/preview`;
  m = url.match(/docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return `https://docs.google.com/spreadsheets/d/${m[1]}/preview`;
  m = url.match(/docs\.google\.com\/forms\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return `https://docs.google.com/forms/d/${m[1]}/viewform?embedded=true`;
  m = url.match(/drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return `https://drive.google.com/file/d/${m[1]}/preview`;
  m = url.match(/airtable\.com\/(?:embed\/)?((app[a-zA-Z0-9]+\/)?)(shr[a-zA-Z0-9]+)/);
  if (m) return `https://airtable.com/embed/${m[1]}${m[3]}?viewControls=on`;
  m = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]+)/);
  if (m) return `https://www.youtube.com/embed/${m[1]}`;
  m = url.match(/vimeo\.com\/(\d+)/);
  if (m) return `https://player.vimeo.com/video/${m[1]}`;
  m = url.match(/loom\.com\/share\/([a-f0-9]+)/);
  if (m) return `https://www.loom.com/embed/${m[1]}`;
  return url;
}

function embedKind(url) {
  if (/presentation/.test(url)) return 'slides';
  if (/document/.test(url))     return 'doc';
  if (/spreadsheets/.test(url)) return 'sheet';
  if (/forms/.test(url))        return 'form';
  if (/drive\.google\.com\/file/.test(url)) {
    try {
      const m = url.match(/file\/d\/([a-zA-Z0-9_-]+)/);
      if (m) {
        const mime = DriveApp.getFileById(m[1]).getMimeType();
        if (/^video\//.test(mime)) return 'drive-video';
        if (/^image\//.test(mime)) return 'drive-image';
        if (mime === 'application/pdf') return 'drive-pdf';
      }
    } catch(e) {}
    return 'drive';
  }
  if (/youtube|youtu\.be/.test(url)) return 'youtube';
  if (/vimeo/.test(url))        return 'vimeo';
  if (/loom/.test(url))         return 'loom';
  if (/airtable\.com/.test(url)) return 'airtable';
  return 'other';
}

function parseHandbookDoc(docId) {
  const doc = DocumentApp.openById(docId);
  const tabs = doc.getTabs();
  const categories = [];

  tabs.forEach(tab => {
    const catTitle = tab.getTitle();
    const body = tab.asDocumentTab().getBody();
    const n = body.getNumChildren();
    const cat = { title: catTitle, sections: [] };
    let sec = null;

    const pushSec = () => { if (sec) { cat.sections.push(sec); sec = null; } };

    for (let i = 0; i < n; i++) {
      const child = body.getChild(i);
      const eType = child.getType();

      if (eType === DocumentApp.ElementType.PARAGRAPH) {
        const para = child.asParagraph();
        const heading = para.getHeading();
        const text = para.getText().trim();

        const inlineEmbedUrl = extractInlineEmbedUrl(para);
        if (inlineEmbedUrl && sec) {
          const src = toEmbedSrc(inlineEmbedUrl);
          sec.content.push({ type: 'embed', url: src, kind: embedKind(inlineEmbedUrl), text: '' });
          continue;
        }

        if (!text) continue;

        if (heading === DocumentApp.ParagraphHeading.HEADING1) {
          pushSec();
          sec = { title: text, content: [] };
        } else {
          if (!sec) continue;
          let type = 'p';
          if (heading === DocumentApp.ParagraphHeading.HEADING3) type = 'h3';
          else if (heading === DocumentApp.ParagraphHeading.HEADING4) type = 'h4';

          if (/^EMBED/i.test(text)) {
            const m = text.match(EMBED_URL_RE);
            if (m) {
              const url = m[1];
              sec.content.push({ type: 'embed', url: toEmbedSrc(url), kind: embedKind(url), text });
            } else {
              sec.content.push({ type: 'embed', text });
            }
            continue;
          }

          if (EMBED_URL_RE.test(text) && text.replace(EMBED_URL_RE, '').trim() === '') {
            const m = text.match(EMBED_URL_RE);
            const url = m[1];
            sec.content.push({ type: 'embed', url: toEmbedSrc(url), kind: embedKind(url), text: url });
            continue;
          }

          if (/^Screenshot\s+\d/i.test(text)) { sec.content.push({ type: 'image', text: '[Image placeholder]' }); continue; }
          sec.content.push({ type, text });
        }

      } else if (eType === DocumentApp.ElementType.LIST_ITEM) {
        if (!sec) continue;
        const item = child.asListItem();
        const text = item.getText().trim();
        if (!text) continue;
        const level = item.getNestingLevel();
        const glyph = item.getGlyphType();
        const ordered = (
          glyph === DocumentApp.GlyphType.DECIMAL ||
          glyph === DocumentApp.GlyphType.LATIN_LOWER ||
          glyph === DocumentApp.GlyphType.LATIN_UPPER ||
          glyph === DocumentApp.GlyphType.ROMAN_LOWER ||
          glyph === DocumentApp.GlyphType.ROMAN_UPPER
        );
        const listType = ordered ? 'olist' : 'list';
        const last = sec.content[sec.content.length - 1];
        if (last && (last.type === 'list' || last.type === 'olist')) {
          last.items.push({ text, level });
        } else {
          sec.content.push({ type: listType, items: [{ text, level }] });
        }

      } else if (eType === DocumentApp.ElementType.TABLE) {
        if (!sec) continue;
        // ── TABLE PARSING: extracts text cells normally, and embed URL cells
        // as objects with embedSrc/embedKind so the frontend can iframe them.
        try {
          const table = child.asTable();
          const numRows = table.getNumRows();
          const rows = [];
          for (let r = 0; r < numRows; r++) {
            const row = table.getRow(r);
            const numCells = row.getNumCells();
            const cells = [];
            for (let c = 0; c < numCells; c++) {
              const cellText = row.getCell(c).getText().trim();
              const embedMatch = cellText.match(EMBED_URL_RE);
              if (embedMatch && cellText.replace(EMBED_URL_RE, '').trim() === '') {
                // Cell contains only an embed URL — convert to iframe object
                const url = embedMatch[1];
                cells.push({ text: cellText, embedSrc: toEmbedSrc(url), embedKind: embedKind(url) });
              } else {
                // Plain text cell
                cells.push({ text: cellText });
              }
            }
            rows.push(cells);
          }
          if (rows.length > 0) {
            sec.content.push({ type: 'table', rows });
          } else {
            sec.content.push({ type: 'table', text: '[Empty table]' });
          }
        } catch(e) {
          sec.content.push({ type: 'table', text: '[Table — see Google Doc for full content]' });
        }
      }
    }
    pushSec();
    categories.push(cat);
  });

  return categories;
}

function diagnoseDoc() {
  const body = DocumentApp.openById(HANDBOOK_DOC_ID).getBody();
  const n = body.getNumChildren();
  const results = [];
  for (let i = 0; i < n; i++) {
    const child = body.getChild(i);
    if (child.getType() === DocumentApp.ElementType.PARAGRAPH) {
      const para = child.asParagraph();
      const text = para.getText().trim();
      const heading = para.getHeading();
      if (text) results.push(heading + ': ' + text.substring(0, 60));
    }
  }
  Logger.log(results.join('\n'));
}

function diagnoseHandbook() {
  const categories = parseHandbookDoc(HANDBOOK_DOC_ID);
  categories.forEach(cat => {
    Logger.log('═══ ' + cat.title + ' ═══');
    cat.sections.forEach(sec => {
      const tables = sec.content.filter(e => e.type === 'table');
      const embeds = sec.content.filter(e => e.type === 'embed');
      const parsedTables = tables.filter(t => t.rows && t.rows.length).length;
      const parsedEmbeds = embeds.filter(e => e.url).length;
      Logger.log(`  ${sec.title}`);
      Logger.log(`    tables: ${tables.length} (${parsedTables} parsed with rows)`);
      Logger.log(`    embeds: ${embeds.length} (${parsedEmbeds} parsed with URLs)`);
    });
  });
}

function diagnosePlaceholders() {
  const PLACEHOLDER_RE = /^(video\s*link|video|embed|tbd|todo|tba|insert(\s+link)?|coming\s+soon|placeholder|link\s+here|\[link\]|\[video\]|\[embed\])$/i;
  const BUTTON_RE = /^[A-Z][A-Z\s\d\-,&':()!]*((VIDEO\s+LINK|VIDEO|EMBED)\s*)$/;

  const doc = DocumentApp.openById(HANDBOOK_DOC_ID);
  const hits = [];
  doc.getTabs().forEach(tab => {
    const tabTitle = tab.getTitle();
    const body = tab.asDocumentTab().getBody();
    const n = body.getNumChildren();
    let currentSection = '(before any heading)';

    function checkText(text, context) {
      if (!text) return null;
      const t = text.trim();
      if (!t) return null;
      if (PLACEHOLDER_RE.test(t)) return { match: t, kind: 'placeholder-exact', context };
      if (BUTTON_RE.test(t)) return { match: t, kind: 'button-placeholder', context };
      return null;
    }

    for (let i = 0; i < n; i++) {
      const child = body.getChild(i);
      const eType = child.getType();

      if (eType === DocumentApp.ElementType.PARAGRAPH) {
        const para = child.asParagraph();
        if (para.getHeading() === DocumentApp.ParagraphHeading.HEADING1) {
          currentSection = para.getText().trim();
        }
        const hit = checkText(para.getText(), 'paragraph');
        if (hit) {
          hits.push({ tab: tabTitle, section: currentSection, ...hit });
        }

      } else if (eType === DocumentApp.ElementType.TABLE) {
        const table = child.asTable();
        const numRows = table.getNumRows();
        for (let r = 0; r < numRows; r++) {
          const row = table.getRow(r);
          const numCells = row.getNumCells();
          for (let c = 0; c < numCells; c++) {
            const cellText = row.getCell(c).getText();
            const hit = checkText(cellText, `table row ${r+1}, cell ${c+1}`);
            if (hit) {
              hits.push({ tab: tabTitle, section: currentSection, ...hit });
            }
          }
        }
      }
    }
  });

  const grouped = {};
  hits.forEach(h => {
    const key = `${h.tab}  >>  ${h.section}`;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(h);
  });

  Logger.log('═══════════════════════════════════════════');
  Logger.log('PLACEHOLDER DIAGNOSTIC — ' + hits.length + ' total');
  Logger.log('═══════════════════════════════════════════');
  Object.keys(grouped).forEach(key => {
    Logger.log('');
    Logger.log('── ' + key);
    grouped[key].forEach(h => {
      Logger.log('   [' + h.kind + '] "' + h.match + '"  (in ' + h.context + ')');
    });
  });
  if (hits.length === 0) Logger.log('No placeholders found — clean doc!');
}

// ── Directory ─────────────────────────────────────────────────────────
function directoryResponse() {
  const { token, baseId } = getProps();
  const records = fetchAll(token, baseId, DIRECTORY_TABLE, DIRECTORY_FIELDS);
  const orgNameById = getRecordNameMap(token, baseId, ORGANIZATIONS_TABLE);
  const filtered = records
    .filter(r => r.fields["Rise Category"] === FILTER)
    .map(r => normaliseDirectory(r.fields, orgNameById));
  return jsonResponse({ count: filtered.length, records: filtered });
}

function normaliseDirectory(f, orgNameById) {
  const photo = Array.isArray(f["Fellow Photo"]) && f["Fellow Photo"].length > 0
    ? f["Fellow Photo"][0].url : "";
  const undergraduateInstitution = linkedRecordText(f["Undergraduate Institution"], orgNameById);
  return {
    id:        f["Unique Contact ID"] || "",
    name:      f["Full Name"]         || "",
    year:      f["Selection Year"]    || "",
    bio:       f["Fellow Bio"]        || "",
    photo,
    email:     f["Email"]             || "",
    country:   f["Current Location (Country)"]  || "",
    city:      f["Current Location (City/Town)"] || "",
    countries: f["Current Location (Country)"]  || "",
    pronouns:  f["Pronouns"] || "",
    linkedin:  f["LinkedIn"] || "",
    university: undergraduateInstitution,
    undergraduateInstitution,
  };
}

function fieldText(value) {
  if (value == null) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value).trim();
  }
  if (Array.isArray(value)) return value.map(fieldText).filter(Boolean).join(", ");
  if (typeof value === "object") {
    for (const key of ["name", "text", "label", "title", "value"]) {
      if (value[key] != null) return fieldText(value[key]);
    }
  }
  return "";
}

function linkedRecordText(value, nameById) {
  if (value == null) return "";
  const resolveOne = item => {
    if (typeof item === "string" && /^rec[A-Za-z0-9]+$/.test(item)) return nameById[item] || "";
    return fieldText(item);
  };
  if (Array.isArray(value)) return value.map(resolveOne).filter(Boolean).join(", ");
  return resolveOne(value);
}

function getRecordNameMap(token, baseId, tableName) {
  const map = {};
  fetchAll(token, baseId, tableName, []).forEach(record => {
    const name = recordDisplayName(record.fields);
    if (name) map[record.id] = name;
  });
  return map;
}

function recordDisplayName(fields) {
  const preferred = ["Organization Name", "Name", "Institution Name", "University Name", "School Name"];
  for (const key of preferred) {
    const value = fieldText(fields[key]);
    if (value) return value;
  }
  for (const key in fields) {
    const value = fieldText(fields[key]);
    if (value) return value;
  }
  return "";
}

// ── Birthdays ─────────────────────────────────────────────────────────
function birthdaysResponse() {
  const { token, baseId } = getProps();
  const currentMonth = new Date().getMonth() + 1;
  const currentYear = new Date().getFullYear();
  const cacheKey = `${BIRTHDAY_CACHE_KEY}:${currentYear}:${currentMonth}`;
  const cache = CacheService.getScriptCache();
  const cached = cache.get(cacheKey);
  if (cached) return jsonResponse(JSON.parse(cached));

  const records = fetchAll(token, baseId, DIRECTORY_TABLE, BIRTHDAY_FIELDS, { view: BIRTHDAY_VIEW });
  const birthdays = records
    .map(r => normaliseBirthday(r.fields))
    .filter(b => b.name && b.dob && b.month === currentMonth)
    .sort((a, b) => a.day - b.day || a.name.localeCompare(b.name));
  const result = {
    count: birthdays.length,
    month: currentMonth,
    monthName: BIRTHDAY_MONTH_NAMES[currentMonth - 1],
    birthdays
  };
  cache.put(cacheKey, JSON.stringify(result), BIRTHDAY_CACHE_TTL_SEC);
  return jsonResponse(result);
}

function normaliseBirthday(f) {
  const first = fieldText(f["Preferred First Name"]);
  const last = fieldText(f["Family Name"]);
  const fallbackName = fieldText(f["Unique Contact ID"]).replace(/\s*\[[^\]]+\]\s*$/, "");
  const dob = parseBirthdayDate(f["DOB"]);
  return {
    id: fieldText(f["Unique Contact ID"]),
    name: [first, last].filter(Boolean).join(" ") || fallbackName,
    year: fieldText(f["Selection Year"]),
    dob: dob ? `${dob.year}-${pad2(dob.month)}-${pad2(dob.day)}` : "",
    dateLabel: dob ? formatBirthdayLabel(dob.month, dob.day) : "",
    month: dob ? dob.month : "",
    day: dob ? dob.day : "",
  };
}

function parseBirthdayDate(value) {
  const text = fieldText(value);
  if (!text) return null;
  const iso = text.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (iso) {
    return {
      year: Number(iso[1]),
      month: Number(iso[2]),
      day: Number(iso[3]),
    };
  }
  const parsed = new Date(text);
  if (isNaN(parsed.getTime())) return null;
  return {
    year: parsed.getFullYear(),
    month: parsed.getMonth() + 1,
    day: parsed.getDate(),
  };
}

function formatBirthdayLabel(month, day) {
  return `${BIRTHDAY_MONTHS[month - 1]} ${day}`;
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

// ── Calendar ──────────────────────────────────────────────────────────
function calendarResponse() {
  const { token, baseId } = getProps();
  const records = fetchAll(token, baseId, CALENDAR_TABLE, []);
  const events = records.map(r => normaliseEvent(r.id, r.fields));
  return jsonResponse({ count: events.length, events });
}

function normaliseEvent(id, f) {
  return {
    id,
    name:        f["Event Name"]   || "",
    date:        f["Start Date"]   || "",
    endDate:     f["End Date"]     || "",
    time:        f["Event Time"]   || "",
    type:        f["Type"]         || "",
    category:    f["Category"]     || "",
    location:    f["Location"]     || "",
    venue:       f["Venue"]        || "",
    description: f["Notes"]        || "",
    link:        f["URL"]          || "",
    status:      f["Event Status"] || "",
  };
}

// ── Shared helpers ────────────────────────────────────────────────────
function getProps() {
  const props  = PropertiesService.getScriptProperties();
  const token  = props.getProperty("AIRTABLE_TOKEN");
  const baseId = props.getProperty("AIRTABLE_BASE");
  if (!token || !baseId) throw new Error("Missing AIRTABLE_TOKEN or AIRTABLE_BASE");
  return { token, baseId };
}

function fetchAll(token, baseId, tableName, fields, opts) {
  const all = [];
  let offset = null;
  do {
    let url = `https://api.airtable.com/v0/${baseId}/${encodeURIComponent(tableName)}?pageSize=100`;
    if (fields && fields.length > 0)
      fields.forEach(f => url += `&fields[]=${encodeURIComponent(f)}`);
    if (opts && opts.view) url += `&view=${encodeURIComponent(opts.view)}`;
    if (offset) url += `&offset=${offset}`;
    const res = UrlFetchApp.fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      muteHttpExceptions: true
    });
    const data = JSON.parse(res.getContentText());
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    all.push(...(data.records || []));
    offset = data.offset || null;
  } while (offset);
  return all;
}

function jsonResponse(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

// ── Diagnostics ───────────────────────────────────────────────────────
function listEventFields() {
  const { token, baseId } = getProps();
  const res = UrlFetchApp.fetch(
    `https://api.airtable.com/v0/meta/bases/${baseId}/tables`,
    { headers: { Authorization: "Bearer " + token }, muteHttpExceptions: true }
  );
  const tables = JSON.parse(res.getContentText()).tables;
  const t = tables.find(t => t.name.includes("Events"));
  Logger.log("Table name: " + t.name);
  Logger.log("Fields:\n" + t.fields.map(f => f.name).join("\n"));
}

function diagnose() {
  const { token, baseId } = getProps();
  Logger.log("Token length: " + token.length);
  Logger.log("Token starts with pat: " + token.startsWith("pat"));
  const res = UrlFetchApp.fetch(
    `https://api.airtable.com/v0/${baseId}/Fellows?maxRecords=1`,
    { headers: { Authorization: "Bearer " + token }, muteHttpExceptions: true }
  );
  Logger.log("HTTP: " + res.getResponseCode());
  Logger.log(res.getContentText());
}

function warmHandbookCache() {
  try {
    const categories = parseHandbookDoc(HANDBOOK_DOC_ID);
    const result = { categories };
    const serialised = JSON.stringify(result);
    Logger.log('Parsed handbook payload: ' + (serialised.length / 1024).toFixed(1) + ' KB');
    writeHandbookCache(serialised);
    const readback = readHandbookCache();
    if (readback && readback.length === serialised.length) {
      Logger.log('Cache warmed and verified at ' + new Date());
    } else {
      Logger.log('Cache warmed but verification failed (write size: ' + serialised.length + ', readback size: ' + (readback ? readback.length : 'null') + ')');
    }
  } catch(e) {
    Logger.log('Cache warm failed: ' + e.message);
  }
}

function testEmbedKind() {
  const testUrls = [
    'https://drive.google.com/file/d/1C__MlLxA2rcsBp4spx_Bc80JZaCeyShH/view',
    'https://drive.google.com/file/d/12AC7aJs6cQFyew8AiiQCocluMnCi8RSP/view',
    'https://drive.google.com/file/d/19GETrGezKu6uiPlH97MYnal4b6FKuifn/view'
  ];
  testUrls.forEach(url => {
    Logger.log('─────────────');
    Logger.log('URL: ' + url);
    const m = url.match(/file\/d\/([a-zA-Z0-9_-]+)/);
    if (!m) { Logger.log('Could not extract file ID'); return; }
    const fileId = m[1];
    try {
      const file = DriveApp.getFileById(fileId);
      const mime = file.getMimeType();
      const name = file.getName();
      Logger.log('Name: ' + name);
      Logger.log('MIME: ' + mime);
      Logger.log('Kind returned by embedKind(): ' + embedKind(url));
    } catch(e) {
      Logger.log('ERROR accessing Drive file: ' + e.message);
      Logger.log('Kind returned by embedKind() (fallback): ' + embedKind(url));
    }
  });
}
