(() => {
  const HELPER_URL = "http://127.0.0.1:8765/capture";
  const TIME_PATTERN = /\b(?:1[0-2]|0?[1-9]):[0-5]\d\s*(?:AM|PM)\b/i;
  const PLAYER_PATTERN = /\b\d+\s*[-\u2013\u2014]\s*\d+\s*Players?\b|\b\d+\s*Players?\b/i;
  const STATE = {
    lastSignature: "",
    lastSentAt: 0
  };

  function textOf(node) {
    return ((node && (node.innerText || node.textContent)) || "").replace(/\s+/g, " ").trim();
  }

  function findDateText() {
    const inputs = Array.from(document.querySelectorAll("input"));
    for (const input of inputs) {
      const value = input.value || input.getAttribute("value") || "";
      const match = value.match(/\b\d{1,2}\/\d{1,2}\/\d{4}\b/);
      if (match) return match[0];
    }

    const match = textOf(document.body).match(/\b\d{1,2}\/\d{1,2}\/\d{4}\b/);
    return match ? match[0] : "";
  }

  function isoDate(mmddyyyy) {
    const match = String(mmddyyyy || "").match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (!match) return "";
    return `${match[3]}-${match[1].padStart(2, "0")}-${match[2].padStart(2, "0")}`;
  }

  function dayName(dateIso) {
    const parts = dateIso.split("-").map(Number);
    if (parts.length !== 3 || parts.some(Number.isNaN)) return "";
    return new Date(parts[0], parts[1] - 1, parts[2]).toLocaleDateString(undefined, { weekday: "long" });
  }

  function parseOpenSpots(text) {
    const range = text.match(/\b(\d+)\s*[-\u2013\u2014]\s*(\d+)\s*Players?\b/i);
    if (range) return Number(range[2]);
    const single = text.match(/\b(\d+)\s*Players?\b/i);
    return single ? Number(single[1]) : 0;
  }

  function parseHoles(text) {
    const cleaned = text.replace(/\$\s*\d+(?:\.\d{2})?/g, " ");
    const match = cleaned.match(/(?:^|\D)(9|18)(?:\D|$)/);
    return match ? Number(match[1]) : null;
  }

  function parsePrice(text) {
    const match = text.match(/\$\s*\d+(?:\.\d{2})?/);
    return match ? match[0].replace(/\s+/g, "") : "";
  }

  function courseName() {
    const bodyText = textOf(document.body);
    const course = bodyText.match(/Course:\s*([^0-9$]+?)(?:\s{2,}|$|Players?|Holes?|tee times?)/i);
    return course ? course[1].trim() : document.title || "EZLinks tee sheet";
  }

  function candidateCards() {
    const elements = Array.from(document.querySelectorAll("article, li, section, div"));
    const cards = [];

    for (const el of elements) {
      const text = textOf(el);
      if (!TIME_PATTERN.test(text) || !PLAYER_PATTERN.test(text)) continue;

      const rect = el.getBoundingClientRect();
      const area = rect.width * rect.height;
      if (rect.width < 80 || rect.height < 60 || rect.width > 720 || rect.height > 580) continue;
      if (text.length > 560) continue;

      cards.push({ el, text, area, y: rect.y });
    }

    cards.sort((a, b) => a.area - b.area);
    const selected = [];
    for (const card of cards) {
      const overlaps = selected.some((other) => card.el.contains(other.el) || other.el.contains(card.el));
      if (!overlaps) selected.push(card);
    }
    return selected.sort((a, b) => a.y - b.y);
  }

  function captureVisibleSlots() {
    const dateText = findDateText();
    const date = isoDate(dateText);
    if (!date) {
      return { ok: false, error: "No tee-sheet date found on page." };
    }

    const course = courseName();
    const slots = candidateCards().map((card) => {
      const text = card.text;
      const link = card.el.querySelector("a[href]");
      const time = text.match(TIME_PATTERN);
      return {
        date,
        day: dayName(date),
        time: time ? time[0].replace(/\s+/g, " ").toUpperCase() : "",
        course,
        open_spots: parseOpenSpots(text),
        holes: parseHoles(text),
        price: parsePrice(text),
        tee: /front/i.test(text) ? "Front nine" : (/back/i.test(text) ? "Back nine" : null),
        booking_url: link ? link.href : window.location.href,
        source_text: text
      };
    });

    return {
      ok: true,
      page_url: window.location.href,
      course_name: course,
      captured_dates: [date],
      slots
    };
  }

  function signature(payload) {
    if (!payload.ok) return `error:${payload.error}`;
    return JSON.stringify(payload.slots.map((slot) => [
      slot.date,
      slot.time,
      slot.open_spots,
      slot.holes,
      slot.price
    ]));
  }

  async function postCapture(payload) {
    const response = await fetch(HELPER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || `Helper HTTP ${response.status}`);
    }
    return result;
  }

  async function captureAndSend(options = {}) {
    const payload = captureVisibleSlots();
    if (!payload.ok) return payload;

    const now = Date.now();
    const nextSignature = signature(payload);
    const force = Boolean(options.force);
    if (!force && nextSignature === STATE.lastSignature && now - STATE.lastSentAt < 45000) {
      return { ok: true, skipped: true, reason: "unchanged", slots: payload.slots.length };
    }

    const result = await postCapture(payload);
    STATE.lastSignature = nextSignature;
    STATE.lastSentAt = now;
    return { ok: true, slots: payload.slots.length, result };
  }

  let observerTimer = 0;
  function schedulePassiveCapture() {
    window.clearTimeout(observerTimer);
    observerTimer = window.setTimeout(() => {
      chrome.storage.local.get({ enabled: true, passiveCapture: true }, (settings) => {
        if (!settings.enabled || !settings.passiveCapture) return;
        captureAndSend({ force: false }).catch(() => {});
      });
    }, 2500);
  }

  const observer = new MutationObserver(schedulePassiveCapture);
  observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  schedulePassiveCapture();

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || message.type !== "TEE_TIME_CAPTURE") return false;
    captureAndSend({ force: Boolean(message.force) })
      .then(sendResponse)
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  });
})();
