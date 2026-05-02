(function () {
  const scriptUrl = new URL(document.currentScript.src);
  const captureUrl = `${scriptUrl.origin}/capture`;
  const timePattern = /\b(?:1[0-2]|0?[1-9]):[0-5]\d\s*(?:AM|PM)\b/i;
  const playerPattern = /\b\d+\s*[-\u2013\u2014]\s*\d+\s*Players?\b|\b\d+\s*Players?\b/i;

  function textOf(node) {
    return (node && (node.innerText || node.textContent) || "").replace(/\s+/g, " ").trim();
  }

  function findDateText() {
    const inputs = Array.from(document.querySelectorAll("input"));
    for (const input of inputs) {
      const value = input.value || input.getAttribute("value") || "";
      const match = value.match(/\b\d{1,2}\/\d{1,2}\/\d{4}\b/);
      if (match) return match[0];
    }

    const bodyText = textOf(document.body);
    const match = bodyText.match(/\b\d{1,2}\/\d{1,2}\/\d{4}\b/);
    if (match) return match[0];
    return window.prompt("Tee sheet date (MM/DD/YYYY)", "");
  }

  function isoDate(mmddyyyy) {
    const match = String(mmddyyyy || "").match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (!match) return "";
    const month = match[1].padStart(2, "0");
    const day = match[2].padStart(2, "0");
    return `${match[3]}-${month}-${day}`;
  }

  function dayName(dateIso) {
    const parts = dateIso.split("-").map(Number);
    if (parts.length !== 3 || parts.some(Number.isNaN)) return "";
    const date = new Date(parts[0], parts[1] - 1, parts[2]);
    return date.toLocaleDateString(undefined, { weekday: "long" });
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
      if (!timePattern.test(text) || !playerPattern.test(text)) continue;

      const rect = el.getBoundingClientRect();
      const area = rect.width * rect.height;
      if (rect.width < 80 || rect.height < 60 || rect.width > 700 || rect.height > 560) continue;
      if (text.length > 520) continue;

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

  function visibleSlots() {
    const dateText = findDateText();
    const date = isoDate(dateText);
    if (!date) throw new Error("Could not determine tee sheet date.");

    const course = courseName();
    return {
      page_url: window.location.href,
      course_name: course,
      captured_dates: [date],
      slots: candidateCards().map((card) => {
        const link = card.el.querySelector("a[href]");
        const timeMatch = card.text.match(timePattern);
        return {
          date,
          day: dayName(date),
          time: timeMatch ? timeMatch[0].replace(/\s+/g, " ").toUpperCase() : "",
          course,
          open_spots: parseOpenSpots(card.text),
          holes: parseHoles(card.text),
          price: parsePrice(card.text),
          tee: /front/i.test(card.text) ? "Front nine" : (/back/i.test(card.text) ? "Back nine" : null),
          booking_url: link ? link.href : window.location.href,
          source_text: card.text
        };
      })
    };
  }

  function showToast(message, isError) {
    const toast = document.createElement("div");
    toast.textContent = message;
    toast.style.cssText = [
      "position:fixed",
      "z-index:2147483647",
      "right:18px",
      "bottom:18px",
      "max-width:420px",
      "padding:14px 16px",
      "border-radius:8px",
      "box-shadow:0 12px 34px rgba(0,0,0,.25)",
      "font:700 14px/1.35 system-ui,-apple-system,Segoe UI,sans-serif",
      `background:${isError ? "#fff1f0" : "#eef9f1"}`,
      `color:${isError ? "#7a1f18" : "#153d32"}`,
      `border:1px solid ${isError ? "#e7aaa4" : "#a9dabc"}`
    ].join(";");
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 9000);
  }

  async function capture() {
    const payload = visibleSlots();
    const response = await fetch(captureUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || `Capture failed with HTTP ${response.status}`);
    }
    showToast(`Captured ${result.slots} visible slots, ${result.matches} dashboard matches.`, false);
  }

  capture().catch((error) => {
    console.error("Tee Time Radar capture failed", error);
    showToast(`Tee Time Radar capture failed: ${error.message}`, true);
  });
}());
