const DEFAULTS = {
  enabled: true,
  passiveCapture: true,
  autoOpenTab: false,
  pollMinutes: 1
};

const fields = {
  enabled: document.getElementById("enabled"),
  passiveCapture: document.getElementById("passiveCapture"),
  autoOpenTab: document.getElementById("autoOpenTab"),
  pollMinutes: document.getElementById("pollMinutes"),
  captureNow: document.getElementById("captureNow"),
  status: document.getElementById("status")
};

function setStatus(message, className = "") {
  fields.status.className = `card status ${className}`.trim();
  fields.status.textContent = message;
}

async function loadSettings() {
  const settings = await chrome.storage.local.get({
    ...DEFAULTS,
    lastCaptureAt: "",
    lastCaptureResult: null
  });
  fields.enabled.checked = Boolean(settings.enabled);
  fields.passiveCapture.checked = Boolean(settings.passiveCapture);
  fields.autoOpenTab.checked = Boolean(settings.autoOpenTab);
  fields.pollMinutes.value = String(settings.pollMinutes || 1);
  renderLastResult(settings.lastCaptureAt, settings.lastCaptureResult);
}

function renderLastResult(at, result) {
  if (!at || !result) {
    setStatus("No capture yet. Open EZLinks and click Capture Now.", "warn");
    return;
  }

  const time = new Date(at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (result.ok) {
    const captured = result.result ? result.result.total_slots : result.slots;
    const matches = result.result ? result.result.matches : 0;
    setStatus(`Last capture ${time}: ${captured || 0} total slots, ${matches || 0} matches.`, "ok");
  } else {
    setStatus(`Last capture ${time}: ${result.error || "failed"}`, "warn");
  }
}

async function saveSettings() {
  await chrome.storage.local.set({
    enabled: fields.enabled.checked,
    passiveCapture: fields.passiveCapture.checked,
    autoOpenTab: fields.autoOpenTab.checked,
    pollMinutes: Number(fields.pollMinutes.value)
  });
}

async function captureNow() {
  setStatus("Capturing visible EZLinks tab...");
  const result = await chrome.runtime.sendMessage({ type: "RUN_CAPTURE_NOW" });
  const at = new Date().toISOString();
  await chrome.storage.local.set({ lastCaptureAt: at, lastCaptureResult: result });
  renderLastResult(at, result);
}

[fields.enabled, fields.passiveCapture, fields.autoOpenTab, fields.pollMinutes].forEach((field) => {
  field.addEventListener("change", saveSettings);
});

fields.captureNow.addEventListener("click", () => {
  captureNow().catch((error) => setStatus(error.message, "warn"));
});

loadSettings().catch((error) => setStatus(error.message, "warn"));
