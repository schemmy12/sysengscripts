const EZLINKS_PATTERN = "https://wildwoodgreenmem.ezlinksgolf.com/*";
const EZLINKS_SEARCH_URL = "https://wildwoodgreenmem.ezlinksgolf.com/index.html#/search";
const DEFAULTS = {
  enabled: true,
  passiveCapture: true,
  autoOpenTab: false,
  pollMinutes: 1
};

async function getSettings() {
  return chrome.storage.local.get(DEFAULTS);
}

async function setAlarm() {
  const settings = await getSettings();
  await chrome.alarms.clear("tee-time-radar");
  if (!settings.enabled) return;
  chrome.alarms.create("tee-time-radar", {
    periodInMinutes: Math.max(1, Number(settings.pollMinutes) || 1)
  });
}

async function notify(title, message) {
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icon.svg",
      title,
      message
    });
  } catch {
    // Notifications are best effort; SMS comes from the local helper.
  }
}

async function getEzlinksTab(settings) {
  const tabs = await chrome.tabs.query({ url: EZLINKS_PATTERN });
  const searchTab = tabs.find((tab) => tab.url && tab.url.includes("#/search"));
  if (searchTab) return searchTab;
  if (tabs[0]) return tabs[0];
  if (!settings.autoOpenTab) return null;
  return chrome.tabs.create({ url: EZLINKS_SEARCH_URL, active: false, pinned: true });
}

async function captureTab(tab, force = false) {
  if (!tab || !tab.id) return { ok: false, error: "No EZLinks tab is open." };
  try {
    return await chrome.tabs.sendMessage(tab.id, { type: "TEE_TIME_CAPTURE", force });
  } catch (error) {
    return { ok: false, error: error.message || String(error) };
  }
}

async function runCapture(force = false) {
  const settings = await getSettings();
  if (!settings.enabled) return { ok: false, error: "Extension monitor is disabled." };

  const tab = await getEzlinksTab(settings);
  if (!tab) {
    return { ok: false, error: "Open an EZLinks search tab or enable auto-open." };
  }

  const result = await captureTab(tab, force);
  await chrome.storage.local.set({
    lastCaptureAt: new Date().toISOString(),
    lastCaptureResult: result
  });

  if (result && result.ok && result.result && result.result.matches > 0) {
    await notify(
      "Tee Time Radar match",
      `${result.result.matches} matching tee time${result.result.matches === 1 ? "" : "s"} captured.`
    );
  }
  return result;
}

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(Object.keys(DEFAULTS));
  await chrome.storage.local.set({ ...DEFAULTS, ...current });
  await setAlarm();
});

chrome.runtime.onStartup.addListener(setAlarm);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.enabled || changes.pollMinutes) setAlarm();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "tee-time-radar") runCapture(false);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "RUN_CAPTURE_NOW") return false;
  runCapture(true).then(sendResponse).catch((error) => sendResponse({ ok: false, error: error.message }));
  return true;
});
