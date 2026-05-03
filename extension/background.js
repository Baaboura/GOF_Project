/**
 * Background Service Worker
 * Keeps the extension alive and handles badge updates.
 * Only activates on localhost / 127.0.0.1 tabs.
 */

function isLocalhost(url) {
  try {
    const { hostname } = new URL(url);
    return hostname === "localhost" || hostname === "127.0.0.1";
  } catch (_) {
    return false;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: "#00f5d4" });
  chrome.action.setBadgeText({ text: "" });
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab && isLocalhost(tab.url)) {
      chrome.action.setBadgeText({ text: "" });
    } else {
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
      chrome.action.setBadgeText({ text: "OFF" });
    }
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (isLocalhost(tab.url)) {
    chrome.action.setBadgeBackgroundColor({ color: "#00f5d4" });
    chrome.action.setBadgeText({ text: "" });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    chrome.action.setBadgeText({ text: "OFF" });
  }
});
