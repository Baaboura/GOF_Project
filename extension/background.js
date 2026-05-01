/**
 * Background Service Worker
 * Keeps the extension alive and handles badge updates.
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: "#00f5d4" });
  chrome.action.setBadgeText({ text: "" });
});

// Update badge when a tab is activated
chrome.tabs.onActivated.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
});
