/**
 * Phishing Analyzer Content Script.
 * Extracts page URL, scans visible links, and supports highlighting suspicious links on-page.
 */

function collectPageLinks() {
  const links = new Set();
  const anchorElements = document.querySelectorAll("a[href]");

  anchorElements.forEach((el) => {
    try {
      const href = el.href;
      if (!href) return;
      // Filter out non-http protocols
      if (href.startsWith("http://") || href.startsWith("https://")) {
        // Exclude current page anchors
        const urlObj = new URL(href);
        if (urlObj.protocol === "http:" || urlObj.protocol === "https:") {
          links.add(urlObj.href);
        }
      }
    } catch (e) {
      // Ignore malformed hrefs
    }
  });

  return Array.from(links).slice(0, 100);
}

function highlightSuspiciousLinks(flaggedUrls) {
  if (!flaggedUrls || !flaggedUrls.length) return;
  const flaggedSet = new Set(flaggedUrls.map(u => u.toLowerCase()));

  const anchorElements = document.querySelectorAll("a[href]");
  anchorElements.forEach((el) => {
    try {
      const href = el.href.toLowerCase();
      if (flaggedSet.has(href)) {
        el.style.outline = "2px dashed #ef4444";
        el.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
        el.style.borderRadius = "3px";
        el.title = "⚠️ Flagged as Suspicious / Phishing by Phishing Analyzer";
      }
    } catch (e) {}
  });
}

function clearHighlights() {
  const anchorElements = document.querySelectorAll("a[href]");
  anchorElements.forEach((el) => {
    el.style.outline = "";
    el.style.backgroundColor = "";
  });
}

// Listen for messages from popup or background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_PAGE_DATA") {
    sendResponse({
      url: window.location.href,
      title: document.title,
      links: collectPageLinks()
    });
  } else if (message.action === "HIGHLIGHT_LINKS") {
    highlightSuspiciousLinks(message.flaggedUrls || []);
    sendResponse({ status: "ok" });
  } else if (message.action === "CLEAR_HIGHLIGHTS") {
    clearHighlights();
    sendResponse({ status: "ok" });
  }
  return true;
});
