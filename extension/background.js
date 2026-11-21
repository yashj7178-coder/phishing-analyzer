/**
 * Phishing Analyzer Background Service Worker.
 * Communicates with the FastAPI backend, batches URL analysis, and caches results.
 */

const API_BASE = "http://127.0.0.1:8000";
const LOCAL_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

async function getCachedUrlResult(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get([`url_${url}`], (result) => {
      const entry = result[`url_${url}`];
      if (entry && (Date.now() - entry.timestamp < LOCAL_CACHE_TTL_MS)) {
        resolve(entry.data);
      } else {
        resolve(null);
      }
    });
  });
}

async function setCachedUrlResult(url, data) {
  return new Promise((resolve) => {
    const key = `url_${url}`;
    chrome.storage.local.set({
      [key]: {
        data: data,
        timestamp: Date.now()
      }
    }, resolve);
  });
}

async function analyzeSingleUrl(url) {
  const cached = await getCachedUrlResult(url);
  if (cached) {
    return { ...cached, from_cache: true };
  }

  const response = await fetchWithTimeout(`${API_BASE}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  if (!response.ok) {
    throw new Error(`Backend returned status ${response.status}`);
  }

  const data = await response.json();
  await setCachedUrlResult(url, data);
  return data;
}

async function batchAnalyzeUrls(urls) {
  const results = [];
  const uncachedUrls = [];

  for (const u of urls) {
    const cached = await getCachedUrlResult(u);
    if (cached) {
      results.push({ ...cached, from_cache: true });
    } else {
      uncachedUrls.push(u);
    }
  }

  if (uncachedUrls.length > 0) {
    const response = await fetchWithTimeout(`${API_BASE}/analyze/url/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: uncachedUrls })
    });

    if (response.ok) {
      const batchData = await response.json();
      for (const item of batchData.results) {
        results.push(item);
        await setCachedUrlResult(item.url, item);
      }
    }
  }

  return results;
}

async function analyzeEmailHeaders(rawContent) {
  const response = await fetchWithTimeout(`${API_BASE}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_content: rawContent })
  });

  if (!response.ok) {
    throw new Error(`Backend returned status ${response.status}`);
  }

  return await response.json();
}

async function getRecentScans() {
  const response = await fetchWithTimeout(`${API_BASE}/recent`, {
    method: "GET"
  });
  if (!response.ok) {
    throw new Error(`Backend returned status ${response.status}`);
  }
  return await response.json();
}

// Message dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.action === "ANALYZE_URL") {
        const result = await analyzeSingleUrl(message.url);
        sendResponse({ success: true, data: result });
      } else if (message.action === "ANALYZE_BATCH") {
        const results = await batchAnalyzeUrls(message.urls || []);
        sendResponse({ success: true, data: results });
      } else if (message.action === "ANALYZE_EMAIL") {
        const result = await analyzeEmailHeaders(message.raw_content);
        sendResponse({ success: true, data: result });
      } else if (message.action === "GET_RECENT_SCANS") {
        const scans = await getRecentScans();
        sendResponse({ success: true, data: scans });
      } else {
        sendResponse({ success: false, error: "Unknown action" });
      }
    } catch (err) {
      sendResponse({
        success: false,
        error: err.message || "Failed to communicate with analyzer backend"
      });
    }
  })();

  return true; // Keep message channel open for async response
});
