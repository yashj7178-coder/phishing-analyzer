/**
 * Phishing Analyzer Popup Script.
 * Coordinates UI, active tab inspection, background communication, and link highlighting.
 */

let currentPageLinks = [];

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  checkBackendHealth();
  initActiveTabScan();
  setupCustomUrlScan();
  setupEmailScan();
  setupHistory();
});

function setupTabs() {
  const tabButtons = document.querySelectorAll(".nav-btn");
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabButtons.forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }

      if (targetId === "tab-history") {
        loadHistory();
      }
    });
  });
}

async function checkBackendHealth() {
  const statusDot = document.querySelector(".status-dot");
  const statusText = document.getElementById("status-text");

  try {
    const res = await fetch("http://127.0.0.1:8000/health");
    if (res.ok) {
      const data = await res.json();
      statusDot.className = "status-dot online";
      statusText.textContent = data.virustotal_configured ? "Online (VT)" : "Online";
    } else {
      throw new Error();
    }
  } catch (e) {
    statusDot.className = "status-dot offline";
    statusText.textContent = "Offline";
  }
}

// TAB 1: Active Tab Scanning
async function initActiveTabScan() {
  const activeUrlDisplay = document.getElementById("active-url-display");
  const resultContainer = document.getElementById("active-page-result");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      activeUrlDisplay.textContent = "Unable to read active tab URL";
      resultContainer.innerHTML = '<div class="empty-state">No inspectable URL found on active tab.</div>';
      return;
    }

    const currentUrl = tab.url;
    activeUrlDisplay.textContent = currentUrl;

    if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("edge://") || currentUrl.startsWith("about:")) {
      resultContainer.innerHTML = '<div class="empty-state">Browser internal pages cannot be analyzed.</div>';
      return;
    }

    // Request active page links from content script
    try {
      chrome.tabs.sendMessage(tab.id, { action: "GET_PAGE_DATA" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          // Content script not loaded yet or restricted page
          return;
        }
        currentPageLinks = response.links || [];
        document.getElementById("links-count-label").textContent = `Page Links: ${currentPageLinks.length} found`;
      });
    } catch (e) {}

    // Send URL to background for analysis
    chrome.runtime.sendMessage({ action: "ANALYZE_URL", url: currentUrl }, (response) => {
      if (response && response.success) {
        renderUrlResult(resultContainer, response.data);
      } else {
        resultContainer.innerHTML = `<div class="empty-state" style="color:var(--risk-high);">${response ? response.error : 'Analysis failed. Backend might be offline.'}</div>`;
      }
    });

  } catch (err) {
    resultContainer.innerHTML = `<div class="empty-state" style="color:var(--risk-high);">Error: ${err.message}</div>`;
  }

  // Setup Scan Links button
  document.getElementById("btn-scan-links").addEventListener("click", scanPageLinks);
}

async function scanPageLinks() {
  const linksContainer = document.getElementById("links-list");
  if (!currentPageLinks || currentPageLinks.length === 0) {
    linksContainer.innerHTML = '<div class="empty-state">No external links found on this page.</div>';
    return;
  }

  linksContainer.innerHTML = '<div class="spinner"></div><div class="empty-state">Batch analyzing visible links...</div>';

  chrome.runtime.sendMessage({ action: "ANALYZE_BATCH", urls: currentPageLinks.slice(0, 30) }, (response) => {
    if (!response || !response.success || !response.data) {
      linksContainer.innerHTML = '<div class="empty-state" style="color:var(--risk-high);">Batch link scan failed.</div>';
      return;
    }

    const results = response.data;
    const flaggedUrls = [];

    linksContainer.innerHTML = "";
    results.forEach((item) => {
      const isHigh = item.risk_level === "High Risk";
      const isSuspicious = item.risk_level === "Suspicious";
      if (isHigh || isSuspicious) {
        flaggedUrls.push(item.url);
      }

      const row = document.createElement("div");
      row.className = "link-row";

      const badgeClass = isHigh ? "high" : (isSuspicious ? "suspicious" : "low");
      row.innerHTML = `
        <span class="link-row-url" title="${item.url}">${item.components.domain || item.url}</span>
        <span class="badge ${badgeClass}">${item.risk_score}</span>
      `;
      linksContainer.appendChild(row);
    });

    // If flagged URLs exist, highlight them in the active tab!
    if (flaggedUrls.length > 0) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: "HIGHLIGHT_LINKS",
            flaggedUrls: flaggedUrls
          });
        }
      });
    }
  });
}

// Render URL result card
function renderUrlResult(container, data) {
  const levelClass = data.risk_level === "Low" ? "low" : (data.risk_level === "Suspicious" ? "suspicious" : "high");
  
  const reasonsHtml = data.reasons && data.reasons.length > 0
    ? data.reasons.map((r) => `<li>${r}</li>`).join("")
    : "<li>Standard baseline benign indicators.</li>";

  const domainAge = data.whois.age_days !== null ? `${data.whois.age_days}d` : (data.whois.error ? 'Unknown' : 'N/A');
  const tlsText = data.tls.valid ? "Valid" : (data.tls.error ? "Invalid" : "None");

  container.innerHTML = `
    <div class="risk-banner ${levelClass}">
      <div>
        <span class="badge ${levelClass}">${data.risk_level}</span>
        <div style="font-size:11px; margin-top:4px; font-weight:600; color:var(--text-main); word-break:break-all;">
          ${data.components.registered_domain || data.components.domain}
        </div>
      </div>
      <div class="score-num">
        ${data.risk_score}<span>/100</span>
      </div>
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Domain Age</div>
        <div class="meta-val">${domainAge}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">TLS/SSL</div>
        <div class="meta-val">${tlsText}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Punycode / IDN</div>
        <div class="meta-val">${data.homograph.is_punycode ? 'DETECTED' : 'None'}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Typo Target</div>
        <div class="meta-val">${data.homograph.target_brand || 'None'}</div>
      </div>
    </div>

    <div class="reasons-box">
      <div class="meta-label" style="margin-bottom:4px;">Detection Signals</div>
      <ul>${reasonsHtml}</ul>
    </div>
  `;
}

// TAB 2: Custom URL Scan
function setupCustomUrlScan() {
  const input = document.getElementById("custom-url-input");
  const btn = document.getElementById("btn-custom-url-scan");
  const resultContainer = document.getElementById("custom-url-result");

  const runScan = () => {
    const url = input.value.trim();
    if (!url) return;

    resultContainer.innerHTML = '<div class="spinner"></div><div class="empty-state">Inspecting heuristics, WHOIS, and TLS...</div>';

    chrome.runtime.sendMessage({ action: "ANALYZE_URL", url: url }, (response) => {
      if (response && response.success) {
        renderUrlResult(resultContainer, response.data);
      } else {
        resultContainer.innerHTML = `<div class="empty-state" style="color:var(--risk-high);">${response ? response.error : 'Analysis failed.'}</div>`;
      }
    });
  };

  btn.addEventListener("click", runScan);
  input.addEventListener("keypress", (e) => {
    if (e.key === "Enter") runScan();
  });
}

// TAB 3: Email Header Scan
function setupEmailScan() {
  const input = document.getElementById("email-header-input");
  const btnScan = document.getElementById("btn-analyze-email");
  const btnSample = document.getElementById("btn-sample-email");
  const resultContainer = document.getElementById("email-analysis-result");

  btnSample.addEventListener("click", () => {
    input.value = `From: "PayPal Account Security" <service@notice-paypal-verify.xyz>
Reply-To: phish-collector@scam-mail.top
Return-Path: <bounce@unrelated-server.net>
Subject: Action Required: Your account has been restricted!
Date: Fri, 20 Nov 2026 10:14:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of service@notice-paypal-verify.xyz does not designate 198.51.100.1 as permitted sender);
       dkim=fail header.i=@notice-paypal-verify.xyz;
       dmarc=fail (p=REJECT) header.from=notice-paypal-verify.xyz

Dear Customer, please verify credentials at http://paypal-account-update.xyz/login`;
  });

  btnScan.addEventListener("click", () => {
    const raw = input.value.trim();
    if (!raw) return;

    resultContainer.innerHTML = '<div class="spinner"></div><div class="empty-state">Verifying SPF/DKIM/DMARC and header alignment...</div>';

    chrome.runtime.sendMessage({ action: "ANALYZE_EMAIL", raw_content: raw }, (response) => {
      if (response && response.success) {
        renderEmailResult(resultContainer, response.data);
      } else {
        resultContainer.innerHTML = `<div class="empty-state" style="color:var(--risk-high);">${response ? response.error : 'Email analysis failed.'}</div>`;
      }
    });
  });
}

function renderEmailResult(container, data) {
  const levelClass = data.risk_level === "Low" ? "low" : (data.risk_level === "Suspicious" ? "suspicious" : "high");
  const reasonsHtml = data.reasons && data.reasons.length > 0
    ? data.reasons.map((r) => `<li>${r}</li>`).join("")
    : "<li>Email authentication headers verify correctly.</li>";

  container.innerHTML = `
    <div class="risk-banner ${levelClass}">
      <div>
        <span class="badge ${levelClass}">${data.risk_level}</span>
        <div style="font-size:11px; margin-top:4px; font-weight:600; color:var(--text-main); max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${data.subject || 'No Subject'}
        </div>
      </div>
      <div class="score-num">
        ${data.risk_score}<span>/100</span>
      </div>
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">SPF</div>
        <div class="meta-val">${(data.spf.status || 'None').toUpperCase()}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">DKIM</div>
        <div class="meta-val">${(data.dkim.status || 'None').toUpperCase()}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">DMARC</div>
        <div class="meta-val">${(data.dmarc.status || 'None').toUpperCase()}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Reply-To Match</div>
        <div class="meta-val">${data.mismatch.reply_to_mismatch ? 'MISMATCH' : 'OK'}</div>
      </div>
    </div>

    <div class="reasons-box">
      <div class="meta-label" style="margin-bottom:4px;">Authentication & Mismatch Flags</div>
      <ul>${reasonsHtml}</ul>
    </div>
  `;
}

// TAB 4: History
function setupHistory() {
  document.getElementById("btn-refresh-history").addEventListener("click", loadHistory);
}

function loadHistory() {
  const container = document.getElementById("history-list");
  container.innerHTML = '<div class="spinner"></div>';

  chrome.runtime.sendMessage({ action: "GET_RECENT_SCANS" }, (response) => {
    if (!response || !response.success || !response.data || response.data.length === 0) {
      container.innerHTML = '<div class="empty-state">No recent scans recorded.</div>';
      return;
    }

    container.innerHTML = "";
    response.data.forEach((item) => {
      const badgeClass = item.risk_level === "Low" ? "low" : (item.risk_level === "Suspicious" ? "suspicious" : "high");
      const row = document.createElement("div");
      row.className = "history-item";
      row.innerHTML = `
        <div>
          <span style="font-size:10px; font-family:var(--font-mono); color:var(--text-muted); text-transform:uppercase;">[${item.type}]</span>
          <div class="history-target" title="${item.target}">${item.target}</div>
        </div>
        <span class="badge ${badgeClass}">${item.risk_score}</span>
      `;
      container.appendChild(row);
    });
  });
}
