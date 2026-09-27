async function auditCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  const urlBox = document.getElementById("url-box");
  const badge = document.getElementById("status-badge");
  const riskPill = document.getElementById("risk-pill");
  const panel = document.getElementById("advisory-panel");
  const summary = document.getElementById("summary-text");
  const doList = document.getElementById("do-items");
  const dontList = document.getElementById("dont-items");

  urlBox.innerText = tab.url;
  badge.className = "badge";
  badge.innerText = "Auditing live vectors...";

  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await res.json();
    const adv = data.advisory;

    riskPill.innerText = `${data.risk_score}% Risk`;
    
    if (data.is_phishing) {
      badge.className = "badge danger";
      badge.innerText = `🚨 ${adv.threat_type}`;
      panel.open = true; // Auto-expand advisory only on high-risk threats
    } else {
      badge.className = "badge safe";
      badge.innerText = `✅ ${adv.threat_type}`;
      panel.open = false; // Keep collapsed on safe sites to prevent user overload
    }

    summary.innerText = adv.summary;
    doList.innerHTML = adv.what_to_do.map(item => `<li>${item}</li>`).join("");
    dontList.innerHTML = adv.what_not_to_do.map(item => `<li>${item}</li>`).join("");
    panel.style.display = "block";

  } catch (err) {
    badge.className = "badge danger";
    badge.innerText = "❌ Backend API Offline";
    summary.innerText = "Run 'python api.py' in your terminal on port 8000.";
    panel.style.display = "block";
  }
}

document.getElementById("rescan-btn").addEventListener("click", auditCurrentTab);
document.addEventListener("DOMContentLoaded", auditCurrentTab);
