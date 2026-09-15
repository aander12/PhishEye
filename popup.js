const hostnameEl = document.getElementById("hostname");
const verdictEl = document.getElementById("verdict");
const findingsListEl = document.getElementById("findingsList");
const trustBtn = document.getElementById("trustBtn");

function setTrustButton(tabId, hostname, isTrusted) {
    trustBtn.hidden = false;
    trustBtn.textContent = isTrusted ? "Remove trust" : "Trust this site";
    trustBtn.onclick = () => toggleTrust(tabId, hostname, !isTrusted);
}

function toggleTrust(tabId, hostname, trust) {
    chrome.storage.local.get(["trustedSites"], (result) => {
        const trustedSites = result.trustedSites || [];
        const updated = trust
            ? Array.from(new Set([...trustedSites, hostname]))
            : trustedSites.filter((site) => site !== hostname);

        chrome.storage.local.set({ trustedSites: updated }, () => {
            // Tell the already-running content script to apply the change
            // immediately, instead of waiting for the next page reload.
            chrome.tabs.sendMessage(tabId, { type: "PHISHEYE_SET_TRUST", trusted: trust }, () => {
                renderStatus(tabId);
            });
        });
    });
}

function renderStatus(tabId) {
    findingsListEl.innerHTML = "";

    chrome.tabs.sendMessage(tabId, { type: "PHISHEYE_GET_FINDINGS" }, (response) => {
        // chrome.runtime.lastError is set when content.js never ran on this tab
        // (e.g. a chrome:// page, or the tab was open before the extension loaded).
        if (chrome.runtime.lastError || !response) {
            verdictEl.textContent = "PhishEye did not run on this page.";
            verdictEl.className = "verdict neutral";
            trustBtn.hidden = true;
            return;
        }

        hostnameEl.textContent = response.hostname;

        if (response.isTrusted) {
            verdictEl.textContent = "Trusted by you -- checks suppressed";
            verdictEl.className = "verdict safe";
        } else if (response.findings.length === 0) {
            verdictEl.textContent = "No red flags detected";
            verdictEl.className = "verdict safe";
        } else {
            verdictEl.textContent = `${response.findings.length} potential red flag(s)`;
            verdictEl.className = "verdict warning";
            response.findings.forEach((finding) => {
                const item = document.createElement("li");
                item.textContent = finding;
                findingsListEl.appendChild(item);
            });
        }

        setTrustButton(tabId, response.hostname, response.isTrusted);
    });
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.id) {
        verdictEl.textContent = "No active tab.";
        return;
    }
    hostnameEl.textContent = tab.url || "";
    renderStatus(tab.id);
});
