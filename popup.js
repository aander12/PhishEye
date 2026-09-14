const hostnameEl = document.getElementById("hostname");
const verdictEl = document.getElementById("verdict");
const findingsListEl = document.getElementById("findingsList");

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.id) {
        verdictEl.textContent = "No active tab.";
        return;
    }

    chrome.tabs.sendMessage(tab.id, { type: "PHISHEYE_GET_FINDINGS" }, (response) => {
        // chrome.runtime.lastError is set when content.js never ran on this tab
        // (e.g. a chrome:// page, or the tab was open before the extension loaded).
        if (chrome.runtime.lastError || !response) {
            hostnameEl.textContent = tab.url || "";
            verdictEl.textContent = "PhishEye did not run on this page.";
            verdictEl.className = "verdict neutral";
            return;
        }

        hostnameEl.textContent = response.hostname;

        if (response.findings.length === 0) {
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
    });
});
