console.log("PhishEye says the current page is:", location.href);

/* ---- Static findings ----
Signals based on the hostname alone. These can't change without a full
navigation, so they're computed once, up front.
*/
const staticFindings = [];

/* ---- Check 1: Raw IP address hostname ----
Most legitimate websites will not use a plain ipv4 address for their domain,
so this checks the hostname string for four groups of 1-3 digits separated
by dots to determine whether this domain can be trusted.
*/
const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
if (ipPattern.test(location.hostname)) {
    staticFindings.push(`Hostname is a raw IP address: ${location.hostname}`);
}

/* ---- Check 2: Suspicious top-level domain ----
Phishing campaigns disproportionately use cheap, loosely-regulated TLDs
because they are easy to register anonymously and in bulk. A hit here is
not proof of phishing on its own, just one signal among several.
*/
const suspiciousTlds = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "country", "work"];
const hostnameParts = location.hostname.split(".");
const tld = hostnameParts[hostnameParts.length - 1].toLowerCase();
if (suspiciousTlds.includes(tld)) {
    staticFindings.push(`Hostname uses a commonly-abused TLD: .${tld}`);
}

/* ---- Check 3: Excessive hyphens / subdomain depth ----
Attackers often stack subdomains or hyphens to bury a fake brand name in
front of the real (malicious) domain, e.g.
"secure-login-amazon-account.verify-user.xyz". Real sites rarely need
more than one or two hyphens or subdomain levels.
*/
const hyphenCount = (location.hostname.match(/-/g) || []).length;
const subdomainCount = hostnameParts.length - 2;
if (hyphenCount >= 3) {
    staticFindings.push(`Hostname has an unusually high number of hyphens (${hyphenCount}): ${location.hostname}`);
}
if (subdomainCount >= 3) {
    staticFindings.push(`Hostname has an unusually deep subdomain chain (${subdomainCount} levels): ${location.hostname}`);
}

/* ---- Check 4: Look-alike / typosquatted brand domains ----
Compares the registrable domain (e.g. "amaz0n" from "amaz0n.com") against a
short list of commonly-spoofed brands using Levenshtein edit distance. A
small distance (1-2 edits) to a well-known brand, on a domain that is NOT
that brand's real domain, is a classic typosquat signal.
*/
function levenshtein(a, b) {
    const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
    for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    return matrix[a.length][b.length];
}

/* Some countries use two-label TLDs (e.g. "co.uk", "com.au") where the
actual brand-owned segment is the THIRD-from-last label, not the
second-from-last. Grabbing the second-from-last unconditionally would
treat "co" in "amazon.co.uk" as the brand name instead of "amazon". This
is a small, curated list of common two-label suffixes -- not the full
Public Suffix List (which has thousands of entries, mostly for obscure
cases irrelevant here).
*/
const twoLabelTlds = [
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "co.jp", "co.kr", "co.in", "co.nz", "co.za", "co.il",
    "com.au", "net.au", "org.au",
    "com.br", "com.mx", "com.tr", "com.sg", "com.hk",
];
const lastTwoLabels = hostnameParts.slice(-2).join(".").toLowerCase();
const isTwoLabelTld = twoLabelTlds.includes(lastTwoLabels);

// knownBrands is declared in brands.js, loaded before this file (see manifest.json).
const registrableDomain = isTwoLabelTld
    ? (hostnameParts.length >= 3 ? hostnameParts[hostnameParts.length - 3].toLowerCase() : "")
    : (hostnameParts.length >= 2 ? hostnameParts[hostnameParts.length - 2].toLowerCase() : "");
// Domains shorter than this can't meaningfully be "close" to a brand name --
// e.g. a single-label host like "localhost" has no registrable domain at
// all (registrableDomain === ""), and levenshtein("", "x") is only 1,
// which would otherwise false-positive as a typosquat of "x" (Twitter/X).
const MIN_COMPARABLE_DOMAIN_LENGTH = 3;
if (registrableDomain.length >= MIN_COMPARABLE_DOMAIN_LENGTH) {
    for (const brand of knownBrands) {
        if (registrableDomain === brand) continue;
        const distance = levenshtein(registrableDomain, brand);
        if (distance > 0 && distance <= 2) {
            staticFindings.push(`Domain "${registrableDomain}" closely resembles known brand "${brand}" (edit distance ${distance})`);
            break;
        }
    }
}

/* ---- Check 5: Punycode / internationalized domain ----
Browsers encode non-ASCII characters in a hostname (e.g. Cyrillic "а"
instead of Latin "a") into an ASCII-safe form called punycode, which
always shows up as a label starting with "xn--". Attackers abuse this to
register domains that LOOK identical to a trusted brand in the address
bar but are technically a completely different domain -- a "homograph"
attack. Plain ASCII comparisons (like the Levenshtein check above) can't
see this at all, since punycode text doesn't resemble the brand name it's
impersonating. Flagging any punycode label is a blunt but effective
signal, since legitimate sites aimed at English-speaking users rarely
need one.
*/
if (hostnameParts.some((label) => label.toLowerCase().startsWith("xn--"))) {
    staticFindings.push(`Hostname uses punycode (encoded non-ASCII characters), which is sometimes used to visually imitate a trusted domain: ${location.hostname}`);
}

/* ---- Check 6: Suspicious subdomain keywords ----
Phishing pages often stack credential-related words into a SUBDOMAIN to
make the address look official at a glance, e.g. "login.secure-paypal.ru"
or "paypal.account-verify.info" -- the brand name and trust words sit in
front of the real (malicious) domain. This only fires when the domain
ISN'T actually the real brand's, so it doesn't flag legitimate subdomains
like login.paypal.com on PayPal's own site.
*/
const suspiciousSubdomainKeywords = ["login", "secure", "verify", "verification", "account", "update", "confirm", "signin", "authenticate", "billing", "support"];
const domainLabelCount = isTwoLabelTld ? 3 : 2;
const subdomainLabels = hostnameParts.length > domainLabelCount ? hostnameParts.slice(0, hostnameParts.length - domainLabelCount) : [];
if (!knownBrands.includes(registrableDomain)) {
    const matchedSubdomainKeyword = subdomainLabels
        .map((label) => label.toLowerCase())
        .find((label) => suspiciousSubdomainKeywords.some((kw) => label.includes(kw)));
    if (matchedSubdomainKeyword) {
        staticFindings.push(`Hostname uses a credential-related subdomain ("${matchedSubdomainKeyword}") on a domain that isn't a known brand: ${location.hostname}`);
    }
}

/* ---- Check 7: Brand name referenced in the URL path/query ----
Attackers can't always get a domain that resembles the brand, so they
sometimes reference it directly in the path instead, e.g.
"totally-random-site.ru/amazon/account/verify". This only checks brands
that AREN'T the actual domain, and skips very short brand names (like
"x" or "ea") since those would match almost any URL by coincidence.
*/
const pathAndQuery = (location.pathname + location.search).toLowerCase();
for (const brand of knownBrands) {
    if (registrableDomain === brand || brand.length < 4) continue;
    if (pathAndQuery.includes(brand)) {
        staticFindings.push(`URL path/query references brand "${brand}" even though the domain (${location.hostname}) is not ${brand}'s`);
        break;
    }
}

/* ---- Dynamic findings ----
Signals based on page CONTENT (links, forms) rather than the hostname.
Unlike the checks above, these can change after the initial page load --
single-page-app sites routinely inject their real login form or links
via JavaScript well after the page first appears. Wrapping these in a
function lets them be re-run whenever the page's DOM changes (see the
MutationObserver setup below), instead of only ever seeing whatever was
present at the exact moment this script first ran.
*/
function scanDynamicSignals() {
    const dynamic = [];

    /* "@" trick in page links.
    In a URL, everything before an "@" is treated as userinfo (credentials),
    and the actual host is whatever comes AFTER the "@". Attackers exploit
    this by writing links like https://accounts.google.com@evil-site.com/
    so the visible text looks like the real brand but the browser actually
    navigates to evil-site.com.
    */
    const suspiciousLinks = [];
    document.querySelectorAll("a[href]").forEach((link) => {
        const href = link.getAttribute("href");
        if (href && /^https?:\/\//i.test(href)) {
            const afterProtocol = href.replace(/^https?:\/\//i, "");
            if (afterProtocol.includes("@")) {
                suspiciousLinks.push(href);
            }
        }
    });
    if (suspiciousLinks.length > 0) {
        dynamic.push(`${suspiciousLinks.length} link(s) on this page use the "@" trick to disguise their real destination`);
    }

    /* Login form submits to a different host.
    A form containing a password field is almost certainly a login/credential
    form. If its "action" points to a DIFFERENT hostname than the page
    you're currently on, that's a strong sign this page collects
    credentials and sends them somewhere else -- regardless of how normal
    the domain name itself looks.
    */
    document.querySelectorAll("form").forEach((form) => {
        const hasPasswordField = form.querySelector("input[type='password']") !== null;
        if (!hasPasswordField) return;

        const action = form.getAttribute("action");
        if (!action) return; // no action means the form submits back to this same page -- not suspicious

        let actionUrl;
        try {
            actionUrl = new URL(action, location.href);
        } catch {
            return; // malformed action attribute -- nothing meaningful to compare
        }

        if (actionUrl.hostname && actionUrl.hostname !== location.hostname) {
            dynamic.push(`Login form submits to a different host (${actionUrl.hostname}) than the current page (${location.hostname})`);
        }
    });

    /* Credentials collected over an unencrypted connection.
    If this page isn't HTTPS at all, any password typed into it can be read
    in transit by anyone on the network path -- a real, independent
    security problem regardless of whether the site is phishing or just
    poorly built.
    */
    if (location.protocol === "http:" && document.querySelector("input[type='password']")) {
        dynamic.push("Page is served over unencrypted HTTP but contains a password field -- credentials could be intercepted in transit");
    }

    /* Urgency language paired with a login form.
    Phishing relies on panic to short-circuit careful thinking. Urgency
    phrases alone are common on legitimate sites too (an expiring sale, a
    real security notice), so this only flags them when the page ALSO has
    a password field -- "something is wrong, log in now" is the actual
    social-engineering pattern being targeted, not the phrase in isolation.
    */
    if (document.querySelector("input[type='password']")) {
        const urgencyPhrases = [
            "verify your account", "account will be suspended", "unusual activity",
            "confirm your identity", "account has been locked", "immediate action required",
            "update your payment", "account will be closed", "security alert",
        ];
        const bodyText = document.body ? document.body.innerText.toLowerCase() : "";
        const matchedPhrase = urgencyPhrases.find((phrase) => bodyText.includes(phrase));
        if (matchedPhrase) {
            dynamic.push(`Page combines a login form with urgent/pressuring language ("${matchedPhrase}"), a common social-engineering pattern`);
        }
    }

    return dynamic;
}

/* ---- Report findings ----
Log everything to the console for debugging, and if anything was found,
inject a small visible banner at the top of the page so the check is not
silent to a real user. renderBanner() removes and rebuilds the banner
each time it's called, so it stays in sync as findings change.
*/
let findings = staticFindings.concat(scanDynamicSignals());

function renderBanner() {
    const existing = document.getElementById("phisheye-banner");
    if (existing) existing.remove();
    if (findings.length === 0) return;

    const banner = document.createElement("div");
    banner.id = "phisheye-banner";
    banner.textContent = `PhishEye: ${findings.length} potential red flag(s) detected on this page. Check the console for details.`;
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.right = "0";
    banner.style.zIndex = "2147483647";
    banner.style.background = "#b91c1c";
    banner.style.color = "#ffffff";
    banner.style.padding = "10px";
    banner.style.fontFamily = "sans-serif";
    banner.style.fontSize = "14px";
    banner.style.textAlign = "center";
    document.documentElement.appendChild(banner);
}

if (findings.length === 0) {
    console.log("PhishEye: No red flags detected. Hostname:", location.hostname);
} else {
    console.warn(`PhishEye: ${findings.length} potential red flag(s) detected:`);
    findings.forEach((f) => console.warn("  -", f));
}
renderBanner();

/* ---- Re-scan on DOM changes ----
MutationObserver fires on essentially every DOM change, which for a busy
page can mean dozens of callbacks per second -- re-running querySelectorAll
scans on every single one would be wasteful. debounceTimer coalesces bursts
of mutations into a single re-scan that runs 500ms after things settle
down. Re-rendering the banner itself triggers a mutation (it's a DOM
change), but since that doesn't alter what scanDynamicSignals() finds, the
finding count stays the same and the "if changed" check below stops it
from looping.
*/
let debounceTimer = null;
const observer = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        const combined = staticFindings.concat(scanDynamicSignals());
        if (combined.length !== findings.length) {
            findings = combined;
            console.warn(`PhishEye: findings changed, now ${findings.length} potential red flag(s):`);
            findings.forEach((f) => console.warn("  -", f));
            renderBanner();
        } else {
            findings = combined;
        }
    }, 500);
});
observer.observe(document.documentElement, { childList: true, subtree: true });

/* ---- Respond to the popup ----
The popup (popup.js) can't see this script's variables directly -- it runs
in a separate context. When it wants to know what PhishEye found on the
current page, it sends a message here, and this listener answers with the
hostname and findings computed above.
*/
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === "PHISHEYE_GET_FINDINGS") {
        sendResponse({ hostname: location.hostname, findings });
    }
});
