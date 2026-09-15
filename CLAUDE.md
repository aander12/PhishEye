# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

PhishEye is a Manifest V3 Chrome extension that heuristically detects phishing pages. It's a learning project — no build tooling, no package manager, no test framework. Plain JS/HTML/CSS files loaded directly by Chrome.

## Commands

There is no build/lint/test pipeline. Validation is manual:

```bash
# Syntax-check a JS file (no execution, just parses)
node --check content.js
node --check popup.js
node --check brands.js

# Validate manifest.json (piping it through PowerShell stdin adds a BOM that
# breaks JSON.parse -- always read the file directly instead)
node -e "JSON.parse(require('fs').readFileSync('manifest.json','utf8')); console.log('OK')"

# Compile-check the local test server
python -m py_compile test-pages/server.py
```

**Loading/reloading the extension in Chrome:** `chrome://extensions` → enable Developer mode → "Load unpacked" → select this folder. After editing any file, click the refresh icon on the extension's card (and reload the target page). After changing `manifest.json` permissions specifically, remove and re-add the extension rather than just refreshing.

**Testing against a live page:** open DevTools console (F12) on any page — PhishEye logs `PhishEye: No red flags detected` or a list of findings there, and shows a red banner at the top of the page if anything fired.

**Local test fixtures** (`test-pages/`, not part of the packaged extension):
- `dynamic-injection-test.html` — injects a fake login form and an `@`-trick link 2-3s after load, to exercise the `MutationObserver` re-scan path.
- `evasive_test.html` + `server.py` — a page deliberately built to dodge every current check (see comments in both files for which trick defeats which check). Serve it with `python test-pages/server.py` (listens on `localhost:8001`) and watch the terminal for `[exfil endpoint received]` when the form is submitted, proving the credential exfiltration happened without any static form-action attribute PhishEye could see.
- Content scripts only match `http://*/*` and `https://*/*` in `manifest.json` — a test page opened via `file://` will NOT get `content.js` injected. Serve it over HTTP first, e.g. `python -m http.server 8000 --directory test-pages`.

## Architecture

**File loading order matters.** `manifest.json`'s `content_scripts.js` array is `["brands.js", "content.js"]`. Chrome injects both into the page in that order, sharing one execution context — `brands.js` declares `const knownBrands = [...]` at top level with no export, and `content.js` just references it directly. If a third data/logic file is ever added, its position in that array determines what it can see and be seen by.

**`content.js` has two phases, split because trust-checking is async:**
- `computeStaticFindings()` — hostname/URL-only signals (raw IP, suspicious TLD, hyphen/subdomain depth, Levenshtein typosquat against `knownBrands`, punycode, suspicious subdomain keywords, brand name in path/query). Computed once per page load since the hostname can't change without a navigation.
- `scanDynamicSignals()` — page-content signals (the `@` URL trick, deceptive link text, cross-host form submission, credential over-collection, hidden password fields, context-menu blocking, HTTP+password, urgency language + login form). Re-run on a debounced `MutationObserver` (500ms after DOM activity settles) because single-page-app sites can inject their real form/links well after initial load.
- Both return plain arrays of human-readable strings; `staticFindings` is computed unconditionally, but whether the user is actually *alerted* (console warnings, the `#phisheye-banner` element, starting the `MutationObserver`) is gated behind an async `chrome.storage.local.get(["trustedSites"])` lookup — see below.

**Trust/whitelist system.** `chrome.storage.local` holds a `trustedSites` array of hostnames. The popup's "Trust this site"/"Remove trust" button writes to that array *and* sends a `PHISHEYE_SET_TRUST` message to the content script already running in the active tab, so the change (banner appearing/disappearing) takes effect immediately rather than waiting for a page reload.

**Popup ↔ content-script messaging.** `popup.html`/`popup.js` run in a separate JS context from `content.js` and cannot share variables — all communication goes through `chrome.runtime.onMessage` / `chrome.tabs.sendMessage`. Two message types: `PHISHEYE_GET_FINDINGS` (returns `{ hostname, findings, isTrusted }`) and `PHISHEYE_SET_TRUST` (returns `{ ok: true }`). `chrome.runtime.lastError` in the popup's callback is how you detect "content script never ran here" (e.g. a `chrome://` page, or a tab that predates the extension being loaded).

**`brands.js` is a deliberately curated list**, not a scraped top-domains dataset — grouped by category (banks, payment/fintech, crypto, big tech, shipping, streaming, telecom, airlines, gaming, government/healthcare). A large generic popularity list was considered and rejected: Levenshtein comparison against it would be too slow to run synchronously per page load, and it would raise false-positive risk against obscure-but-legitimate domains without meaningfully improving detection, since phishing targets a small, predictable set of recognizable brands.

**Known, intentional false-positive guards worth preserving when touching detection logic:**
- Typosquat/subdomain-keyword checks skip entirely when the domain is *itself* a `knownBrands` entry (`isAlreadyKnownBrand`) — otherwise two unrelated real brands close in edit distance (e.g. `github`/`gitlab`, distance 2) flag each other.
- Typosquat check requires `registrableDomain.length >= 3` — otherwise a single-label host like `localhost` (empty registrable domain) can false-positive against very short brand entries (e.g. `levenshtein("", "x") === 1`).
- Two-label TLDs (`co.uk`, `com.au`, etc.) are handled via a curated `twoLabelTlds` list so the registrable-domain extraction doesn't grab `"co"` instead of the actual brand segment — deliberately not the full Public Suffix List (thousands of mostly-irrelevant entries).
- Check 7 (brand name in URL path) skips entirely on a curated `multiTenantPlatforms` list (GitHub, npm, Reddit, etc.), since org/user namespaces on those sites routinely and legitimately contain brand names.
- Urgency-language phrases only count as a finding when a password field is also present on the page — the phrase alone is common on legitimate sites (sales, real security notices).
