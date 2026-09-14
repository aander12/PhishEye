/* PhishEye brand list.
This is data, not logic — kept in its own file so it can grow or be edited
without touching the detection code in content.js. Chrome loads this file
before content.js (see manifest.json "js" order), and because content
scripts listed together share one execution context, the `knownBrands`
const declared here is directly usable inside content.js.

Curated (not a raw "top domains by traffic" dump) on purpose: phishing
overwhelmingly impersonates a fairly small set of highly recognizable
brands, not random long-tail popular sites. A large generic list would
mostly add false-positive risk and CPU cost without catching more real
phishing. Grouped by category for readability/maintenance.
*/

const knownBrands = [
    // Big tech / accounts
    "google", "microsoft", "apple", "amazon", "facebook", "meta", "instagram",
    "whatsapp", "yahoo", "aol", "outlook", "office365", "icloud", "adobe",
    "dropbox", "linkedin", "twitter", "x", "tiktok", "snapchat", "pinterest",
    "reddit", "discord", "telegram", "signal", "zoom", "skype", "slack",

    // Banks / finance
    "chase", "wellsfargo", "bankofamerica", "citibank", "citi", "usbank",
    "capitalone", "americanexpress", "amex", "discover", "hsbc", "barclays",
    "santander", "tdbank", "pnc", "truist", "ally", "navyfederal", "usaa",
    "fidelity", "vanguard", "schwab", "robinhood", "etrade",

    // Payment / fintech
    "paypal", "venmo", "zelle", "cashapp", "square", "stripe", "wise",
    "westernunion", "moneygram", "klarna", "affirm", "afterpay",

    // Crypto
    "coinbase", "binance", "kraken", "blockchain", "metamask", "crypto",
    "gemini", "kucoin", "bitfinex", "ledger", "trezor",

    // E-commerce / retail
    "ebay", "walmart", "target", "bestbuy", "costco", "etsy", "shopify",
    "aliexpress", "alibaba", "wayfair", "homedepot", "lowes", "ikea",
    "macys", "nordstrom", "chewy", "wish",

    // Shipping / delivery
    "ups", "fedex", "usps", "dhl", "amazonlogistics", "doordash",
    "ubereats", "grubhub", "instacart", "postmates", "uber", "lyft",

    // Streaming / media
    "netflix", "hulu", "disneyplus", "disney", "hbo", "hbomax", "max",
    "spotify", "youtube", "primevideo", "peacocktv", "paramountplus",
    "twitch", "crunchyroll",

    // Telecom / ISP
    "verizon", "att", "tmobile", "sprint", "comcast", "xfinity",
    "spectrum", "cox", "centurylink",

    // Airlines / travel
    "delta", "united", "americanairlines", "southwest", "jetblue",
    "airbnb", "booking", "expedia", "tripadvisor", "marriott", "hilton",

    // Software / cloud / security
    "salesforce", "oracle", "sap", "cisco", "vmware", "intuit",
    "turbotax", "quickbooks", "norton", "mcafee", "avast", "docusign",
    "godaddy", "namecheap", "cloudflare", "github", "gitlab", "aws",
    "azure", "digitalocean",

    // Gaming
    "steam", "playstation", "xbox", "nintendo", "epicgames", "ea",
    "battlenet", "roblox", "minecraft",

    // Government / healthcare (generic, commonly spoofed in scams)
    "irs", "ssa", "medicare", "unitedhealthcare", "anthem", "cigna",
    "aetna", "bluecross",
];
