(() => {
function normalizeDomain(domain) {
    const replacements = {
        "0": "o",
        "1": "l",
        "2": "z",
        "3": "e",
        "5": "s",
        "6": "g",
        "7": "t",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i"
    };

    return Array.from(domain, (char) => replacements[char] || char).join("");
}

function isTrustedDomain(domain) {
    const trustedDomains = [
        "google.com",
        "youtube.com",
        "github.com",
        "wikipedia.org",
        "openai.com",
        "stackoverflow.com",
        "microsoft.com",
        "apple.com",
        "amazon.com"
    ];

    return trustedDomains.some((trustedDomain) => {
        return domain === trustedDomain || domain.endsWith(`.${trustedDomain}`);
    });
}

function analyzeUrl(rawUrl) {
    let url = String(rawUrl || "");
    let score = 0;
    const reasons = [];
    const originalScheme = url.split(":")[0]?.toLowerCase() || "";

    if (originalScheme === "javascript" || originalScheme === "data") {
        return {
            risk: "HIGH",
            score: 100,
            reasons: [`Uses unsafe URL scheme (${originalScheme})`]
        };
    }

    if (!/^(https?:|data:|javascript:)/i.test(url)) {
        url = `http://${url}`;
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return {
            risk: "HIGH",
            score: 100,
            reasons: ["Invalid or malformed URL"]
        };
    }

    const domain = parsed.hostname.toLowerCase();
    const decodedUrl = decodeURIComponent(url);

    if (parsed.protocol === "https:" && isTrustedDomain(domain)) {
        return {
            risk: "SAFE",
            score: 0,
            reasons: ["Trusted domain"]
        };
    }

    let hasIp = false;
    let hasAt = false;
    let hasShortener = false;
    let noHttps = false;
    let suspiciousDomain = false;
    let hasManySubdomains = false;
    let hasLongUrl = false;

    if (url.toLowerCase().includes("@")) {
        hasAt = true;
        reasons.push("Contains '@' symbol");
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
        hasIp = true;
        reasons.push("Uses IP address instead of domain");
    }

    const shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st",
        "soo.gd", "s2r.co", "tiny.cc", "clicky.me", "bl.ink",
        "rb.gy", "clck.ru", "v.gd", "lnkd.in", "db.tt"
    ];

    if (shorteners.some((shortener) => domain.includes(shortener))) {
        hasShortener = true;
        reasons.push("Uses URL shortener");
    }

    if (parsed.protocol === "http:") {
        noHttps = true;
        reasons.push("Does not use HTTPS");
    }

    const dotCount = url.split(".").length - 1;
    if (dotCount > 4) {
        hasManySubdomains = true;
        score += 15;
        reasons.push("Too many subdomains");
    }

    if (url.length > 75) {
        hasLongUrl = true;
        score += 15;
        reasons.push("URL is too long");
    }

    const brands = ["paypal", "google", "facebook", "amazon", "instagram", "bank"];
    const keywords = ["login", "secure", "verify", "update", "account"];
    const normalized = normalizeDomain(domain);

    for (const brand of brands) {
        if (normalized.includes(brand) && !domain.includes(brand)) {
            suspiciousDomain = true;
            reasons.push("Lookalike domain (character substitution)");
            break;
        }
    }

    const keywordMatches = keywords.filter((keyword) => domain.includes(keyword));
    if (keywordMatches.length > 0) {
        score += keywordMatches.length >= 2 ? 30 : 15;
        reasons.push("Security-sensitive keyword in domain");
    }

    if (
        brands.some((brand) => domain.includes(brand)) &&
        keywordMatches.length > 0
    ) {
        suspiciousDomain = true;
        reasons.push("Brand name with suspicious keywords");
    }

    const parts = domain.split(".");
    if (parts.length >= 2) {
        const mainDomain = parts.slice(-2).join(".");
        if (brands.some((brand) => domain.includes(brand) && !mainDomain.includes(brand))) {
            suspiciousDomain = true;
            reasons.push("Brand in subdomain (possible spoofing)");
        }
    }

    if (suspiciousDomain) {
        score += 30;

        if (!hasIp && !hasAt && !hasShortener) {
            score += 20;
            reasons.push("Clean-looking impersonation domain");
        }
    }

    const redirectParams = ["url=", "redirect=", "next=", "target=", "dest="];
    if (
        redirectParams.some((param) => decodedUrl.toLowerCase().includes(param)) &&
        /(http:\/\/|https:\/\/)/i.test(decodedUrl)
    ) {
        score += 30;
        reasons.push("Possible open redirect (embedded URL)");
    }

    if (keywordMatches.length > 0 && hasLongUrl) {
        score += 15;
        reasons.push("Long URL combined with security-sensitive keyword");
    }

    if (keywordMatches.length > 0 && hasManySubdomains) {
        score += 15;
        reasons.push("Many subdomains combined with security-sensitive keyword");
    }

    if (keywordMatches.length > 0 && noHttps) {
        score += 15;
        reasons.push("HTTP link combined with security-sensitive keyword");
    }

    if (
        (hasIp && hasAt) ||
        (hasAt && hasShortener) ||
        (hasIp && noHttps) ||
        (noHttps && dotCount > 4) ||
        (suspiciousDomain && (hasAt || hasIp)) ||
        (suspiciousDomain && noHttps)
    ) {
        return {
            risk: "HIGH",
            score: 100,
            reasons: [...reasons, "Critical phishing pattern detected"]
        };
    }

    if (hasIp) score += 30;
    if (hasAt) score += 25;
    if (hasShortener) score += 20;
    if (noHttps) score += 15;

    let risk = "SAFE";
    if (score >= 70) {
        risk = "HIGH";
    } else if (score >= 30) {
        risk = "SUSPICIOUS";
    }

    return { risk, score, reasons };
}

globalThis.LinkShieldAnalyzer = {
    analyzeUrl,
    isTrustedDomain,
    normalizeDomain
};
})();
