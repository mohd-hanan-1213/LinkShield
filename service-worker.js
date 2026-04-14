importScripts("analyzer.js");

const { analyzeUrl } = globalThis.LinkShieldAnalyzer;

const bypassTabs = new Set();
const bypassUrls = new Map();
const pendingTabs = new Map();

const LOW_RISK_THRESHOLD = 30;
const HIGH_RISK_THRESHOLD = 70;
const SCAN_RESULT_PREFIX = "scanResult:";
const BYPASS_TTL_MS = 60000;
const ALLOW_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function getBypassKeys(url) {
    try {
        const parsed = new URL(url);
        return [parsed.href, parsed.origin];
    } catch {
        return [url];
    }
}

function rememberBypassUrl(url) {
    const createdAt = Date.now();

    getBypassKeys(url).forEach((key) => {
        bypassUrls.set(key, { createdAt });
    });
}

function hasActiveBypassUrl(url) {
    const now = Date.now();
    const keys = getBypassKeys(url);

    for (const key of keys) {
        const bypass = bypassUrls.get(key);

        if (bypass && now - bypass.createdAt < BYPASS_TTL_MS) {
            return true;
        }
    }

    keys.forEach((key) => bypassUrls.delete(key));
    return false;
}

async function saveScanResult(url, result) {
    await chrome.storage.local.set({
        [`${SCAN_RESULT_PREFIX}${url}`]: {
            ...result,
            savedAt: Date.now()
        }
    });
}

function getScanResultKeys(url) {
    try {
        const parsed = new URL(url);
        return [
            `${SCAN_RESULT_PREFIX}${url}`,
            `${SCAN_RESULT_PREFIX}${parsed.href}`
        ];
    } catch {
        return [`${SCAN_RESULT_PREFIX}${url}`];
    }
}

async function hasRecentAllowedResult(url) {
    const stored = await chrome.storage.local.get(getScanResultKeys(url));
    const now = Date.now();

    return Object.values(stored).some((result) => {
        return result?.decision === "allow" &&
            typeof result.savedAt === "number" &&
            now - result.savedAt < ALLOW_CACHE_TTL_MS;
    });
}

async function showWarningPage(tabId, originalUrl, result) {
    await saveScanResult(originalUrl, result);

    const redirectUrl = chrome.runtime.getURL(
        "warning.html?url=" + encodeURIComponent(originalUrl)
    );

    await chrome.tabs.update(tabId, { url: redirectUrl });
}

async function showScanPage(tabId, originalUrl, localResult) {
    await saveScanResult(originalUrl, {
        ...localResult,
        decision: "scan",
        decisionSource: "local"
    });

    const redirectUrl = chrome.runtime.getURL(
        "scan.html?url=" + encodeURIComponent(originalUrl)
    );

    await chrome.tabs.update(tabId, { url: redirectUrl });
}

async function handleNavigation(tabId, originalUrl) {
    if (await hasRecentAllowedResult(originalUrl)) {
        return;
    }

    const localResult = analyzeUrl(originalUrl);

    if (localResult.score < LOW_RISK_THRESHOLD) {
        return;
    }

    if (localResult.score >= HIGH_RISK_THRESHOLD) {
        await showWarningPage(tabId, originalUrl, {
            ...localResult,
            decision: "warn",
            decisionSource: "local"
        });
        return;
    }

    await showScanPage(tabId, originalUrl, localResult);
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;

    const tabId = details.tabId;
    const originalUrl = details.url;
    if (hasActiveBypassUrl(originalUrl)) {
        return;
    }

    if (bypassTabs.has(tabId)) {
        bypassTabs.delete(tabId);
        return;
    }

    if (!/^https?:\/\//i.test(originalUrl)) return;
    if (originalUrl.includes("warning.html")) return;
    if (originalUrl.includes("scan.html")) return;
    if (pendingTabs.get(tabId) === originalUrl) return;

    pendingTabs.set(tabId, originalUrl);

    handleNavigation(tabId, originalUrl).finally(() => {
        if (pendingTabs.get(tabId) === originalUrl) {
            pendingTabs.delete(tabId);
        }
    });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "continue") {
        if (msg.url) {
            rememberBypassUrl(msg.url);
            sendResponse({ ok: true });
            return;
        }

        const tabId = msg.tabId ?? sender.tab?.id;

        if (typeof tabId !== "number") {
            sendResponse({ ok: false, error: "Missing tab id" });
            return;
        }

        bypassTabs.add(tabId);
        sendResponse({ ok: true });
        return;
    }

    if (msg.action === "closeTab") {
        const tabId = msg.tabId ?? sender.tab?.id;

        if (typeof tabId === "number") {
            chrome.tabs.remove(tabId);
        }
    }
});
