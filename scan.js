const { analyzeUrl } = globalThis.LinkShieldAnalyzer;

const SCAN_RESULT_PREFIX = "scanResult:";
const BACKEND_BASE_URL = globalThis.LinkShieldConfig?.backendBaseUrl || "http://localhost:8787";
const SLOW_SCAN_MS = 12000;

async function saveScanResult(url, result) {
    const savedResult = {
        ...result,
        savedAt: Date.now()
    };
    const records = {
        [`${SCAN_RESULT_PREFIX}${url}`]: savedResult
    };

    try {
        records[`${SCAN_RESULT_PREFIX}${new URL(url).href}`] = savedResult;
    } catch {
        // Keep the original key for malformed URLs.
    }

    await chrome.storage.local.set(records);
}

async function fetchBackendVerdict(url, localResult) {
    const response = await fetch(`${BACKEND_BASE_URL}/api/url-check`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url, localResult })
    });

    if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
    }

    return response.json();
}

function getCurrentTabId() {
    return new Promise((resolve) => {
        chrome.tabs.getCurrent((tab) => {
            resolve(tab?.id);
        });
    });
}

async function openOriginalUrl(url) {
    const tabId = await getCurrentTabId();

    chrome.runtime.sendMessage({ action: "continue", url, tabId }, () => {
        window.location.href = url;
    });
}

function openWarningPage(url) {
    window.location.href = chrome.runtime.getURL(
        "warning-screen.html?url=" + encodeURIComponent(url)
    );
}

function showSlowScanActions() {
    document.getElementById("status").innerText =
        "This reputation check is taking longer than expected. You can keep waiting, try again, go back, or continue only if you trust the site.";
    document.getElementById("actions").classList.add("visible");
}

document.addEventListener("DOMContentLoaded", async () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get("url");
    document.getElementById("url").innerText = url;

    const localResult = analyzeUrl(url);
    const localScoreValue = document.getElementById("localScoreValue");
    const localScoreCaption = document.getElementById("localScore");

    if (localScoreValue) {
        localScoreValue.innerText = `${localResult.score}`;
    }

    if (localScoreCaption) {
        localScoreCaption.innerText =
            localResult.score >= 60
                ? "Strong local phishing indicators detected."
                : "Moderate local risk signals triggered a reputation check.";
    }
    const slowScanTimer = setTimeout(showSlowScanActions, SLOW_SCAN_MS);

    document.getElementById("retry").addEventListener("click", () => {
        window.location.reload();
    });

    document.getElementById("back").addEventListener("click", () => {
        window.history.back();
    });

    document.getElementById("continue").addEventListener("click", async () => {
        const confirmed = window.confirm(
            "LinkShield has not finished verifying this URL. Continue only if you trust the site."
        );

        if (!confirmed) return;

        await openOriginalUrl(url);
    });

    try {
        const backendResult = await fetchBackendVerdict(url, localResult);
        clearTimeout(slowScanTimer);
        const scanResult = {
            ...localResult,
            ...backendResult,
            decisionSource: "backend"
        };

        await saveScanResult(url, scanResult);

        if (backendResult.decision === "allow") {
            await openOriginalUrl(url);
            return;
        }

        openWarningPage(url);
    } catch (error) {
        clearTimeout(slowScanTimer);
        await saveScanResult(url, {
            ...localResult,
            reasons: [
                ...localResult.reasons,
                "Unable to verify URL with the reputation service"
            ],
            decision: "warn",
            decisionSource: "fallback",
            backendError: error.message
        });

        openWarningPage(url);
    }
});
