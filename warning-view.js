const { analyzeUrl } = globalThis.LinkShieldAnalyzer;

const SCAN_RESULT_PREFIX = "scanResult:";

function getCurrentTabId() {
    return new Promise((resolve) => {
        chrome.tabs.getCurrent((tab) => {
            resolve(tab?.id);
        });
    });
}

function setExplanation(scanResult) {
    const explain = document.getElementById("explain");

    if (scanResult.decisionSource === "backend" && scanResult.vtStats) {
        const { malicious = 0, suspicious = 0 } = scanResult.vtStats;
        explain.innerText =
            `Server reported ${malicious} malicious and ${suspicious} suspicious engine hits for this URL.`;
        return;
    }

    if (scanResult.decisionSource === "fallback") {
        explain.innerText =
            "This link matched suspicious local patterns, but the reputation service could not be reached. LinkShield blocked it as a safety fallback.";
        return;
    }

    explain.innerText =
        scanResult.risk === "SAFE"
            ? "No suspicious patterns detected."
            : "This link may impersonate a trusted service.";
}

function renderSignalSummary(scanResult) {
    const signalSummary = document.getElementById("signalSummary");
    const verdictSource = document.getElementById("verdictSource");

    if (signalSummary) {
        if (scanResult.decisionSource === "backend" && scanResult.vtStats) {
            signalSummary.innerText =
                `Reputation data and local heuristics both contributed to this warning. ${scanResult.reasons.length} recorded signals are available below.`;
        } else if (scanResult.reasons?.length) {
            signalSummary.innerText =
                `${scanResult.reasons.length} suspicious signal${scanResult.reasons.length === 1 ? "" : "s"} were recorded before the page was blocked.`;
        } else {
            signalSummary.innerText = "LinkShield recorded a warning but did not store any additional signal details.";
        }
    }

    if (verdictSource) {
        const sourceMap = {
            local: "Decision source: local analysis",
            backend: "Decision source: hosted reputation service",
            fallback: "Decision source: safety fallback"
        };

        verdictSource.innerText = sourceMap[scanResult.decisionSource] || "";
    }
}

function renderIssues(scanResult) {
    const issues = document.getElementById("issues");
    issues.innerHTML = "";

    if (!scanResult.reasons || scanResult.reasons.length === 0) {
        const li = document.createElement("li");
        li.innerText = "No specific issues were recorded.";
        issues.appendChild(li);
        return;
    }

    scanResult.reasons.forEach((reason) => {
        const li = document.createElement("li");
        li.innerText = reason;
        issues.appendChild(li);
    });
}

function renderScore(scanResult) {
    const legacyScore = document.getElementById("score");
    const scoreValue = document.getElementById("scoreValue");
    const riskLabel = document.getElementById("riskLabel");

    if (legacyScore) {
        legacyScore.innerText = `Risk Score: ${scanResult.score}% (${scanResult.risk})`;
    }

    if (scoreValue) {
        scoreValue.innerText = `${scanResult.score}`;
    }

    if (riskLabel) {
        riskLabel.innerText = `${scanResult.risk} risk`;
    }

    const fill = document.getElementById("fill");
    fill.style.width = `${scanResult.score}%`;

    if (scanResult.score < 30) fill.style.background = "#22c55e";
    else if (scanResult.score < 60) fill.style.background = "#eab308";
    else if (scanResult.score < 80) fill.style.background = "#f97316";
    else fill.style.background = "#ef4444";
}

document.addEventListener("DOMContentLoaded", async () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get("url");
    document.getElementById("url").innerText = url;

    const storageKey = `${SCAN_RESULT_PREFIX}${url}`;
    const stored = await chrome.storage.local.get(storageKey);
    const scanResult = stored[storageKey] || analyzeUrl(url);

    renderScore(scanResult);
    setExplanation(scanResult);
    renderSignalSummary(scanResult);
    renderIssues(scanResult);

    document.getElementById("toggleBtn").addEventListener("click", () => {
        const details = document.getElementById("details");
        const btn = document.getElementById("toggleBtn");

        if (details.classList.contains("hidden")) {
            details.classList.remove("hidden");
            btn.innerText = "Hide Details";
        } else {
            details.classList.add("hidden");
            btn.innerText = "Show Details";
        }
    });

    document.querySelector(".continue").addEventListener("click", async () => {
        if (scanResult.score >= 70 || scanResult.decision === "warn") {
            const confirmed = window.confirm(
                "LinkShield flagged this URL as risky. Continue only if you trust the site."
            );

            if (!confirmed) return;
        }

        const tabId = await getCurrentTabId();

        chrome.runtime.sendMessage({ action: "continue", url, tabId }, () => {
            window.location.href = url;
        });
    });

    document.querySelector(".back").addEventListener("click", async () => {
        const tabId = await getCurrentTabId();

        chrome.runtime.sendMessage({ action: "closeTab", tabId });
    });
});
