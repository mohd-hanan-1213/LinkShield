const bypassTabs = new Set();

function isLikelySafe(url) {
    try {
        const u = new URL(url);
        const domain = u.hostname.toLowerCase();

        // trusted domains
        const safeDomains = [
            "google.com",
            "youtube.com",
            "openai.com",
            "wikipedia.org",
            "github.com",
            "stackoverflow.com",
            "microsoft.com",
            "apple.com",
            "amazon.com"
        ];

        // allow trusted domains
        if (safeDomains.some(d => domain === d || domain.endsWith("." + d)))
            return true;

        // allow normal HTTPS (not suspicious)
        if (
            url.startsWith("https://") &&
            url.length < 60 &&
            !url.includes("@") &&                        // avoid @ attack
            !/\d+\.\d+\.\d+\.\d+/.test(url) &&          // avoid IP address
            !domain.match(/paypa1|g00gle|faceb00k/i)    // avoid lookalikes
        ) {
            return true;
        }

    } catch {
        return false;
    }

    return false;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (!changeInfo.url) return;

    const originalUrl = changeInfo.url;

    // allow once after continue
    if (bypassTabs.has(tabId)) {
        bypassTabs.delete(tabId);
        return;
    }

    if (!/^https?:\/\//i.test(originalUrl)) return;
    if (originalUrl.includes("warning.html")) return;

    // SAFE → open directly
    if (isLikelySafe(originalUrl)) return;

    // otherwise show warning
    const redirectUrl = chrome.runtime.getURL(
        "warning.html?url=" + encodeURIComponent(originalUrl)
    );

    chrome.tabs.update(tabId, { url: redirectUrl });
});


chrome.runtime.onMessage.addListener((msg, sender) => {

    if (msg.action === "continue") {
        bypassTabs.add(sender.tab.id);
    }

    if (msg.action === "closeTab") {
        chrome.tabs.remove(sender.tab.id);
    }

});