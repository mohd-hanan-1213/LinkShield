chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // run only when URL changes
    if (!changeInfo.url) return;

    const originalUrl = changeInfo.url;

    // 1. intercept only http and https
    if (!/^https?:\/\//i.test(originalUrl)) return;

    // 2. avoid infinite loop (don't intercept your own warning page)
    if (originalUrl.includes("warning.html")) return;

    // 3. build redirect URL (pass original URL as parameter)
    const warningPage = chrome.runtime.getURL(
        "warning.html?url=" + encodeURIComponent(originalUrl)
    );

    // 4. redirect user to warning page
    chrome.tabs.update(tabId, { url: warningPage });
});