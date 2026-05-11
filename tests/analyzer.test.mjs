import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const context = {
    URL,
    console,
    globalThis: {}
};

vm.createContext(context);
vm.runInContext(fs.readFileSync(new URL("../analyzer.js", import.meta.url), "utf8"), context);

const { analyzeUrl } = context.globalThis.LinkShieldAnalyzer;

function actionFor(url) {
    const result = analyzeUrl(url);

    if (result.score < 30) return { action: "OPEN", result };
    if (result.score >= 70) return { action: "WARN", result };
    return { action: "SCAN", result };
}

const cases = [
    ["https://google.com", "OPEN"],
    ["https://accounts.google.com", "OPEN"],
    ["https://github.com", "OPEN"],
    ["https://example.com/login/account/verify/update/security/session/user/profile/confirm", "OPEN"],
    ["https://a.b.c.d.e.example.com", "OPEN"],
    ["https://login.secure.account.verify.example.com", "SCAN"],
    ["https://paypal.com.security-check.example.com", "SCAN"],
    ["https://google.com.login.example.com", "SCAN"],
    ["https://example.com/redirect?url=https://google.com", "SCAN"],
    ["https://secure-account-example.com", "SCAN"],
    ["http://192.168.1.1/login", "WARN"],
    ["http://example.com@evil.com", "SCAN"],
    ["https://g00gle.com", "SCAN"]
];

for (const [url, expectedAction] of cases) {
    const { action, result } = actionFor(url);
    assert.equal(
        action,
        expectedAction,
        `${url} expected ${expectedAction}, got ${action} (${result.score}: ${result.reasons.join("; ")})`
    );
}

console.log(`Analyzer tests passed (${cases.length} cases)`);
