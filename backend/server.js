const http = require("http");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 8787);
const VT_API_KEY = process.env.VT_API_KEY;
const VT_API_BASE = "https://www.virustotal.com/api/v3";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

if (!VT_API_KEY) {
    throw new Error("Missing VT_API_KEY environment variable");
}

function sendJson(res, statusCode, body) {
    res.writeHead(statusCode, {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Content-Type": "application/json"
    });
    res.end(JSON.stringify(body));
}

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", (chunk) => {
            body += chunk;
        });

        req.on("end", () => {
            try {
                resolve(JSON.parse(body || "{}"));
            } catch (error) {
                reject(error);
            }
        });

        req.on("error", reject);
    });
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeUrl(url) {
    const parsed = new URL(url);
    return parsed.toString();
}

function toBase64Url(value) {
    return Buffer.from(value)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function vtFetch(path, options = {}) {
    const response = await fetch(`${VT_API_BASE}${path}`, {
        ...options,
        headers: {
            "x-apikey": VT_API_KEY,
            ...(options.headers || {})
        }
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`VirusTotal ${response.status}: ${text}`);
    }

    return response.json();
}

async function getUrlReport(url) {
    const urlId = toBase64Url(normalizeUrl(url));
    return vtFetch(`/urls/${urlId}`);
}

async function submitUrl(url) {
    const body = new URLSearchParams({ url });
    const analysis = await vtFetch("/urls", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body
    });

    return analysis.data.id;
}

async function getAnalysis(analysisId) {
    return vtFetch(`/analyses/${analysisId}`);
}

async function ensureUrlAnalysis(url) {
    try {
        return await getUrlReport(url);
    } catch (error) {
        if (!String(error.message).includes("404")) {
            throw error;
        }
    }

    const analysisId = await submitUrl(url);

    for (let attempt = 0; attempt < 15; attempt += 1) {
        const analysis = await getAnalysis(analysisId);
        const attributes = analysis.data?.attributes || {};

        if (attributes.status === "completed") {
            try {
                return await getUrlReport(url);
            } catch {
                return analysis;
            }
        }

        await sleep(2000);
    }

    throw new Error("VirusTotal analysis timed out");
}

function buildDecision(report) {
    const attributes = report.data?.attributes || {};
    const stats = attributes.last_analysis_stats || attributes.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const categories = attributes.categories || {};
    const categoryValues = Object.values(categories);

    if (malicious > 0 || suspicious > 0) {
        return {
            decision: "warn",
            risk: "HIGH",
            score: 85,
            reasons: [
                `This URL had been flagged with ${malicious} malicious and ${suspicious} suspicious detections.`,
                ...categoryValues.slice(0, 3).map((value) => `Category: ${value}`)
            ],
            vtStats: { malicious, suspicious, harmless, undetected }
        };
    }

    return {
        decision: "allow",
        risk: "SAFE",
        score: harmless > 0 || undetected >= 0 ? 20 : 30,
        reasons: [
            "No malicious or suspicious detections reported for this URL."
        ],
        vtStats: { malicious, suspicious, harmless, undetected }
    };
}

const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
        sendJson(res, 204, {});
        return;
    }

    if (req.method === "POST" && req.url === "/api/url-check") {
        try {
            const body = await readJsonBody(req);
            const url = String(body.url || "").trim();

            if (!url) {
                sendJson(res, 400, { error: "Missing url" });
                return;
            }

            console.log(`Checking URL in server: ${url}`);
            const report = await ensureUrlAnalysis(url);
            const decision = buildDecision(report);
            console.log(`Server decision for ${url}: ${decision.decision}`);
            sendJson(res, 200, decision);
        } catch (error) {
            console.error(`Server lookup failed: ${error.message}`);
            sendJson(res, 502, {
                error: "Upstream reputation lookup failed",
                detail: error.message
            });
        }
        return;
    }

    sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
    console.log(`LinkShield backend listening on http://localhost:${PORT}`);
});
