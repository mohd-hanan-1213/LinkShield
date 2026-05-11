function jsonResponse(body, status = 200, origin = "*") {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Content-Type": "application/json"
        }
    });
}

function getAllowedOrigin(originHeader, allowedOriginsValue) {
    const allowedOrigins = String(allowedOriginsValue || "*")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);

    if (allowedOrigins.includes("*")) {
        return "*";
    }

    if (originHeader && allowedOrigins.includes(originHeader)) {
        return originHeader;
    }

    return allowedOrigins[0] || "*";
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeUrl(url) {
    const parsed = new URL(url);
    return parsed.toString();
}

function toBase64Url(value) {
    return btoa(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function vtFetch(path, env, options = {}) {
    const response = await fetch(`https://www.virustotal.com/api/v3${path}`, {
        ...options,
        headers: {
            "x-apikey": env.VT_API_KEY,
            ...(options.headers || {})
        }
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`VirusTotal ${response.status}: ${text}`);
    }

    return response.json();
}

async function getUrlReport(url, env) {
    const urlId = toBase64Url(normalizeUrl(url));
    return vtFetch(`/urls/${urlId}`, env);
}

async function submitUrl(url, env) {
    const body = new URLSearchParams({ url });
    const analysis = await vtFetch("/urls", env, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body
    });

    return analysis.data.id;
}

async function getAnalysis(analysisId, env) {
    return vtFetch(`/analyses/${analysisId}`, env);
}

async function ensureUrlAnalysis(url, env) {
    try {
        return await getUrlReport(url, env);
    } catch (error) {
        if (!String(error.message).includes("404")) {
            throw error;
        }
    }

    const analysisId = await submitUrl(url, env);

    for (let attempt = 0; attempt < 15; attempt += 1) {
        const analysis = await getAnalysis(analysisId, env);
        const attributes = analysis.data?.attributes || {};

        if (attributes.status === "completed") {
            try {
                return await getUrlReport(url, env);
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

export default {
    async fetch(request, env) {
        const allowedOrigin = getAllowedOrigin(
            request.headers.get("Origin"),
            env.ALLOWED_ORIGIN
        );

        if (request.method === "OPTIONS") {
            return jsonResponse({}, 204, allowedOrigin);
        }

        const url = new URL(request.url);

        if (request.method === "GET" && url.pathname === "/health") {
            return jsonResponse({ status: "ok" }, 200, allowedOrigin);
        }

        if (request.method === "POST" && url.pathname === "/api/url-check") {
            try {
                const body = await request.json();
                const targetUrl = String(body.url || "").trim();

                if (!targetUrl) {
                    return jsonResponse({ error: "Missing url" }, 400, allowedOrigin);
                }

                console.log(`Checking URL in worker: ${targetUrl}`);
                const report = await ensureUrlAnalysis(targetUrl, env);
                const decision = buildDecision(report);
                console.log(`Worker decision for ${targetUrl}: ${decision.decision}`);

                return jsonResponse(decision, 200, allowedOrigin);
            } catch (error) {
                console.error(`Worker lookup failed: ${error.message}`);
                return jsonResponse({
                    error: "Upstream reputation lookup failed",
                    detail: error.message
                }, 502, allowedOrigin);
            }
        }

        return jsonResponse({ error: "Not found" }, 404, allowedOrigin);
    }
};
