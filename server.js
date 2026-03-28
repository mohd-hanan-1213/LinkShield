// ─────────────────────────────────────────────
// FULL BACKEND: VirusTotal + Python Analyzer
// ─────────────────────────────────────────────

const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());

// ─────────────────────────────────────────────
// 🔧 RUN PYTHON ANALYZER
// ─────────────────────────────────────────────
function runAnalyzer(url) {
  return new Promise((resolve, reject) => {
    const py = spawn("python", ["analyzer.py", url]);

    let data = "";

    py.stdout.on("data", (chunk) => {
      data += chunk.toString();
    });

    py.stderr.on("data", (err) => {
      console.error("Python error:", err.toString());
    });

    py.on("close", () => {
      try {
        const parsed = JSON.parse(data);
        resolve(parsed);
      } catch (e) {
        reject("Invalid JSON from analyzer");
      }
    });

    py.on("error", reject);
  });
}

// ─────────────────────────────────────────────
// 🔗 MAIN ANALYSIS ROUTE (EXTENSION USES THIS)
// ─────────────────────────────────────────────
app.post('/api/check', async (req, res) => {
  const { url, apiKey } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    // 1️⃣ Run Python Analyzer
    let localResult = await runAnalyzer(url);

    // 2️⃣ VirusTotal (optional if API key provided)
    let vtResult = null;

    if (apiKey) {
      // Submit URL
      const submit = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      const submitData = await submit.json();
      const id = submitData.data.id;

      // Wait briefly for analysis
      await new Promise(r => setTimeout(r, 3000));

      // Get results
      const result = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${id}`,
        {
          headers: { 'x-apikey': apiKey }
        }
      );

      const resultData = await result.json();
      vtResult = resultData.data.attributes.stats;
    }

    // 3️⃣ FINAL DECISION
    let block = false;

    if (localResult.risk === "HIGH") {
      block = true;
    }

    if (vtResult && vtResult.malicious > 0) {
      block = true;
    }

    // 4️⃣ RESPONSE
    res.json({
      safe: !block,
      local: localResult,
      virusTotal: vtResult
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Analysis failed" });
  }
});

// ─────────────────────────────────────────────
// 🚀 START SERVER
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔥 Server running at http://localhost:${PORT}\n`);
});