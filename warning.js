document.addEventListener("DOMContentLoaded", () => {

const params = new URLSearchParams(window.location.search);
const url = params.get("url");

document.getElementById("url").innerText = url;


// CALL PYTHON ANALYZER
fetch("http://localhost:5000/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
})
.then(res => res.json())
.then(data => {

    // score
    document.getElementById("score").innerText =
        `Risk Score: ${data.score}% (${data.risk})`;

    // ai
    /* document.getElementById("ai").innerText =
        `AI Verdict: ${data.risk}`; */

    // explanation
    document.getElementById("explain").innerText =
        data.risk === "SAFE"
        ? "No suspicious patterns detected."
        : "This link may impersonate a trusted service.";

    // threats
    /* const threats = document.getElementById("threats");
    threats.innerHTML = "";

    if(data.reasons.length === 0){
        let li = document.createElement("li");
        li.innerText = "No threats detected";
        threats.appendChild(li);
    } else {
        data.reasons.forEach(r => {
            let li = document.createElement("li");
            li.innerText = r;
            threats.appendChild(li);
        });
    } */

    // issues
    const issues = document.getElementById("issues");
    issues.innerHTML = "";

    data.reasons.forEach(r => {
        let li = document.createElement("li");
        li.innerText = r;
        issues.appendChild(li);
    });

    // progress bar
    const fill = document.getElementById("fill");
    fill.style.width = data.score + "%";

    if(data.score < 30) fill.style.background="#22c55e";
    else if(data.score < 60) fill.style.background="#eab308";
    else if(data.score < 80) fill.style.background="#f97316";
    else fill.style.background="#ef4444";

});


// SHOW DETAILS
document.getElementById("toggleBtn").addEventListener("click", () => {
    const details = document.getElementById("details");
    const btn = document.getElementById("toggleBtn");

    if(details.classList.contains("hidden")){
        details.classList.remove("hidden");
        btn.innerText="Hide Details";
    } else {
        details.classList.add("hidden");
        btn.innerText="Show Details";
    }
});


// CONTINUE
document.querySelector(".continue").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "continue" }, () => {
        window.location.href = url;
    });
});


// GO BACK
document.querySelector(".back").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "closeTab" });
});

});