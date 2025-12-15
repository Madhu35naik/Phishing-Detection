console.log("🔥 CONTENT SCRIPT LOADED!");

const API_URL = "http://localhost:5000/api/scan";

// ============ LOAD WHITELIST FIRST ============
let whitelist = [];

chrome.storage.sync.get(["whitelist"], (r) => {
    whitelist = r.whitelist || [];
    autoScan();  // start only after whitelist loaded
});

// ============ AUTO SCAN ============
function autoScan() {
    const url = window.location.href;
    const hostname = new URL(url).hostname;

    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;
    if (whitelist.includes(hostname)) return;

    scanURL(url);
}

// ============ SCAN API ============
async function scanURL(url) {
    try {
        const res = await fetch(API_URL, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ url })
        });

        const data = await res.json();

        chrome.runtime.sendMessage({ action: "save_history", data });

        if (data.prediction === "phishing") {
            playSound();
            showWarningOverlay(data);
        }

    } catch (err) {
        console.log("Scan error:", err);
    }
}

// ============ SOUND ALERT ============
function playSound() {
    const audio = new Audio(chrome.runtime.getURL("alert.mp3"));
    audio.volume = 0.5;
    audio.play().catch(() => {});
}

// ============ WARNING OVERLAY ============
function showWarningOverlay(data) {
    const overlay = document.createElement("div");
    overlay.id = "ps-overlay";

    overlay.innerHTML = `
        <div class="ps-box">
            <h2>⚠️ Phishing Risk Detected!</h2>
            <p>${data.url}</p>
            <p><strong>Risk Score:</strong> ${data.risk_score}%</p>

            <button id="ps-back">Go Back</button>
            <button id="ps-continue">Continue Anyway</button>
            <button id="ps-allow">Always Allow This Site</button>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("ps-back").onclick = () => {
        location.href = "https://google.com";
    };

    document.getElementById("ps-continue").onclick = () => {
        overlay.remove();
    };

    document.getElementById("ps-allow").onclick = () => {
        const domain = new URL(data.url).hostname;
        chrome.runtime.sendMessage({ action: "add_whitelist", domain });
        overlay.remove();
    };
}
