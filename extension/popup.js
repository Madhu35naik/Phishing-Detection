chrome.storage.sync.get(["history", "whitelist"], (r) => {
    const hist = r.history || [];
    const wl = r.whitelist || [];

    const hBox = document.getElementById("history");
    hBox.innerHTML = "";

    hist.slice(0, 10).forEach(h => {
        let div = document.createElement("div");
        div.className = "item";

        div.innerHTML = `
            <b>${h.url}</b><br>
            ${h.prediction} • ${h.confidence}%
        `;
        hBox.appendChild(div);
    });

    document.getElementById("whitelist").innerText = wl.join("\n");
});
