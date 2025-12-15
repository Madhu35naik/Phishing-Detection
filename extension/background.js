chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    // Save scan history
    if (msg.action === "save_history") {
        chrome.storage.sync.get(["history"], (res) => {
            const history = res.history || [];
            history.unshift(msg.data);
            chrome.storage.sync.set({ history: history.slice(0, 50) }); // keep last 50
        });
    }

    // Add to whitelist
    if (msg.action === "add_whitelist") {
        chrome.storage.sync.get(["whitelist"], (res) => {
            const list = res.whitelist || [];
            if (!list.includes(msg.domain)) {
                list.push(msg.domain);
                chrome.storage.sync.set({ whitelist: list });
            }
        });
    }
});
