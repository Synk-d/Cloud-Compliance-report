chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "logActivity") {
        const item = request.data;

        chrome.storage.local.get({ visitedPages: [] }, function(data) {
            let pages = data.visitedPages || [];
            pages.unshift({ title: item.blade, url: item.url, time: item.timestamp });
            if (pages.length > 10) pages.pop();

            chrome.storage.local.set({ visitedPages: pages });
        });

        // FastAPI POST call
        fetch('http://127.0.0.1:8000/api/log-activity', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                activity: item.blade,
                target: item.blade,
                url: item.url,
                timestamp: item.timestamp
            })
        }).catch(err => console.log("Backend sync offline:", err));
    }
});