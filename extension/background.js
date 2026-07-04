// Arcis Phishing Shield Background Service Worker

// Active tab analysis cache to avoid redundant hits
const scanCache = {};

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only trigger when URL is updated and fully loaded
    if (changeInfo.url && (changeInfo.url.startsWith('http://') || changeInfo.url.startsWith('https://'))) {
        const url = changeInfo.url;
        
        // Skip if already in cache
        if (scanCache[url]) {
            updateBadge(tabId, scanCache[url]);
            return;
        }

        // Run background scan
        fetch('http://localhost:5001/api/analyze/url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) throw new Error('API Error');
            return response.json();
        })
        .then(data => {
            const risk = data.risk_score_pct;
            scanCache[url] = risk;
            updateBadge(tabId, risk);
        })
        .catch(err => {
            console.error('Background Scan failed:', err);
            // On error, clear badge
            chrome.action.setBadgeText({ tabId: tabId, text: '' });
        });
    }
});

function updateBadge(tabId, riskScore) {
    if (riskScore < 30) {
        // Safe: clear badge
        chrome.action.setBadgeText({ tabId: tabId, text: '' });
    } else if (riskScore < 70) {
        // Suspicious
        chrome.action.setBadgeText({ tabId: tabId, text: 'WARN' });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#f59e0b' });
    } else {
        // Dangerous
        chrome.action.setBadgeText({ tabId: tabId, text: 'BAD' });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#ef4444' });
    }
}

// Message listener to handle privileged fetch requests bypassing Gmail CSP
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyze_email') {
        fetch('http://localhost:5001/api/analyze/email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request.data)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.detail || 'API Error');
                });
            }
            return response.json();
        })
        .then(data => {
            sendResponse({ success: true, data: data });
        })
        .catch(err => {
            console.error('Background Email Scan failed:', err);
            sendResponse({ success: false, error: err.message });
        });
        return true; // Keep message channel open for async response
    }
});

