console.log("SecOps Azure Real-Time Telemetry Active.");

function getAzurePageName() {
    const rawTitle = (document.title || "").replace(" - Microsoft Azure", "").trim();
    const hash = window.location.hash || "";

    // 1. Direct Heading & Breadcrumb DOM Inspection (Accurate for any blade)
    const bladeHeader = document.querySelector('.ext-header-text, .fxs-blade-title-titleText, h1, h2');
    if (bladeHeader && bladeHeader.innerText && bladeHeader.innerText.trim().length > 1) {
        const text = bladeHeader.innerText.trim();
        if (!text.toLowerCase().includes("microsoft azure") && !text.toLowerCase().includes("home")) {
            return text;
        }
    }

    // 2. Hash & Resource Provider Mapping
    if (hash.toLowerCase().includes("documentdb") || hash.toLowerCase().includes("cosmos")) {
        return "Azure Cosmos DB";
    }
    if (hash.toLowerCase().includes("loadbalancer") || rawTitle.toLowerCase().includes("load balancing")) {
        return "Load balancing and content delivery";
    }
    if (hash.toLowerCase().includes("virtualmachine") || rawTitle.toLowerCase().includes("virtual machine")) {
        return "Virtual Machines";
    }
    if (hash.toLowerCase().includes("storageaccount") || rawTitle.toLowerCase().includes("storage account")) {
        return "Storage Accounts";
    }
    if (hash.toLowerCase().includes("networksecuritygroup") || hash.toLowerCase().includes("firewall")) {
        return "Network Security Groups";
    }
    if (hash.toLowerCase().includes("subscriptionsblade") || rawTitle.toLowerCase().includes("subscription")) {
        return "Subscriptions";
    }
    if (hash.toLowerCase().includes("keyvault") || rawTitle.toLowerCase().includes("key vault")) {
        return "Key Vaults";
    }

    // 3. Fallback Clean Title
    if (rawTitle && rawTitle !== "Microsoft Azure" && rawTitle !== "Home") {
        return rawTitle.split("|")[0].trim();
    }

    return "Azure Portal Home";
}

let currentActivePage = "";

function pushTelemetryInstant() {
    const pageName = getAzurePageName();
    if (pageName === currentActivePage) return;
    currentActivePage = pageName;

    try {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
            chrome.runtime.sendMessage({
                action: "logActivity",
                data: {
                    blade: pageName,
                    url: window.location.href,
                    timestamp: new Date().toLocaleTimeString()
                }
            });
        }
    } catch (e) {
        // Safe fail
    }
}

// Click par instant capture
document.addEventListener('click', () => {
    setTimeout(pushTelemetryInstant, 100);
    setTimeout(pushTelemetryInstant, 300);
}, true);

// Hash / SPA route change
window.addEventListener('hashchange', () => setTimeout(pushTelemetryInstant, 100));
window.addEventListener('popstate', () => setTimeout(pushTelemetryInstant, 100));

// Background scanner
setInterval(pushTelemetryInstant, 350);
pushTelemetryInstant();