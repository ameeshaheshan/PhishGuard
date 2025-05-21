const suspiciousTLDs = [".tk", ".gq", ".ml", ".ga", ".cf", ".top", ".xyz"];
const phishingKeywords = [
  "login",
  "verify",
  "bank",
  "account",
  "secure",
  "update",
  "confirm",
];
const blacklistedDomains = new Set();

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard installed successfully!");

  chrome.contextMenus.create({
    id: "scanLink",
    title: "Scan for phishing",
    contexts: ["link"],
  });

  chrome.storage.local.set({
    enableRealTimeScanning: true,
    enableBlacklistCheck: true,
    enableHeuristicCheck: true,
    customBlacklist: [],
    customWhitelist: [],
  });

  fetchBlacklist();
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scanLink" && info.linkUrl) {
    scanUrl(info.linkUrl).then((result) => {
      // Send scan results to the content script
      chrome.tabs.sendMessage(tab.id, {
        action: "showScanResult",
        url: info.linkUrl,
        result: result,
      });
    });
  }
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    chrome.storage.local.get("enableRealTimeScanning", (data) => {
      if (data.enableRealTimeScanning) {
        scanUrl(details.url).then((result) => {
          if (result.threatLevel === "high") {
            chrome.tabs.sendMessage(details.tabId, {
              action: "showWarning",
              url: details.url,
              result: result,
            });
          }
        });
      }
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanUrl") {
    scanUrl(request.url).then((result) => {
      sendResponse(result);
    });
    return true;
  } else if (request.action === "getTabInfo") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        sendResponse({ url: tabs[0].url, id: tabs[0].id });
      } else {
        sendResponse({ error: "No active tab found" });
      }
    });
    return true;
  } else if (request.action === "updateSettings") {
    chrome.storage.local.set(request.settings, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// Replace checkDomainAge with real WhoAPI call
async function checkDomainAge(domain) {
  const apiKey = "52c7cd4822a3df062fb0fcc92d0743d3";
  try {
    const response = await fetch(`https://api.whoapi.com/?apikey=${apiKey}&r=whois&domain=${domain}`);
    const data = await response.json();

    if (data.status === 0) {
      throw new Error(data.status_desc || "API request failed");
    }

    const creationDate = new Date(data.date_created);
    const currentDate = new Date();
    const ageInMilliseconds = currentDate - creationDate;
    const ageInDays = Math.floor(ageInMilliseconds / (1000 * 60 * 60 * 24));
    const ageInYears = Math.floor(ageInDays / 365.25);

    return {
      age: ageInDays,
      ageInYears: ageInYears,
      registrationDate: data.date_created,
    };
  } catch (error) {
    return {
      age: null,
      ageInYears: null,
      registrationDate: null,
      error: "Failed to get domain age",
      details: error.message,
    };
  }
}

// In scanUrl, update result.domainAge to store the full info
async function scanUrl(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    let result = {
      url: url,
      domain: domain,
      threatLevel: "safe",
      issues: [],
      secureConnection: urlObj.protocol === "https:",
      domainAge: null, // will be object now
      redirectChain: [],
      ipAddress: null,
    };

    // If domain is already an IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      result.issues.push("URL contains IP address instead of domain name");
      result.threatLevel = "suspicious";
      result.ipAddress = domain;
    } else {
      // Try to resolve domain to IP address
      try {
        result.ipAddress = await resolveDomainToIP(domain);
      } catch (e) {
        result.ipAddress = "Unknown";
      }
    }

    const tld = "." + domain.split(".").pop();
    if (suspiciousTLDs.includes(tld)) {
      result.issues.push(`Suspicious top-level domain (${tld})`);
      result.threatLevel = "suspicious";
    }

    const subdomainCount = domain.split(".").length - 2;
    if (subdomainCount > 3) {
      result.issues.push(`Excessive number of subdomains (${subdomainCount})`);
      result.threatLevel = "suspicious";
    }

    for (const keyword of phishingKeywords) {
      if (url.toLowerCase().includes(keyword)) {
        result.issues.push(
          `URL contains potential phishing keyword: "${keyword}"`
        );
        result.threatLevel = "suspicious";
        break;
      }
    }

    if (blacklistedDomains.has(domain)) {
      result.issues.push("Domain appears in phishing blacklist");
      result.threatLevel = "high";
    }

    // Check domain age via WHOIS API (now using WhoAPI)
    try {
      const domainAgeInfo = await checkDomainAge(domain);
      result.domainAge = domainAgeInfo;

      if (domainAgeInfo.age !== null && domainAgeInfo.age < 30) {
        result.issues.push(
          `Recently registered domain (${domainAgeInfo.age} days old)`
        );
        result.threatLevel = "suspicious";
      }
    } catch (error) {
      result.issues.push("Unable to determine domain age");
    }

    if (urlObj.protocol === "https:") {
      const sslCheck = await checkSSLCertificate(domain);

      if (!sslCheck.valid) {
        result.issues.push("Invalid SSL certificate");
        result.threatLevel = "suspicious";
      }
    } else {
      result.issues.push("Not using secure connection (HTTPS)");
      result.threatLevel = "suspicious";
    }

    if (result.issues.length >= 3) {
      result.threatLevel = "high";
    }

    return result;
  } catch (error) {
    return {
      url: url,
      threatLevel: "error",
      issues: [`Error analyzing URL: ${error.message}`],
      ipAddress: "Unknown",
    };
  }
}

// Add this helper function to resolve domain to IP (using a public API)
async function resolveDomainToIP(domain) {
  // Use a public DNS API (e.g., Cloudflare DNS over HTTPS)
  const response = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
    {
      headers: { accept: "application/dns-json" },
    }
  );
  const data = await response.json();
  if (
    data.Answer &&
    Array.isArray(data.Answer) &&
    data.Answer.length > 0
  ) {
    // Find the first A record
    const aRecord = data.Answer.find((a) => a.type === 1);
    if (aRecord) {
      return aRecord.data;
    }
  }
  throw new Error("IP address not found");
}

async function checkSSLCertificate(domain) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        valid: Math.random() > 0.1,
        issuer: "Demo CA",
        expiryDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      });
    }, 300);
  });
}

async function fetchBlacklist() {
  setTimeout(() => {
    const mockBlacklistedDomains = [
      "evil-phishing-site.com",
      "fake-bank-login.com",
      "login-secure-verify.tk",
      "accounts-verify-now.gq",
    ];

    mockBlacklistedDomains.forEach((domain) => {
      blacklistedDomains.add(domain);
    });

    console.log("Blacklist updated with entries:", blacklistedDomains.size);
  }, 1000);
}
