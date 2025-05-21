document.addEventListener("DOMContentLoaded", function () {
  const tabs = document.querySelectorAll(".nav-tabs button");
  const tabContents = document.querySelectorAll(".tab-content");

  tabs.forEach((tab) => {
    tab.classList.remove("active");
  });
  tabContents.forEach((content) => content.classList.remove("active"));

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tab.classList.add("active");
      const tabId = tab.id.replace("tab-", "");
      document.getElementById(`${tabId}-tab`).classList.add("active");
    });
  });

  const listTabs = document.querySelectorAll(".list-tabs button");
  const listContents = document.querySelectorAll(".list-content");

  listTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      listTabs.forEach((t) => t.classList.remove("active"));
      listContents.forEach((content) => content.classList.remove("active"));

      tab.classList.add("active");
      const contentId = tab.id.replace("-tab", "-content");
      document.getElementById(contentId).classList.add("active");
    });
  });

  getCurrentTabInfo();

  document.getElementById("scan-button").addEventListener("click", function () {
    const urlElement = document.getElementById("current-url");
    const url = urlElement.textContent;

    if (url && url !== "Loading...") {
      performScan(url);
    }
  });

  loadSettings();

  document
    .getElementById("save-settings")
    .addEventListener("click", saveSettings);

  document
    .getElementById("reset-settings")
    .addEventListener("click", resetSettings);

  document
    .getElementById("add-blacklist")
    .addEventListener("click", function () {
      const input = document.getElementById("blacklist-input");
      const domain = input.value.trim();

      if (domain) {
        addToList("customBlacklist", domain);
        input.value = "";
      }
    });

  document
    .getElementById("add-whitelist")
    .addEventListener("click", function () {
      const input = document.getElementById("whitelist-input");
      const domain = input.value.trim();

      if (domain) {
        addToList("customWhitelist", domain);
        input.value = "";
      }
    });

  document
    .getElementById("report-button")
    .addEventListener("click", exportReport);
});

function getCurrentTabInfo() {
  chrome.runtime.sendMessage({ action: "getTabInfo" }, function (response) {
    if (response && response.url) {
      document.getElementById("current-url").textContent = response.url;
      performScan(response.url);
    }
  });
}

function performScan(url) {
  updateStatusUI("scanning", "Scanning URL...", "Analyzing security features");
  clearResults();

  chrome.runtime.sendMessage(
    { action: "scanUrl", url: url },
    function (result) {
      updateScanResults(result);
    }
  );
}

function updateScanResults(result) {
  clearResults();

  if (!result || result.threatLevel === "error") {
    updateStatusUI(
      "warning",
      "Unable to scan URL",
      "An error occurred during analysis"
    );
    addResultItem("Unable to analyze URL. Please try again.", "warning");
    return;
  }

  let statusTitle, statusDescription;

  switch (result.threatLevel) {
    case "high":
      statusTitle = "High Risk Detected!";
      statusDescription = "This site shows multiple phishing indicators";
      updateStatusUI("danger", statusTitle, statusDescription);
      break;
    case "suspicious":
      statusTitle = "Suspicious Site";
      statusDescription = "This site has some suspicious characteristics";
      updateStatusUI("warning", statusTitle, statusDescription);
      alert('This site has some suspicious characteristics');
      break;
    case "safe":
      statusTitle = "Site Appears Safe";
      statusDescription = "No phishing indicators detected";
      updateStatusUI("safe", statusTitle, statusDescription);
      break;
  }

  addResultItem(`Domain: ${result.domain}`, "info");
  addResultItem(`IP Address: ${result.ipAddress}`, "info");
  addResultItem(`Scan Date: ${new Date().toLocaleString()}`, "info");

  if (result.secureConnection) {
    addResultItem("Uses secure connection (HTTPS)", "good");
  } else {
    addResultItem("Not using secure connection (HTTP)", "warning");
  }

  if (result.domainAge && result.domainAge.age !== null && result.domainAge.age !== undefined) {
    const ageText =
      result.domainAge.age < 30
        ? `Recently registered domain (${result.domainAge.age} days old)`
        : `Domain age: ${result.domainAge.age} days`;

    const type = result.domainAge.age < 30 ? "warning" : "good";
    addResultItem(ageText, type);
  }

  if (result.issues && result.issues.length > 0) {
    result.issues.forEach((issue) => {
      addResultItem(issue, "warning");
    });
  } else if (result.threatLevel === "safe") {
    addResultItem("No suspicious characteristics found", "good");
  }

  displayScanResult(result);
}

function displayScanResult(result) {
  document.getElementById("ipAddress").textContent = result.ipAddress || "Unknown";
  if (result.domainAge && result.domainAge.age !== null) {
    document.getElementById("domainAge").textContent =
      `${result.domainAge.age} days (${result.domainAge.ageInYears} years)`;
    document.getElementById("domainCreationDate").textContent =
      result.domainAge.registrationDate;
  } else {
    document.getElementById("domainAge").textContent = "Unknown";
    document.getElementById("domainCreationDate").textContent = "Unknown";
  }
}

function updateStatusUI(status, title, description) {
  const statusIcon = document.getElementById("security-status");
  const statusTitle = document.getElementById("status-title");
  const statusDescription = document.getElementById("status-description");

  statusIcon.classList.remove("safe", "warning", "danger");
  statusIcon.classList.add(status);
  statusTitle.textContent = title;
  statusDescription.textContent = description;
}

function addResultItem(text, type) {
  const resultsContainer = document.getElementById("results-container");
  const resultItem = document.createElement("div");
  resultItem.className = "result-item";
  const resultIcon = document.createElement("div");
  resultIcon.className = "result-icon";

  let iconSvg;
  switch (type) {
    case "good":
      iconSvg =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20"><path fill="none" d="M0 0h24v24H0z"/><path fill="#4caf50" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-.997-6l7.07-7.071-1.414-1.414-5.656 5.657-2.829-2.829-1.414 1.414L11.003 16z"/></svg>';
      break;
    case "warning":
      iconSvg =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20"><path fill="none" d="M0 0h24v24H0z"/><path fill="#ff9800" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-2a8 8 0 1 0 0-16 8 8 0 0 0 0 16zm-1-5h2v2h-2v-2zm0-8h2v6h-2V7z"/></svg>';
      break;
    case "danger":
      iconSvg =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20"><path fill="none" d="M0 0h24v24H0z"/><path fill="#f44336" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-1-7v2h2v-2zm0-8v6h2V7h-2z"/></svg>';
      break;
    default:
      iconSvg =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20"><path fill="none" d="M0 0h24v24H0z"/><path fill="#1a73e8" d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-2a8 8 0 1 0 0-16 8 8 0 0 0 0 16zm-1-5h2v2h-2v-2zm0-8h2v6h-2V7z"/></svg>';
  }

  resultIcon.innerHTML = iconSvg;

  const resultDetail = document.createElement("div");
  resultDetail.className = "result-detail";
  resultDetail.textContent = text;

  resultItem.appendChild(resultIcon);
  resultItem.appendChild(resultDetail);
  resultsContainer.appendChild(resultItem);
}

function clearResults() {
  const resultsContainer = document.getElementById("results-container");
  resultsContainer.innerHTML = "";
}

function loadSettings() {
  chrome.storage.local.get(
    [
      "enableRealTimeScanning",
      "enableBlacklistCheck",
      "enableHeuristicCheck",
      "customBlacklist",
      "customWhitelist",
    ],
    function (result) {
      document.getElementById("enableRealTimeScanning").checked =
        result.enableRealTimeScanning !== undefined
          ? result.enableRealTimeScanning
          : true;

      document.getElementById("enableBlacklistCheck").checked =
        result.enableBlacklistCheck !== undefined
          ? result.enableBlacklistCheck
          : true;

      document.getElementById("enableHeuristicCheck").checked =
        result.enableHeuristicCheck !== undefined
          ? result.enableHeuristicCheck
          : true;

      updateListUI("customBlacklist", result.customBlacklist || []);
      updateListUI("customWhitelist", result.customWhitelist || []);
    }
  );
}

function saveSettings() {
  const settings = {
    enableRealTimeScanning: document.getElementById("enableRealTimeScanning")
      .checked,
    enableBlacklistCheck: document.getElementById("enableBlacklistCheck")
      .checked,
    enableHeuristicCheck: document.getElementById("enableHeuristicCheck")
      .checked,
  };

  chrome.storage.local.set(settings, function () {
    const saveButton = document.getElementById("save-settings");
    const originalText = saveButton.textContent;
    saveButton.textContent = "Saved!";

    setTimeout(function () {
      saveButton.textContent = originalText;
    }, 1500);

    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: settings,
    });
  });
}

function resetSettings() {
  const defaultSettings = {
    enableRealTimeScanning: true,
    enableBlacklistCheck: true,
    enableHeuristicCheck: true,
    customBlacklist: [],
    customWhitelist: [],
  };

  chrome.storage.local.set(defaultSettings, function () {
    loadSettings();

    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: defaultSettings,
    });

    const resetButton = document.getElementById("reset-settings");
    const originalText = resetButton.textContent;
    resetButton.textContent = "Reset Complete!";

    setTimeout(function () {
      resetButton.textContent = originalText;
    }, 1500);
  });
}

function addToList(listName, domain) {
  chrome.storage.local.get(listName, function (result) {
    let list = result[listName] || [];

    if (!list.includes(domain)) {
      list.push(domain);

      const update = {};
      update[listName] = list;

      chrome.storage.local.set(update, function () {
        updateListUI(listName, list);

        chrome.runtime.sendMessage({
          action: "updateSettings",
          settings: update,
        });
      });
    }
  });
}

function removeFromList(listName, domain) {
  chrome.storage.local.get(listName, function (result) {
    let list = result[listName] || [];

    const index = list.indexOf(domain);
    if (index !== -1) {
      list.splice(index, 1);

      const update = {};
      update[listName] = list;

      chrome.storage.local.set(update, function () {
        updateListUI(listName, list);

        chrome.runtime.sendMessage({
          action: "updateSettings",
          settings: update,
        });
      });
    }
  });
}

function updateListUI(listName, items) {
  const containerID =
    listName === "customBlacklist" ? "blacklist-items" : "whitelist-items";
  const container = document.getElementById(containerID);

  container.innerHTML = "";

  items.forEach((item) => {
    const listItem = document.createElement("div");
    listItem.className = "list-item";

    const itemText = document.createElement("span");
    itemText.textContent = item;

    const removeButton = document.createElement("button");
    removeButton.textContent = "×";
    removeButton.addEventListener("click", function () {
      removeFromList(listName, item);
    });

    listItem.appendChild(itemText);
    listItem.appendChild(removeButton);
    container.appendChild(listItem);
  });

  if (items.length === 0) {
    const emptyMessage = document.createElement("div");
    emptyMessage.className = "list-item";
    emptyMessage.textContent = "No items in list";
    container.appendChild(emptyMessage);
  }
}

function exportReport() {
  const url = document.getElementById("current-url").textContent;
  const status = document.getElementById("status-title").textContent;
  const statusDescription =
    document.getElementById("status-description").textContent;

  let resultsText = "";
  const resultItems = document.querySelectorAll(".result-item");
  resultItems.forEach((item) => {
    resultsText +=
      "- " + item.querySelector(".result-detail").textContent + "\n";
  });

  const reportText = `PhishGuard Security Report
  ===========================
  URL: ${url}
  Status: ${status}
  Summary: ${statusDescription}
  
  Detailed Findings:
  ${resultsText}
  
  Report generated on: ${new Date().toLocaleString()}
  `;

  const blob = new Blob([reportText], { type: "text/plain" });

  const url_obj = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url_obj;
  a.download = "phishguard-report.txt";

  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url_obj);
}
