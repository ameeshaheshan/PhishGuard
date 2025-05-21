issueItem.style.alignItems = 'center';
issueItem.style.marginBottom = '8px';

const icon = document.createElement('div');
icon.innerHTML = '⚠️';
icon.style.marginRight = '8px';

const text = document.createElement('div');
text.textContent = issue;
text.style.fontSize = '14px';
text.style.color = '#333';

issueItem.appendChild(icon);
issueItem.appendChild(text);
resultsList.appendChild(issueItem);


statusIndicator.appendChild(statusIcon);
statusIndicator.appendChild(statusText);
resultsSection.appendChild(statusIndicator);
resultsSection.appendChild(resultsList);

content.appendChild(header);
content.appendChild(urlSection);
content.appendChild(resultsSection);
overlay.appendChild(content);
document.body.appendChild(overlay);

setTimeout(() => {
  popup.style.opacity = '1';
  popup.style.transform = 'translateY(0)';
}, 50);

setTimeout(() => {
  popup.style.opacity = '0';
  popup.style.transform = 'translateY(-20px)';
  setTimeout(() => {
    document.body.removeChild(popup);
  }, 300);
}, 10000);

function detectHiddenForms() {
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  const suspiciousFields = [];

  hiddenInputs.forEach(input => {
    const name = input.name.toLowerCase();
    if (name.includes('user') || name.includes('pass') || name.includes('auth')) {
      suspiciousFields.push({
        name: input.name,
        id: input.id,
        value: input.value
      });
    }
  });

  if (suspiciousFields.length > 0) {
    chrome.runtime.sendMessage({
      action: 'hiddenFieldsDetected',
      fields: suspiciousFields
    });
  }
}

function detectSuspiciousScripts() {
  const scripts = document.getElementsByTagName('script');
  const suspiciousScripts = [];

  Array.from(scripts).forEach(script => {

    if (script.src) {
      try {
        const scriptURL = new URL(script.src);
        if (!scriptURL.hostname.endsWith(window.location.hostname)) {
          suspiciousScripts.push(script.src);
        }
      } catch (e) {
        suspiciousScripts.push('Invalid script URL');
      }
    }

    else {
      if (script.textContent.includes('base64')) {
        suspiciousScripts.push('Base64 encoded data found');
      }
      if (script.textContent.includes('eval(')) {
        suspiciousScripts.push('Suspicious eval() function used');
      }
    }
  });

  if (suspiciousScripts.length > 0) {
    chrome.runtime.sendMessage({
      action: 'suspiciousScripts',
      scripts: suspiciousScripts
    });
  }
}

window.addEventListener('load', () => {
  detectHiddenForms();
  detectSuspiciousScripts();
  scanPageLinks();
});

let redirectHistory = [];

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'updateRedirects') {
    redirectHistory = message.redirects;
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getRedirects') {
    sendResponse({ redirects: redirectHistory });
  }
});