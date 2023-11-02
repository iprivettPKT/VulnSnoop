chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.sendMessage(tab.id, { checkVulnerabilities: true }, (response) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError.message);
      return;
    }

    if (response.xssDetected) {
      let message = 'Vulnerabilities detected:\n\n';

      const vulnerabilityDetails = response.vulnerabilityDetails;

      // XSS vulnerability details
      if (vulnerabilityDetails.xssVulnerabilities.length > 0) {
        message += 'Potential XSS vulnerabilities:\n';
        vulnerabilityDetails.xssVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // SQL Injection vulnerability details
      if (vulnerabilityDetails.sqlInjectionVulnerabilities.length > 0) {
        message += 'Potential SQL Injection vulnerabilities:\n';
        vulnerabilityDetails.sqlInjectionVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // Autocomplete vulnerability details
      if (vulnerabilityDetails.autocompleteVulnerabilities.length > 0) {
        message += 'Potential Autocomplete vulnerabilities:\n';
        vulnerabilityDetails.autocompleteVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // Directory Traversal vulnerability details
      if (vulnerabilityDetails.directoryTraversalVulnerabilities.length > 0) {
        message += 'Potential Directory Traversal vulnerabilities:\n';
        vulnerabilityDetails.directoryTraversalVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // Command Injection vulnerability details
      if (vulnerabilityDetails.commandInjectionVulnerabilities.length > 0) {
        message += 'Potential Command Injection vulnerabilities:\n';
        vulnerabilityDetails.commandInjectionVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // Information Disclosure vulnerability details
      if (vulnerabilityDetails.informationDisclosureVulnerabilities.length > 0) {
        message += 'Potential Information Disclosure vulnerabilities:\n';
        vulnerabilityDetails.informationDisclosureVulnerabilities.forEach((vuln) => {
          message += `- ${vuln.outerHTML}\n`;
        });
        message += '\n';
      }

      // CSRF Token vulnerability details
      if (vulnerabilityDetails.csrfTokenWords.length > 0) {
        message += 'Found potential CSRF tokens:\n';
        vulnerabilityDetails.csrfTokenWords.forEach((token) => {
          message += `- ${token}\n`;
        });
        message += '\n';
      }

      // WebSocket usage details
      if (vulnerabilityDetails.webSocketUsage) {
        message += `Potential WebSocket vulnerability detected in inline script: ${vulnerabilityDetails.webSocketUsage.outerHTML}\n`;
      }

      // DOM-based XSS vulnerability details
      if (vulnerabilityDetails.domXssVulnerabilities) {
        message += `Potential DOM-based XSS vulnerability detected in inline script: ${vulnerabilityDetails.domXssVulnerabilities.outerHTML}\n`;
      }

      alert(message);
    } else {
      console.log('No vulnerabilities detected.');
    }
  });
});