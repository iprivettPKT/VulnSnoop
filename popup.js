document.getElementById("checkVulnerabilities").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.scripting.executeScript(
      {
        target: { tabId: tabs[0].id },
        files: ["content-script.js"],
      },
      () => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError.message);
          return;
        }

        chrome.runtime.onMessage.addListener((response) => {

		if (!response.vulnerabilityDetails) {
		    console.error('Error: vulnerabilityDetails is undefined.');
		    alert('Error: vulnerabilityDetails is undefined.');
 		   return;
		  }

          let vulnerabilitiesFound = false;
          let message = "Vulnerabilities detected:\n\n";
          const vulnerabilityDetails = response.vulnerabilityDetails;

          // XSS vulnerability details
		if (vulnerabilityDetails.xssVulnerabilities && vulnerabilityDetails.xssVulnerabilities.length > 0) {
		  vulnerabilitiesFound = true;
		  message += "Potential XSS vulnerabilities:\n";
		  vulnerabilityDetails.xssVulnerabilities.forEach((vuln) => {
		    message += `- ${vuln.outerHTML}\n`;
		  });
		  message += "\n";
		  message += "\n";
		}

            // SQL Injection vulnerability details
            if (vulnerabilityDetails.sqlInjectionVulnerabilities.length > 0) {
              message += "Potential SQL Injection vulnerabilities:\n";
              vulnerabilityDetails.sqlInjectionVulnerabilities.forEach((vuln) => {
                message += `- ${vuln.outerHTML}\n`;
              });
              message += "\n";
              message += "\n";
            }

            // Autocomplete vulnerability details
            if (vulnerabilityDetails.autocompleteVulnerabilities.length > 0) {
              message += "Potential Autocomplete vulnerabilities:\n";
              vulnerabilityDetails.autocompleteVulnerabilities.forEach((vuln) => {
                message += `- ${vuln.outerHTML}\n`;
              });
              message += "\n";
              message += "\n";
            }

            // Directory Traversal vulnerability details
            if (vulnerabilityDetails.directoryTraversalVulnerabilities.length > 0) {
              message += "Potential Directory Traversal vulnerabilities:\n";
              vulnerabilityDetails.directoryTraversalVulnerabilities.forEach((vuln) => {
                message += `- ${vuln.outerHTML}\n`;
              });
              message += "\n";
              message += "\n";
            }

            // Command Injection vulnerability details
            if (vulnerabilityDetails.commandInjectionVulnerabilities.length > 0) {
              message += "Potential Command Injection vulnerabilities:\n";
              vulnerabilityDetails.commandInjectionVulnerabilities.forEach((vuln) => {
                message += `- ${vuln.outerHTML}\n`;
              });
              message += "\n";
              message += "\n";
            }

            // Information Disclosure vulnerability details
		if (vulnerabilityDetails.informationDisclosureVulnerabilities.length > 0) {
		  vulnerabilitiesFound = true;
		  message += "Potential Information Disclosure vulnerabilities:\n";
		  vulnerabilityDetails.informationDisclosureVulnerabilities.forEach((vuln) => {
		    const formattedCommentText = vuln.textContent.replace(/\n/g, ' | ');
		    message += `- ${vuln.tagName}: ${formattedCommentText}\n`;
 		  });
		  message += "\n";
		  message += "\n";
		}

            // CSRF Token vulnerability details
            if (vulnerabilityDetails.csrfTokenWords.length > 0) {
              message += "Found potential CSRF tokens:\n";
              vulnerabilityDetails.csrfTokenWords.forEach((token) => {
                message += `- ${token}\n`;
              });
              message += "\n";
              message += "\n";
            }

            // WebSocket usage details
            if (vulnerabilityDetails.webSocketUsage) {
              message += `Potential WebSocket vulnerability detected in inline script: ${vulnerabilityDetails.webSocketUsage.outerHTML}\n`;
              message += "\n";
            }

            // DOM-based XSS vulnerability details
            if (vulnerabilityDetails.domXssVulnerabilities) {
              message += `Potential DOM-based XSS vulnerability detected in inline script: ${vulnerabilityDetails.domXssVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

            // Clickjacking vulnerability details
            if (vulnerabilityDetails.clickjackingVulnerabilities) {
              message += `Potential Clickjacking vulnerability detected: ${vulnerabilityDetails.clickjackingVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

            // CORS vulnerability details
            if (vulnerabilityDetails.corsVulnerabilities) {
              message += `Potential CORS vulnerability detected: ${vulnerabilityDetails.corsVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

            // Access control vulnerability details
            if (vulnerabilityDetails.accessControlVulnerabilities) {
              message += `Potential Access Control vulnerability detected: ${vulnerabilityDetails.accessControlVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

            // XXE injection vulnerability details
            if (vulnerabilityDetails.xxeVulnerabilities) {
              message += `Potential XXE injection vulnerability detected: ${vulnerabilityDetails.xxeVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

            // CSRF vulnerability details
            if (vulnerabilityDetails.csrfVulnerabilities) {
              message += `Potential CSRF vulnerability detected: ${vulnerabilityDetails.csrfVulnerabilities.outerHTML}\n`;
              message += "\n";
            }

             // Directory traversal vulnerability details
  		if (vulnerabilityDetails.directoryTraversalVulnerabilities.length > 0) {
  			vulnerabilitiesFound = true;
  			message += "Potential Directory Traversal vulnerabilities:\n";
  			vulnerabilityDetails.directoryTraversalVulnerabilities.forEach((vuln) => {
    				message += `- URL: ${vuln.url}, Vulnerable Parameter: ${vuln.parameter}\n`;
  			});
  			message += "\n";
              message += "\n";
		}
		
		// HTML comments
		if (vulnerabilityDetails.htmlComments.length > 0) {
  			vulnerabilitiesFound = true;
  			message += "HTML comments:\n";
  			vulnerabilityDetails.htmlComments.forEach((comment) => {
				const formattedCommentText = comment.textContent.replace(/\n/g, ' | ');
    				message += `- ${comment.textContent}\n`; 
  			});
  			message += "\n";
		}

  	//if (vulnerabilitiesFound) {
    		//alert(message);
  	//} else {
    		//console.log("No vulnerabilities detected.");
		//alert("No vulnerabilities detected.");
  	 //}

     if (vulnerabilitiesFound) {
    document.getElementById("vulnerabilityList").innerHTML = message.split("\n").join("<br>");
} else {
    document.getElementById("vulnerabilityList").textContent = "No vulnerabilities detected.";
}
          
        });
      });
  });
}); 


