function checkForVulnerabilities() {
 
function serializeElement(element) {
  return {
    tagName: element.tagName,
    outerHTML: element.tagName === 'A' ? element.href : element.outerHTML,
  };
}

function serializeComment(comment) {
  return {
    textContent: comment.textContent,
  };
}

function detectXssVulnerabilities() {
  const scriptTags = document.getElementsByTagName('script');
  const xssVulnerabilities = [];

  for (const script of scriptTags) {
    if (!script.src && script.textContent.includes('<')) {
      xssVulnerabilities.push(script);
    }
  }

  return xssVulnerabilities;
}

function detectSqlInjectionVulnerabilities() {
  const inputTags = document.getElementsByTagName('input');
  const sqlInjectionVulnerabilities = [];

  for (const input of inputTags) {
    if (input.type.toLowerCase() === 'text' && input.name.toLowerCase().includes('sql')) {
      sqlInjectionVulnerabilities.push(input);
    }
  }

  return sqlInjectionVulnerabilities;
}

function detectAutocompleteVulnerabilities() {
  const inputTags = document.getElementsByTagName('input');
  const autocompleteVulnerabilities = [];

  for (const input of inputTags) {
    if (
      (input.type.toLowerCase() === 'password' || input.type.toLowerCase() === 'text') &&
      input.autocomplete !== 'off' &&
      input.autocomplete !== 'new-password'
    ) {
      autocompleteVulnerabilities.push(input);
    }
  }

  return autocompleteVulnerabilities;
}

function detectDirectoryTraversalVulnerabilities() {
  const anchorTags = document.getElementsByTagName('a');
  const directoryTraversalVulnerabilities = [];

  for (const anchor of anchorTags) {
    if (anchor.href.includes('../')) {
      directoryTraversalVulnerabilities.push(anchor);
    }
  }

  return directoryTraversalVulnerabilities;
}

function detectCommandInjectionVulnerabilities() {
  const inputTags = document.getElementsByTagName('input');
  const commandInjectionVulnerabilities = [];

  for (const input of inputTags) {
    if (input.type.toLowerCase() === 'text' && input.name.toLowerCase().includes('cmd')) {
      commandInjectionVulnerabilities.push(input);
    }
  }

  return commandInjectionVulnerabilities;
}

function detectInformationDisclosureVulnerabilities() {
  const sensitiveKeywords = [
    'password', 'api_key', 'api-key', 'secret_key', 'secret-key', 'access_key', 'access-key', 'private_key', 'private-key', 'client_secret', 'client-secret',
  ];

  const comments = document.evaluate(
    '//comment()', document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null
  );

  const informationDisclosureVulnerabilities = [];

  for (let i = 0; i < comments.snapshotLength; i++) {
    const comment = comments.snapshotItem(i);

    for (const keyword of sensitiveKeywords) {
      if (comment.textContent.toLowerCase().includes(keyword)) {
        informationDisclosureVulnerabilities.push(comment);
      }
    }
  }

  // Detecting /*...*/ comments in <script> and <style> tags
  const scriptAndStyleTags = Array.from(document.getElementsByTagName('script'))
    .concat(Array.from(document.getElementsByTagName('style')));

  for (const tag of scriptAndStyleTags) {
    const tagContent = tag.textContent;
    const regex = /\/\*[\s\S]*?\*\//g;
    const matches = tagContent.match(regex);

    if (matches) {
      matches.forEach(match => {
        for (const keyword of sensitiveKeywords) {
          if (match.toLowerCase().includes(keyword)) {
            const comment = {
              tagName: tag.tagName,
              textContent: match.trim(),
              outerHTML: tag.outerHTML,
            };
            informationDisclosureVulnerabilities.push(comment);
          }
        }
      });
    }
  }

  return informationDisclosureVulnerabilities;
}

function detectCsrfTokenWords() {
  const csrfTokenWords = [
    'csrf_token', 'csrf-token', 'csrfmiddlewaretoken', 'xsrf_token', 'xsrf-token', '_csrf', 'csrf', 'authenticity_token',
  ];

  const foundTokenWords = [];

  for (const tokenWord of csrfTokenWords) {
    if (document.documentElement.innerHTML.toLowerCase().includes(tokenWord)) {
      foundTokenWords.push(tokenWord);
    }
  }

  return foundTokenWords;
}

function detectDomXssVulnerabilities() {
  const inlineScripts = document.querySelectorAll('script:not([src])');

  for (const script of inlineScripts) {
    const scriptContent = script.textContent.toLowerCase();

    if (
      scriptContent.includes('innerhtml') ||
      scriptContent.includes('outerhtml') ||
      scriptContent.includes('document.write') ||
      scriptContent.includes('document.writeln')
    ) {
      return script;
    }
  }

  return null;
}

function detectWebSocketUsage() {
  const inlineScripts = document.querySelectorAll('script:not([src])');

  for (const script of inlineScripts) {
    const scriptContent = script.textContent.toLowerCase();

    if (scriptContent.includes('websocket(')) {
      return script;
    }
  }

  return null;
}

function findHTMLComments(documentRoot) {
  const commentNodes = [];
  const iterator = document.createNodeIterator(documentRoot, NodeFilter.SHOW_COMMENT);

  let currentNode;
  while ((currentNode = iterator.nextNode())) {
    commentNodes.push(currentNode);
  }

  return commentNodes;
}

  const vulnerabilityDetails = {
  xssVulnerabilities: detectXssVulnerabilities().map(serializeElement),
  sqlInjectionVulnerabilities: detectSqlInjectionVulnerabilities().map(serializeElement),
  autocompleteVulnerabilities: detectAutocompleteVulnerabilities().map(serializeElement),
  directoryTraversalVulnerabilities: detectDirectoryTraversalVulnerabilities().map(serializeElement),
  commandInjectionVulnerabilities: detectCommandInjectionVulnerabilities().map(serializeElement),
  informationDisclosureVulnerabilities: detectInformationDisclosureVulnerabilities().map(serializeComment),
  csrfTokenWords: detectCsrfTokenWords(),
  webSocketUsage: detectWebSocketUsage() ? serializeElement(detectWebSocketUsage()) : null,
  domXssVulnerabilities: detectDomXssVulnerabilities() ? serializeElement(detectDomXssVulnerabilities()) : null,
  clickjackingVulnerabilities: null,
  corsVulnerabilities: null,
  accessControlVulnerabilities: null,
  xxeVulnerabilities: null,
  csrfVulnerabilities: null,
  htmlComments: findHTMLComments(document).map(serializeComment),
};

if (
  vulnerabilityDetails.xssVulnerabilities.length > 0 ||
  vulnerabilityDetails.sqlInjectionVulnerabilities.length > 0 ||
  vulnerabilityDetails.autocompleteVulnerabilities.length > 0 ||
  vulnerabilityDetails.directoryTraversalVulnerabilities.length > 0 ||
  vulnerabilityDetails.commandInjectionVulnerabilities.length > 0 ||
  vulnerabilityDetails.informationDisclosureVulnerabilities.length > 0 ||
  vulnerabilityDetails.csrfTokenWords.length > 0 ||
  vulnerabilityDetails.domXssVulnerabilities ||
  vulnerabilityDetails.webSocketUsage
) {
  chrome.runtime.sendMessage({ xssDetected: true, vulnerabilityDetails });
} else {
  chrome.runtime.sendMessage({ xssDetected: false });
}
}
checkForVulnerabilities();