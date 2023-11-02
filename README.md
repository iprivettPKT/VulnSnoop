# VulnSnoop

VulnSnoop is a Chrome extension designed to enhance web security by scanning pages for potential vulnerabilities. It helps identify issues such as XSS, SQL injection, and more, providing a safer browsing experience.



## Features

- XSS Detection: Scans for and alerts about potential cross-site scripting (XSS) vulnerabilities.

- SQL Injection Detection: Identifies possible SQL injection points in web forms.

- Autocomplete Vulnerabilities: Detects if sensitive input fields are susceptible to autocomplete.

- Directory Traversal & Command Injection Detection: Checks for directory traversal and command injection vulnerabilities.

- Information Disclosure: Finds comments or scripts that may inadvertently disclose sensitive information.

- CSRF Token Detection: Looks for CSRF tokens to assess form security.

- DOM-Based XSS Scanning: Identifies DOM-based XSS vulnerabilities.

- WebSocket Usage Analysis: Alerts on pages using WebSockets.

- HTML Comment Scanning: Finds and displays HTML comments that might reveal internal information.



## Installation

1. To install the extension:

2. Clone the repository or download the source code.

3. Open Chrome and navigate to chrome://extensions/.

4. Enable "Developer mode".

5. Click "Load unpacked" and select the directory of your cloned or downloaded extension.



## Usage

After installation, the extension automatically scans each web page you visit when you click the button. Detected vulnerabilities are reported via a popup notification with details.



## Contributing

Contributions to VulnSnoop are welcome. Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the existing style and has been thoroughly tested.


## License

This project is licensed under the MIT License.







