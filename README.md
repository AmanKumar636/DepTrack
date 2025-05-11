# DepTrack

**Dependency & Security Tracker for VS Code**

DepTrack is a lightweight Visual Studio Code extension that helps you keep your project dependencies and code quality in check. With a single dashboard you can scan for outdated packages, security vulnerabilities, license issues, code smells and more—right inside your editor.

---

**Version:** 0.0.1  
**Publisher:** AmanKumar  
**Display Name:** DepTrack  
**Description:** Dependency & Security Tracker for Visual Studio Code

---

## Table of Contents

1. [Supported Operating Systems](#supported-operating-systems)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Usage](#usage)  
5. [Key Features](#key-features)  
6. [Configuration](#configuration)  
7. [Development & Building from Source](#development--building-from-source)  
8. [Troubleshooting](#troubleshooting)  
9. [License](#license)

---

## Supported Operating Systems

- **Windows:** Windows 10 or later  
- **macOS:**  macOS 11 (Big Sur) or later  
- **Linux:** Ubuntu 18.04+, Fedora 33+, Debian 10+, Arch Linux (Any distro supported by VS Code)

> DepTrack is a pure JavaScript/HTML extension and runs on any OS supported by Visual Studio Code.

---

## Prerequisites

- **Visual Studio Code** version 1.88.0 or later  
- **.VSIX package** for DepTrack (e.g. `deptrack-0.0.4.vsix`)  
- **Node.js** v16.0.0 or later and **npm** v8.0.0 or later (only required if building from source)  

---

## Installation

### 1. Install from VSIX (Recommended)

1. Download `deptrack.vsix` to your local machine.  
2. Open **Visual Studio Code**.  
3. Go to **Extensions** sidebar (⇧⌘X / Ctrl+Shift+X).  
4. Click the ⋯ menu in the top-right corner of the Extensions view.  
5. Choose **Install from VSIX…**  
6. Browse to and select your downloaded `deptrack.vsix`.  
7. After installation, click **Reload** when prompted.

### 2. Install via Command-Line

```bash
code --install-extension path/to/deptrack-0.0.4.vsix
```
Replace the path with wherever you saved the file.
After installation, restart VS Code or run Developer: Reload Window.

---

## Usage

1. Open the Command Palette (⇧⌘P / Ctrl+Shift+P).
2. Type DepTrack: to see available commands.
3. Run DepTrack: DepTrack: Open Dashboard to bring up the DepTrack panel.
4. Use the toolbar buttons to scan for:

  - Outdated Packages
  - Vulnerabilities
  - License Issues
  - ESLint Issues
  - Code Duplication
  - Cyclomatic Complexity
  - Secrets
  - Dependency Graph
  - Sonar Report
  - Suggested fixes
  - Industry Standard Code
  - Chatbot Assistance
  
---
## Key Features

- **Outdated Packages**  
  Quickly identify and update npm packages that are behind the latest published versions.

- **Vulnerability Scanning**  
  Integrates with Snyk and other vulnerability databases to highlight known security issues.

- **License Compliance**  
  Detects forbidden or incompatible licenses in your dependency tree.

- **ESLint Issues**  
  Runs ESLint rules and shows errors and warnings directly in the dashboard.

- **Code Duplication**  
  Uses JSCPD to find and report duplicated code blocks across your project.

- **Cyclomatic Complexity & SLOC**  
  Computes complexity metrics and maintainability scores to pinpoint potentially problematic code.

- **Secrets Detection**  
  Scans for accidentally committed API keys, passwords, and other secrets.

- **Industry Standard Code** <br>
  Check your code if it follows industry standards.
  
- **Dependency Graph**  
  Visualizes your project’s dependency graph with major version breakdowns.

- **Sonar Integration**  
  Pulls in SonarQube metrics (bugs, code smells, coverage, duplication) for a holistic quality overview.

- **Export & Reports**  
  • Export scan results as CSV or PDF  
  • Send email alerts or schedule PDF/CSV reports via SMTP  

- **AI-Powered Chatbot**  
  Ask questions, get suggestions or guidance about your code and dependencies using built-in AI assistance.
---

## Configuration

You can configure DepTrack settings in your VS Code Settings (settings.json):

```bash
{
  "deptrack.email.service": "gmail",
  "deptrack.email.auth.user": "<your-email@example.com>",
  "deptrack.email.auth.pass": "<your-email-password-or-app-token>",
  "deptrack.email.to": "<recipient@example.com>",
  "deptrack.snykOrg": "<your-snyk-organization-id>"
}
```
---

## Development & Building from Source
If you wish to modify or rebuild DepTrack:

### 1.Clone the repository

```bash
git clone https://github.com/deptrack/deptrack-vscode.git
cd deptrack-vscode
```

### 2.Install dev dependencies

```bash
npm install
```

### 3. Install Global CLI Tools:

   Run below command to put all required CLIs on your PATH:
   
  ```bash
   npm install -g vsce snyk eslint jscpd jsinspect plato chokidar-cli jest license-checker sonar-scanner 
  ```

### 4.Build/Bundle
  DepTrack is distributed as CommonJS; no transpilation is required.

  ```bash
  npm run build  
  ```

### 5.Run Extension in VS Code

  a.Open this folder in VS Code.
  b.Press F5 to launch the extension in a new Extension Development Host window.

---

## Troubleshooting

### 1.Extension failed to activate

  Verify your VS Code version is ≥ 1.88.0.
  Reload the window (⇧⌘P / Ctrl+Shift+P → Developer: Reload Window).

### 2.Email not sending

  Double-check SMTP settings under deptrack.email.*.
  If using Gmail, you may need an App Password.

### 3.Snyk integration errors

  Ensure deptrack.snykOrg is correctly set in settings.

===

## Tip:

You can also run:

```bash
code --uninstall-extension deptrack.deptrack
```
to remove the extension.

If you’re developing locally, open your extension folder in VS Code and press F5 to launch a Development Host with your latest changes.

---

## License

Copyright (c) 2025 Aman Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the “Software”), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.








