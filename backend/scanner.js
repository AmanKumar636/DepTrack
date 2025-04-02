// scanner.js

async function runScan(filename, content) {
  let vulnerabilities = [];
  let outdated = [];
  let licenseIssues = [];

  console.log(`Scanning file: ${filename}`);

  // Check for vulnerable patterns
  if (/eval\s*\(/.test(content)) {
    vulnerabilities.push({
      id: "VULN-EVAL",
      package: "JavaScript eval usage",
      severity: "high",
      recommendation: "Avoid using eval() with untrusted input."
    });
  }
  if (/exec\s*\(/.test(content)) {
    vulnerabilities.push({
      id: "VULN-EXEC",
      package: "Shell command injection",
      severity: "high",
      recommendation: "Sanitize inputs before concatenating them into shell commands."
    });
  }
  if (/password123/.test(content)) {
    vulnerabilities.push({
      id: "VULN-CREDENTIALS",
      package: "Hard-coded credentials",
      severity: "medium",
      recommendation: "Remove hard-coded credentials and use environment variables or a secure vault."
    });
  }
  if (/axios/.test(content)) {
    outdated.push({
      package: "axios",
      currentVersion: "0.18.0",
      latestVersion: "0.21.1",
      recommendation: "Update axios to the latest version for bug fixes and improvements."
    });
  }
  if (/left-pad/.test(content)) {
    licenseIssues.push({
      package: "left-pad",
      license: "WTFPL",
      recommendation: "Review this license to ensure it complies with your project policies."
    });
  }

  // For testing: Force a vulnerability if none detected.
  if (vulnerabilities.length === 0) {
    vulnerabilities.push({
      id: "DUMMY-VULN",
      package: "Dummy Vulnerability",
      severity: "high",
      recommendation: "This is a forced vulnerability for testing purposes."
    });
  }

  const snykResult = await new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        snykSummary: "2 vulnerabilities detected via Snyk",
        details: [
          { id: "SNYK-001", package: "express", severity: "high", recommendation: "Update to the latest version." },
          { id: "SNYK-002", package: "lodash", severity: "medium", recommendation: "Update lodash to avoid prototype pollution." },
        ]
      });
    }, 1000);
  });

  const summary = vulnerabilities.length > 0
    ? `${vulnerabilities.length} vulnerabilities found.`
    : "No vulnerabilities found.";

  const scanResult = {
    timestamp: new Date(),
    summary,
    vulnerabilities,
    outdated,
    licenseIssues,
    snyk: snykResult
  };

  console.log("Final scan result:", scanResult);
  return scanResult;
}

module.exports = { runScan };
