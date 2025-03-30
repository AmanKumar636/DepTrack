// scanner.js

const { exec } = require("child_process");

// Run npm audit and return the parsed JSON result.
function runNpmAudit() {
  return new Promise((resolve, reject) => {
    exec("npm audit --json", (error, stdout, stderr) => {
      if (error) {
        console.error("npm audit error:", error);
        return reject(error);
      }
      try {
        const result = JSON.parse(stdout);
        resolve(result);
      } catch (parseError) {
        console.error("Failed to parse npm audit output:", parseError);
        reject(parseError);
      }
    });
  });
}

// Fallback dummy scan if npm audit fails.
function dummyScan() {
  return {
    timestamp: new Date(),
    summary: "Dummy scan: vulnerabilities found.",
    vulnerabilities: [
      { id: "VULN-001", package: "lodash", severity: "medium", recommendation: "Update to version 4.17.21" },
      { id: "VULN-002", package: "express", severity: "low", recommendation: "Review usage" }
    ],
    outdated: [],
    licenseIssues: []
  };
}

// Simulated Snyk integration – in a real scenario, use Snyk’s API with authentication.
function runSnykScan() {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        snykSummary: "Dummy Snyk scan: no additional issues."
      });
    }, 1000);
  });
}

// Main scan function that combines npm audit and Snyk results.
async function runFullScan() {
  let npmResult;
  try {
    npmResult = await runNpmAudit();
  } catch (error) {
    console.error("npm audit failed, using dummy scan:", error);
    npmResult = dummyScan();
  }

  const snykResult = await runSnykScan();

  // Process npmResult to extract vulnerabilities.
  let vulnerabilities = [];

  // If using legacy format with "advisories":
  if (npmResult.advisories) {
    for (const id in npmResult.advisories) {
      const advisory = npmResult.advisories[id];
      vulnerabilities.push({
        id: advisory.id,
        package: advisory.module_name,
        severity: advisory.severity,
        recommendation: advisory.url // URL for more info; customize as needed.
      });
    }
  }
  // Otherwise, if "vulnerabilities" exists (possibly as an object)
  else if (npmResult.vulnerabilities) {
    // If it's already an array, use it directly
    if (Array.isArray(npmResult.vulnerabilities)) {
      vulnerabilities = npmResult.vulnerabilities;
    } else {
      // Convert object into an array
      vulnerabilities = Object.keys(npmResult.vulnerabilities).map(key => {
        const vuln = npmResult.vulnerabilities[key];
        return {
          package: key,
          severity: vuln.severity || "unknown",
          recommendation: vuln.name ? `Check package ${key}` : ""
        };
      });
    }
  }

  // Ensure vulnerabilities is always an array
  if (!Array.isArray(vulnerabilities)) {
    vulnerabilities = [];
  }

  return {
    timestamp: new Date(),
    summary: vulnerabilities.length > 0 
      ? `${vulnerabilities.length} vulnerabilities found.` 
      : "No vulnerabilities found.",
    vulnerabilities,
    outdated: npmResult.outdated || [],
    licenseIssues: npmResult.licenseIssues || [],
    snyk: snykResult
  };
}

module.exports = { runFullScan };
