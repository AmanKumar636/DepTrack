const vscode = require('vscode');
const fetch = require('node-fetch');

function activate(context) {
  let disposable = vscode.commands.registerCommand('deptrack.check', async function () {
    // This function is executed when the command is invoked
    vscode.window.showInformationMessage("Running DepTrack scan...");

    // Optionally, you can call your backend API here (if available)
    try {
      const response = await fetch("http://localhost:3001/api/scan");
      const data = await response.json();
      let message = `Scan completed: ${data.summary}`;
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        message += ` (${data.vulnerabilities.length} vulnerabilities found)`;
      }
      vscode.window.showInformationMessage(message);
    } catch (error) {
      vscode.window.showErrorMessage("Error running scan: " + error.message);
    }
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};
