const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const { IncomingWebhook } = require('@slack/webhook');
const PDFDocument = require('pdfkit');

let panel;
let interval;
let latestPayload = null;

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('deptrack.openDashboard', () => {
      if (!panel) {
        panel = vscode.window.createWebviewPanel(
          'deptrackDashboard',
          'DepTrack Dashboard',
          vscode.ViewColumn.One,
          {
            enableScripts: true,
            localResourceRoots: [
              vscode.Uri.file(path.join(context.extensionPath, 'dist'))
            ]
          }
        );
        panel.webview.html = getWebviewContent(context, panel);

        panel.webview.onDidReceiveMessage(msg => {
          switch (msg.command) {
            case 'refresh':
              runAllChecks(context);
              break;

            case 'smokeTest':
              panel.webview.postMessage({
                command: 'smokeTestResult',
                payload: `VS Code ${vscode.version}`
              });
              break;

            case 'exportCSV':
              exportCsv(context);
              break;

            case 'exportPDF':
              exportPdf(context);
              break;

            case 'sendSlack':
              sendSlackNotification(context);
              break;

            case 'notify':
              // NEW: show notifications instead of alert()
              vscode.window.showInformationMessage(msg.text);
              break;
          }
        });

        panel.onDidDispose(() => panel = undefined);
      } else {
        panel.reveal(vscode.ViewColumn.One);
      }

      runAllChecks(context);
    })
  );

  // every 5 minutes
  interval = setInterval(() => runAllChecks(context), 5 * 60 * 1000);
  context.subscriptions.push({ dispose: () => clearInterval(interval) });

  // on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => runAllChecks(context))
  );
}

async function runAllChecks(context) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    return vscode.window.showErrorMessage('DepTrack: open a folder to monitor.');
  }
  const ws = folders[0].uri.fsPath;

  const [outdated, vuln, rawLicenses, lint] = await Promise.all([
    execJson('npm outdated --json', ws),
    execJson('snyk test --json', ws),
    execJson('npx license-checker --json', ws),
    execJson('npx eslint . -f json', ws),
  ]);

  const licenses = processLicenses(rawLicenses);
  latestPayload = { outdated, vuln, licenses, lint };

  panel?.webview.postMessage({ command: 'updateData', payload: latestPayload });

  const vulnCount = Object.keys(vuln?.vulnerabilities || {}).length;
  if (vulnCount > 0) {
    await sendSlackNotification(context, `🚨 ${vulnCount} vulnerabilities found.`);
  }
}

function processLicenses(raw) {
  const counts = {};
  for (const info of Object.values(raw || {})) {
    let lic = info.licenses;
    if (Array.isArray(lic)) lic = lic.join(', ');
    counts[lic] = (counts[lic] || 0) + 1;
  }
  return Object.entries(counts).map(([license, count]) => ({ license, count }));
}

function execJson(cmd, cwd) {
  return new Promise(resolve => {
    exec(cmd, { cwd }, (err, stdout) => {
      if (err && !stdout) return resolve({});
      try { resolve(JSON.parse(stdout)); } catch { resolve({}); }
    });
  });
}

async function sendSlackNotification(context, text = 'DepTrack alert') {
  const cfg = vscode.workspace.getConfiguration('deptrack');
  const url = cfg.get('slackWebhookUrl');
  if (!url) {
    return vscode.window.showWarningMessage('DepTrack: Slack webhook not configured.');
  }
  const webhook = new IncomingWebhook(url);
  await webhook.send({ text });
  vscode.window.showInformationMessage('DepTrack: Slack alert sent.');
}

function exportCsv(context) {
  if (!latestPayload) return;
  const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
  let csv = 'Category,Package,Details\n';

  Object.entries(latestPayload.outdated || {}).forEach(([pkg, i]) => {
    csv += `Outdated,${pkg},"${i.current}→${i.latest}"\n`;
  });
  Object.entries(latestPayload.vuln?.vulnerabilities || {}).forEach(([pkg, i]) => {
    csv += `Vulnerability,${pkg},"severity ${JSON.stringify(i.severity)}"\n`;
  });
  latestPayload.licenses.forEach(l => {
    csv += `License,${l.license},${l.count}\n`;
  });
  (latestPayload.lint || []).forEach(issue => {
    csv += `ESLint,${issue.filePath},"${issue.messages.length} issues"\n`;
  });

  const uri = vscode.Uri.file(path.join(ws, 'deptrack-report.csv'));
  vscode.workspace.fs.writeFile(uri, Buffer.from(csv, 'utf8'))
    .then(() => vscode.window.showInformationMessage('CSV exported'))
    .catch(e => vscode.window.showErrorMessage(`CSV export failed: ${e.message}`));
}

function exportPdf(context) {
  if (!latestPayload) return;
  const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const out = path.join(ws, 'deptrack-report.pdf');
  const doc = new PDFDocument();
  doc.pipe(fs.createWriteStream(out));

  doc.fontSize(20).text('DepTrack Report', { underline: true }).moveDown();
  doc.fontSize(14).text('Outdated Packages:');
  for (const [pkg, i] of Object.entries(latestPayload.outdated || {})) {
    doc.text(` • ${pkg}: ${i.current} → ${i.latest}`);
  }
  doc.moveDown().text('Vulnerabilities:');
  for (const [pkg, i] of Object.entries(latestPayload.vuln?.vulnerabilities || {})) {
    doc.text(` • ${pkg}: severity ${JSON.stringify(i.severity)}`);
  }
  doc.moveDown().text('Licenses:');
  latestPayload.licenses.forEach(l => doc.text(` • ${l.license}: ${l.count}`));
  doc.moveDown().text('ESLint Issues:');
  (latestPayload.lint || []).forEach(issue => {
    doc.text(` • ${issue.filePath}: ${issue.messages.length} messages`);
  });

  doc.end();
  doc.on('finish', () => vscode.window.showInformationMessage('PDF exported'));
}

function getWebviewContent(context, panel) {
  const html = fs.readFileSync(
    path.join(context.extensionPath, 'dist', 'dashboard.html'),
    'utf8'
  );
  const chartUri = panel.webview.asWebviewUri(
    vscode.Uri.file(path.join(context.extensionPath, 'dist', 'chart.min.js'))
  );
  return html.replace(
    /<script src="chart\.min\.js"><\/script>/,
    `<script src="${chartUri}"></script>`
  );
}

function deactivate() {
  clearInterval(interval);
}

module.exports = { activate, deactivate };
