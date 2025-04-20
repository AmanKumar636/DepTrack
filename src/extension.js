// src/extension.js
const vscode      = require('vscode');
const { exec }    = require('child_process');
const path        = require('path');
const fs          = require('fs');
const nodemailer  = require('nodemailer');
const PDFDocument = require('pdfkit');

let panel, interval, latestPayload = null;

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('deptrack.openDashboard', () => {
      if (!panel) {
        panel = vscode.window.createWebviewPanel(
          'deptrackDashboard','DepTrack Dashboard',
          vscode.ViewColumn.One,
          { enableScripts:true, localResourceRoots:[
              vscode.Uri.file(path.join(context.extensionPath,'dist'))
            ]}
        );
        panel.webview.html = fs.readFileSync(
          path.join(context.extensionPath,'dist','dashboard.html'),'utf8'
        );
        panel.webview.onDidReceiveMessage(msg => {
          if (msg.command === 'refresh')     runAllChecks();
          if (msg.command === 'healthCheck') runHealthCheck();
          if (msg.command === 'sendEmail')   sendEmailNotification();
          if (msg.command === 'exportCSV')   exportCsv();
          if (msg.command === 'exportPDF')   exportPdf();
        });
      }
      panel.reveal();
      runAllChecks();
      interval = setInterval(runAllChecks, 5*60*1000);
    })
  );
}

async function runAllChecks() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) return vscode.window.showErrorMessage('Open a folder first');

  // 1) fetch data
  const [outdated, snykRes, rawLint] = await Promise.all([
    execJson('npm outdated --json', ws),
    execJson('snyk test --json',      ws),
    execJson('npx eslint . -f json',  ws),
  ]);

  // 2) extract vulnerabilities
  const vulnerabilities = snykRes.vulnerabilities || {};

  // 3) extract license issues robustly
  let rawLic = [];
  if (Array.isArray(snykRes.licensesPolicy)) {
    rawLic = snykRes.licensesPolicy;
  } else if (Array.isArray(snykRes.licensesPolicy?.invalidLicenses)) {
    rawLic = snykRes.licensesPolicy.invalidLicenses;
  }
  const licenseIssues = rawLic.map(p => ({
    name:     p.packageName,
    licenses: (p.licenses || []).join(', ')
  }));

  // 4) build suggestions
  const suggestions = makeSuggestions(outdated, vulnerabilities, licenseIssues, rawLint);

  latestPayload = { outdated, vuln: vulnerabilities, licenseIssues, rawLint, suggestions };
  panel.webview.postMessage({ command:'updateData', payload: latestPayload });

  // auto-email on vulns
  if (Object.keys(vulnerabilities).length) {
    sendEmailNotification(
      'DepTrack Vulnerability Alert',
      `Detected ${Object.keys(vulnerabilities).length} vulnerabilities.`
    );
  }
}

async function runHealthCheck() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  try {
    await Promise.all([
      execCmd('npm outdated --json', ws),
      execCmd('snyk test --json',    ws),
      execCmd('npx eslint . -f json', ws),
    ]);
    vscode.window.showInformationMessage('DepTrack: All systems go');
  } catch {
    vscode.window.showWarningMessage('DepTrack: Issues detected');
  }
}

function execJson(cmd, cwd) {
  return new Promise(res => {
    exec(cmd, { cwd }, (err, out) => {
      if (err && !out)       return res({});
      try { return res(JSON.parse(out)); }
      catch { return res({}); }
    });
  });
}
function execCmd(cmd, cwd) {
  return new Promise((res, rej) =>
    exec(cmd, { cwd }, err => err ? rej(err) : res())
  );
}

function makeSuggestions(out, vulns, lics, lint) {
  const s = [];
  // outdated
  Object.keys(out||{}).forEach(p =>
    s.push({ category:'Outdated', suggestion:`npm install ${p}@latest` })
  );
  // vulnerabilities
  if (Object.keys(vulns).length)
    s.push({
      category:'Vulnerabilities',
      suggestion:'npm audit fix  — or run "snyk wizard" to apply fixes'
    });
  // license
  lics.forEach(x =>
    s.push({
      category:'License',
      suggestion:`Replace or whitelist "${x.name}" (${x.licenses})`
    })
  );
  // lint
  if (Array.isArray(lint) && lint.length)
    s.push({ category:'Lint', suggestion:'npx eslint . --fix' });
  return s;
}

async function sendEmailNotification(subject='DepTrack Alert', text='') {
  const cfg  = vscode.workspace.getConfiguration('deptrack.email');
  const user = cfg.get('auth.user'), pass = cfg.get('auth.pass'), to = cfg.get('to');
  if (!user||!pass||!to) {
    return vscode.window.showWarningMessage(
      'Configure deptrack.email.auth.user, auth.pass, and to in settings. ' +
      'For Gmail+2FA use an app‑specific password: https://support.google.com/mail/?p=InvalidSecondFactor'
    );
  }
  const transporter = nodemailer.createTransport({ service:'gmail', auth:{ user, pass } });
  try {
    await transporter.sendMail({ from:user, to, subject, text });
    vscode.window.showInformationMessage('DepTrack: Email sent');
  } catch (err) {
    vscode.window.showErrorMessage(
      err.responseCode===534
        ? 'Gmail requires app‑specific password with 2FA'
        : `Email failed: ${err.message}`
    );
  }
}

function exportCsv() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!latestPayload) return;
  let csv = 'Category,Name,Details\n';
  Object.entries(latestPayload.outdated)
    .forEach(([p,i])=> csv+=`Outdated,${p},"${i.current}→${i.latest}"\n`);
  Object.entries(latestPayload.vuln)
    .forEach(([p,v])=> csv+=`Vulnerability,${p},"${v.severity}"\n`);
  latestPayload.licenseIssues
    .forEach(x=> csv+=`License,${x.name},"${x.licenses}"\n`);
  (latestPayload.rawLint||[]).forEach(issue=>{
    const f=issue.filePath||issue.file;
    csv+=`Lint,${f},"${(issue.messages||[]).length} issues"\n`;
  });
  latestPayload.suggestions
    .forEach(x=> csv+=`Suggestion,${x.category},"${x.suggestion}"\n`);
  const uri = vscode.Uri.file(path.join(ws,'deptrack-report.csv'));
  vscode.workspace.fs.writeFile(uri, Buffer.from(csv,'utf8'))
    .then(()=>vscode.window.showInformationMessage('CSV exported'));
}

function exportPdf() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!latestPayload) return;
  const out = path.join(ws,'deptrack-report.pdf');
  const doc = new PDFDocument();
  doc.pipe(fs.createWriteStream(out));

  doc.fontSize(20).text('DepTrack Report',{underline:true}).moveDown();
  doc.text('Outdated Packages:');
  Object.entries(latestPayload.outdated)
    .forEach(([p,i])=>doc.text(` • ${p}: ${i.current}→${i.latest}`));
  doc.moveDown().text('Vulnerabilities:');
  Object.entries(latestPayload.vuln)
    .forEach(([p,v])=>doc.text(` • ${p}: ${v.severity}`));
  doc.moveDown().text('License Issues:');
  latestPayload.licenseIssues
    .forEach(x=>doc.text(` • ${x.name}: ${x.licenses}`));
  doc.moveDown().text('Linting Issues:');
  (latestPayload.rawLint||[]).forEach(issue=>{
    const f=issue.filePath||issue.file;
    doc.text(` • ${f}: ${(issue.messages||[]).length} issues`);
  });
  doc.moveDown().text('Fix Suggestions:');
  latestPayload.suggestions
    .forEach(x=>doc.text(` • [${x.category}] ${x.suggestion}`));

  doc.end();
  doc.on('finish',()=>vscode.window.showInformationMessage('PDF exported'));
}

function deactivate() {
  clearInterval(interval);
}

module.exports = { activate, deactivate };
