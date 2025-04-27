const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec: execCb, execSync } = require('child_process');
const execP = util.promisify(require('child_process').exec);
const axios = require('axios');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const semver = require('semver');
const stripAnsi = require('strip-ansi').default || require('strip-ansi');
const { ESLint } = require('eslint');
const fg = require('fast-glob');
require('dotenv').config()


const patterns = [
  { name: 'AWS Key',    regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private Key', regex: /-----BEGIN PRIVATE KEY-----/g }
];
const forbiddenLicenses = ['GPL','AGPL','LGPL','PROPRIETARY','UNKNOWN'];

let panel;
let refreshInterval;
let chatHistory = [];
let outputChannel;
let logLines = [];
const toolExists = {};
let isScanning = false;


let latestPayload = {
  outdated: {},
  vuln: {},
  vulnError: null,
  licenseIssues: [],
  eslintDetails: [],
  sonarResult: {},
  complexity: [],
  duplicationDetails: [],
  secrets: [],
  depGraph: {},
  chatHistory: [],
  suggestedFixes: []
};

function logError(fnName, err) {
  const msg = stripAnsi(err.stack || err.message || err);
  outputChannel && outputChannel.appendLine(`[${fnName}] ERROR: ${msg}`);
}

function resolveCmd(ws, tool) {
  try {
    execSync(`${tool} --version`, { stdio: 'ignore' });
    toolExists[tool] = true;
    return tool;
  } catch {}
  const bin = process.platform === 'win32' ? `${tool}.cmd` : tool;
  const local = path.join(ws, 'node_modules', '.bin', bin);
  if (fs.existsSync(local)) {
    toolExists[tool] = true;
    return local;
  }
  toolExists[tool] = false;
  return null;
}

async function scanSecrets(ws) {
  const fn = 'scanSecrets';
  outputChannel.appendLine('[Secrets] start');
  const results = [];
  const ignored = ['.git', 'node_modules', 'dist', 'report', '.scannerwork'];

  async function walk(dir) {
    try {
      const entries = await fs.promises.readdir(dir, { withFileTypes: true });
      for (const ent of entries) {
        if (ignored.includes(ent.name)) continue;
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          await walk(full);
        } else if (ent.isFile() && /\.(js|ts|py|sh|env|json)$/.test(ent.name)) {
          let txt;
          try { txt = await fs.promises.readFile(full, 'utf8'); } catch { continue; }
          for (const p of patterns) {
            let m;
            while ((m = p.regex.exec(txt)) !== null) {
              results.push({
                file: path.relative(ws, full),
                line: txt.slice(0, m.index).split('\n').length,
                rule: p.name,
                match: m[0]
              });
            }
          }
        }
      }
    } catch (e) {
      logError(fn, e);
    }
  }


  await walk(ws);
  outputChannel.appendLine(`[Secrets] found ${results.length} items`);
  outputChannel.appendLine('[Secrets] done');
  return results;
}


/**
 * Generates a flat dependency graph by reading package-lock.json (or yarn.lock) 
 * and flattening nested dependencies.
 */
const { parse: parseYarnLock } = require('@yarnpkg/lockfile');

async function checkDepGraph(ws) {
  const fn       = 'checkDepGraph';
  outputChannel.appendLine('[DepGraph] start');

  const npmLock  = path.join(ws, 'package-lock.json');
  const yarnLock = path.join(ws, 'yarn.lock');
  let graph       = {};

  try {
    if (fs.existsSync(npmLock)) {
      const lockRaw  = fs.readFileSync(npmLock, 'utf8');
      const lockData = JSON.parse(lockRaw);

      if (lockData.packages) {
        // npm v7+ lockfileVersion 2: flat map under "packages"
        for (const [pkgPath, info] of Object.entries(lockData.packages)) {
          if (pkgPath === '') continue;              // skip root
          const name = info.name
                     || pkgPath.split('node_modules/').pop();
          graph[name] = { version: info.version };
        }
      }
      else if (lockData.dependencies) {
        // classic npm lockfile
        graph = flattenDeps(lockData);
      }
      outputChannel.appendLine(`[DepGraph] npm entries: ${Object.keys(graph).length}`);
    }
    else if (fs.existsSync(yarnLock)) {
      // Yarn v1
      const raw    = fs.readFileSync(yarnLock, 'utf8');
      const parsed = parseYarnLock(raw);
      if (parsed.type === 'success') {
        for (const key of Object.keys(parsed.object)) {
          const info = parsed.object[key];
          const pkg  = key.replace(/@[^@]+$/, '');
          graph[pkg] = { version: info.version };
        }
        outputChannel.appendLine(`[DepGraph] yarn entries: ${Object.keys(graph).length}`);
      } else {
        outputChannel.appendLine('[DepGraph] failed — invalid yarn.lock');
      }
    }
    else {
      outputChannel.appendLine('[DepGraph] skipped — no lockfile found');
    }
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[DepGraph] failed — could not parse lockfile');
  }

  outputChannel.appendLine('[DepGraph] done');
  return graph;
}

function flattenDeps(tree, acc = {}) {
  for (const [name, info] of Object.entries(tree.dependencies || {})) {
    acc[name] = { version: info.version };
    flattenDeps(info, acc);
  }
  return acc;
}

function deactivate() {
  clearInterval(refreshInterval);
}

const abortControllers = {};

async function activate(context) {
  outputChannel = vscode.window.createOutputChannel('DepTrack');
  const orig = outputChannel.appendLine.bind(outputChannel);
  outputChannel.appendLine = line => {
    const entry = `[${new Date().toLocaleTimeString()}] ${stripAnsi(line)}`;
    orig(entry);
    logLines.push(entry);
    panel?.webview.postMessage({ command: 'logUpdate', payload: logLines });
  };
  outputChannel.appendLine('activate start');

  // Command to open the dashboard webview
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.openDashboard', () => {
      if (!panel) {
        panel = vscode.window.createWebviewPanel(
          'deptrackDashboard',
          'DepTrack Dashboard',
          vscode.ViewColumn.One,
          {
            enableScripts: true,
            localResourceRoots: [
              vscode.Uri.file(path.join(context.extensionPath, 'src'))
            ]
          }
        );
        webviewPanel = panel;
        panel.webview.html = fs.readFileSync(
          path.join(context.extensionPath, 'src', 'dashboard.html'),
          'utf8'
        );

        panel.webview.onDidReceiveMessage(async msg => {
          outputChannel.appendLine(`Received command: ${msg.command}`);
          try {
            switch (msg.command) {
              // Bulk scans
              case 'refresh':
              case 'scanAll':
                return withAbort('all', runAllChecks);
              case 'scanView':
                return runView(msg.view);

              // Send email
              case 'sendEmail': {
                const cfg = vscode.workspace.getConfiguration('deptrack.email');
                const to = msg.email || cfg.get('to');
                await sendEmailNotification(
                  'DepTrack Scan Results',
                  'Your dependency scan has completed. See your dashboard for details.',
                  to
                );
                break;
              }

              // Send PDF report
              case 'sendReportEmail': {
                const wf = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
                if (!wf) {
                  webviewPanel.webview.postMessage({
                    command: 'emailStatus',
                    success: false,
                    error: 'No workspace open'
                  });
                  break;
                }
                const pdfPath = path.join(wf, 'deptrack-report.pdf');
                if (!fs.existsSync(pdfPath)) {
                  webviewPanel.webview.postMessage({
                    command: 'emailStatus',
                    success: false,
                    error: 'deptrack-report.pdf not found in workspace root'
                  });
                  break;
                }
                const cfg = vscode.workspace.getConfiguration('deptrack.email');
                const to = cfg.get('to');
                await sendEmailNotification(
                  'DepTrack PDF Report',
                  'Attached is the latest DepTrack PDF report.',
                  to,
                  [{ filename: 'deptrack-report.pdf', path: pdfPath }]
                );
                break;
              }

case 'sendCsvReportEmail': {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) {
    webviewPanel.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: 'No workspace open'
    });
    break;
  }
  const csvPath = path.join(workspaceRoot, 'deptrack-report.csv');
  if (!fs.existsSync(csvPath)) {
    webviewPanel.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: 'deptrack-report.csv not found in workspace root'
    });
    break;
  }
  const cfg = vscode.workspace.getConfiguration('deptrack.email');
  const to = cfg.get('to');
  await sendEmailNotification(
    'DepTrack CSV Report',
    'Attached is the latest DepTrack CSV report.',
    to,
    [{ filename: 'deptrack-report.csv', path: csvPath }]
  );
  break;
}

              // Exports & chat
              case 'exportCSV': return exportCsv();
              case 'exportPDF': return exportPdf();
              case 'chat':      return handleChat(msg.text);

              // Individual refresh
              case 'refreshOutdated':    return withAbort('outdated', runOutdated);
              case 'refreshVuln':        return withAbort('vuln', runVuln);
              case 'refreshLicense':     return withAbort('license', runLicenses);
              case 'refreshEslint':      return withAbort('eslint', runESLint);
              case 'refreshDuplication': return withAbort('duplication', runDuplication);
              case 'refreshComplexity':  return withAbort('complexity', runComplexity);
              case 'refreshSecret':      return withAbort('secret', runSecrets);
              case 'refreshDepgraph':    return withAbort('depgraph', runDepGraph);
              case 'refreshFixes':       return withAbort('fixes', runFixes);
              case 'refreshSonar':       return withAbort('sonar', runSonar);

              // Cancellation
              case 'cancelAll':        abortControllers.all?.abort(); break;
              case 'cancelOutdated':   abortControllers.outdated?.abort(); break;
              case 'cancelVuln':       abortControllers.vuln?.abort(); break;
              case 'cancelLicense':    abortControllers.license?.abort(); break;
              case 'cancelEslint':     abortControllers.eslint?.abort(); break;
              case 'cancelDuplication':abortControllers.duplication?.abort(); break;
              case 'cancelComplexity': abortControllers.complexity?.abort(); break;
              case 'cancelSecret':     abortControllers.secret?.abort(); break;
              case 'cancelDepgraph':   abortControllers.depgraph?.abort(); break;
              case 'cancelFixes':      abortControllers.fixes?.abort(); break;
              case 'cancelSonar':      abortControllers.sonar?.abort(); break;

              default:
                outputChannel.appendLine(`Unknown command: ${msg.command}`);
            }
          } catch (err) {
            console.error('[DepTrack] handler error:', err);
            webviewPanel.webview.postMessage({
              command: 'emailStatus',
              success: false,
              error: err.message
            });
          }
        });

        panel.onDidDispose(() => {
          panel = null;
          webviewPanel = null;
        }, null, context.subscriptions);
      }
    })
  );

  // Shortcut commands
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.refresh', () =>
      withAbort('all', runAllChecks)
    ),
    vscode.commands.registerCommand('Aman.deptrack.sendReportEmail', () =>
      vscode.commands
        .executeCommand('Aman.deptrack.openDashboard')
        .then(() => panel.webview.postMessage({ command: 'sendReportEmail' }))
    )
  );

context.subscriptions.push(
  vscode.commands.registerCommand('Aman.deptrack.sendCsvReportEmail', () =>
    vscode.commands.executeCommand('Aman.deptrack.openDashboard').then(() =>
      panel.webview.postMessage({ command: 'sendCsvReportEmail' })
    )
  )
);

  // Open dashboard on startup
  vscode.commands.executeCommand('Aman.deptrack.openDashboard');
  outputChannel.appendLine('activate done');
}

function deactivate() {
  panel = null;
  webviewPanel = null;
}

async function runAllChecks() {
  if (isScanning) return;
  isScanning = true;

  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }

  logLines = [];
  outputChannel.show(true);
  outputChannel.appendLine('runAllChecks start');


  outputChannel.appendLine('-> checkOutdated');
  try {
    outdated = await checkOutdated(ws);
  } catch (e) {
    logError('runAllChecks.checkOutdated', e);
  }

  outputChannel.appendLine('-> checkVuln');
  try {
    vulnPayload = await checkVuln(ws);
  } catch (e) {
    logError('runAllChecks.checkVuln', e);
  }

  outputChannel.appendLine('-> checkLicenses');
  try {
    licenseIssues = await checkLicenses(ws);
  } catch (e) {
    logError('runAllChecks.checkLicenses', e);
  }

  outputChannel.appendLine('-> checkESLint');
  try {
    eslintDetails = await checkESLint(ws);
  } catch (e) {
    logError('runAllChecks.checkESLint', e);
  }

  outputChannel.appendLine('-> checkSonar');
  try {
    sonarResult = await checkSonar(ws);
  } catch (e) {
    logError('runAllChecks.checkSonar', e);
  }

  outputChannel.appendLine('-> checkComplexity');
  try {
    complexity = await checkComplexity(ws);
  } catch (e) {
    logError('runAllChecks.checkComplexity', e);
  }

  outputChannel.appendLine('-> checkDuplication');
  try {
    duplicationDetails = await checkDuplication(ws);
  } catch (e) {
    logError('runAllChecks.checkDuplication', e);
  }

  outputChannel.appendLine('-> scanSecrets');
  try {
    secrets = await scanSecrets(ws);
  } catch (e) {
    logError('runAllChecks.scanSecrets', e);
  }

  outputChannel.appendLine('-> checkDepGraph');
  try {
    depGraph = await checkDepGraph(ws);
  } catch (e) {
    logError('runAllChecks.checkDepGraph', e);
  }

  // build suggested fixes once all data is available
  const suggestedFixes = await getSuggestedFixes({
    outdated,
    vuln: vulnPayload.data,
    licenseIssues,
    eslintDetails,
    duplicationDetails,
    secrets
  });


  latestPayload = {
    outdated,
    vuln: vulnPayload.data,
    vulnError: vulnPayload.error,
    licenseIssues,
    eslintDetails,
    sonarResult,
    complexity,
    duplicationDetails,
    secrets,
    depGraph,
    chatHistory,
    suggestedFixes
  };

  panel?.webview.postMessage({
    command: 'updateData',
    payload: latestPayload
  });

  outputChannel.appendLine('runAllChecks done');
  isScanning = false;
}



async function runOutdated() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runOutdated start');
  try {
    const outdated = await checkOutdated(ws);
    latestPayload.outdated = outdated;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runOutdated', e);
  }
  outputChannel.appendLine('runOutdated done');
  isScanning = false;
}

async function runVuln() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runVuln start');
  try {
    const vulnPayload = await checkVuln(ws);
    latestPayload.vuln = vulnPayload.data;
    latestPayload.vulnError = vulnPayload.error;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runVuln', e);
  }
  outputChannel.appendLine('runVuln done');
  isScanning = false;
}

async function runLicenses() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runLicenses start');
  try {
    const licenseIssues = await checkLicenses(ws);
    latestPayload.licenseIssues = licenseIssues;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runLicenses', e);
  }
  outputChannel.appendLine('runLicenses done');
  isScanning = false;
}

async function runESLint() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runESLint start');
  try {
    const eslintDetails = await checkESLint(ws);
    latestPayload.eslintDetails = eslintDetails;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runESLint', e);
  }
  outputChannel.appendLine('runESLint done');
  isScanning = false;
}

async function runSonar() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runSonar start');
  try {
    const sonarResult = await checkSonar(ws);
    latestPayload.sonarResult = sonarResult;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runSonar', e);
  }
  outputChannel.appendLine('runSonar done');
  isScanning = false;
}

async function runComplexity() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runComplexity start');
  try {
    const complexity = await checkComplexity(ws);
    latestPayload.complexity = complexity;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runComplexity', e);
  }
  outputChannel.appendLine('runComplexity done');
  isScanning = false;
}

async function runDuplication() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runDuplication start');
  try {
    const duplicationDetails = await checkDuplication(ws);
    latestPayload.duplicationDetails = duplicationDetails;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runDuplication', e);
  }
  outputChannel.appendLine('runDuplication done');
  isScanning = false;
}

async function runSecrets() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runSecrets start');
  try {
    const secrets = await scanSecrets(ws);
    latestPayload.secrets = secrets;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runSecrets', e);
  }
  outputChannel.appendLine('runSecrets done');
  isScanning = false;
}

async function runDepGraph() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runDepGraph start');
  try {
    const depGraph = await checkDepGraph(ws);
    latestPayload.depGraph = depGraph;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runDepGraph', e);
  }
  outputChannel.appendLine('runDepGraph done');
  isScanning = false;
}

async function runFixes() {
  if (isScanning) return;
  isScanning = true;
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    isScanning = false;
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine('runFixes start');
  try {
    const fixes = await getSuggestedFixes({
      outdated: latestPayload.outdated,
      vuln: latestPayload.vuln,
      licenseIssues: latestPayload.licenseIssues,
      eslintDetails: latestPayload.eslintDetails,
      duplicationDetails: latestPayload.duplicationDetails,
      secrets: latestPayload.secrets
    });
    latestPayload.suggestedFixes = fixes;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runFixes', e);
  }
  outputChannel.appendLine('runFixes done');
  isScanning = false;
}


// Updated checkOutdated: treats npm outdated exit-code 1 as normal, cleans up logging
async function checkOutdated(ws) {
  const fn = 'checkOutdated';
  const npm = resolveCmd(ws, 'npm');
  const res = {};
  const pkgJson = path.join(ws, 'package.json');

  if (!npm) {
    outputChannel.appendLine('[Outdated] skipped — npm not found');
    return res;
  }
  if (!fs.existsSync(pkgJson)) {
    outputChannel.appendLine('[Outdated] skipped — no package.json');
    return res;
  }

  outputChannel.appendLine('[Outdated] start');
  let raw = '';
  try {
    const { stdout } = await execP(`"${npm}" outdated --json`, { cwd: ws, maxBuffer: 52428800 });
    raw = stdout.trim();
  } catch (e) {
    // exit code >0 may simply indicate outdated packages
    raw = (e.stdout || '').trim();
    if (!raw) {
      logError(fn, e);
      outputChannel.appendLine('[Outdated] done');
      return res;
    }
  }

  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[Outdated] JSON parse failed');
    outputChannel.appendLine('[Outdated] done');
    return res;
  }

  for (const [pkg, info] of Object.entries(data)) {
    const diff = semver.diff(info.current, info.latest);
    res[pkg] = {
      current: info.current,
      latest:  info.latest,
      status:  diff === 'major' ? 'critical' : diff === 'minor' ? 'warning' : 'good'
    };
  }

  const count = Object.keys(res).length;
  if (!count) {
    outputChannel.appendLine('[Outdated] none found');
  } else {
    outputChannel.appendLine(`[Outdated] found ${count} outdated package${count > 1 ? 's' : ''}`);
  }
  outputChannel.appendLine('[Outdated] done');
  return res;
}


// Updated checkVuln: treats Snyk exit-code 1 as normal, silences raw snippet logs

async function checkVuln(ws) {
  const fn = 'checkVuln'
  const snyk = resolveCmd(ws, 'snyk')
  const npm  = resolveCmd(ws, 'npm')
  const res  = {}
  let vulnError = null
  const pkgJson = path.join(ws, 'package.json')

  if (!fs.existsSync(pkgJson)) {
    outputChannel.appendLine('[Vuln] skipped — no package.json')
    return { data: res, error: null }
  }

  // pull the token from process.env (dotenv has already loaded it)
  const token = process.env.SNYK_TOKEN
  if (!token) {
    outputChannel.appendLine('[Vuln] warning — SNYK_TOKEN not set in environment')
  }

  // common exec options, injecting our full process.env (which includes SNYK_TOKEN)
  const execOpts = {
    cwd: ws,
    maxBuffer: 52428800,
    env: { ...process.env }
  }

  outputChannel.appendLine('[Vuln] start')
  let payload = null

  if (snyk) {
    try {
      // The Snyk CLI will automatically read SNYK_TOKEN from the environment
      const { stdout } = await execP(`"${snyk}" test --json`, execOpts)
      payload = JSON.parse(stdout)
    } catch (e) {
      const raw = e.stdout || ''
      if (raw) {
        try {
          payload = JSON.parse(raw)
        } catch (pe) {
          vulnError = `Snyk JSON parse failed: ${pe.message}`
        }
      } else {
        vulnError = `Snyk failed: ${stripAnsi(e.stderr || e.message)}`
      }
    }
  }

  if (!payload && npm) {
    try {
      const { stdout } = await execP(`"${npm}" audit --json`, execOpts)
      payload = JSON.parse(stdout)
    } catch (e) {
      const raw = e.stdout || ''
      if (raw) {
        try {
          payload = JSON.parse(raw)
        } catch (pe) {
          vulnError = `npm audit JSON parse failed: ${pe.message}`
        }
      } else {
        vulnError = `npm audit failed: ${stripAnsi(e.stderr || e.message)}`
      }
    }
  }

  if (payload && typeof payload === 'object') {
    const list = Array.isArray(payload.vulnerabilities)
               ? payload.vulnerabilities
               : Object.values(payload.vulnerabilities || {})
    outputChannel.appendLine(`[Vuln] total vulnerabilities: ${list.length}`)
    for (const v of list) {
      const pkgName = v.packageName || v.name || v.module_name
      const severity = (v.severity || v.cvssScore || 'unknown').toString().toLowerCase()
      const title    = v.title || v.overview || ''
      ;(res[pkgName] ||= []).push({ severity, title })
    }
  } else if (vulnError) {
    outputChannel.appendLine(`[Vuln] error: ${vulnError}`)
  }

  if (!Object.keys(res).length && !vulnError) {
    outputChannel.appendLine('[Vuln] none found')
  }
  outputChannel.appendLine('[Vuln] done')
  return { data: res, error: vulnError }
}


async function checkLicenses(ws) {
  const fn = 'checkLicenses';
  outputChannel.appendLine('[License] start');
  const tool = resolveCmd(ws, 'license-checker');
  if (!tool) { outputChannel.appendLine('[License] skipped'); outputChannel.appendLine('[License] done'); return []; }
  let res = [];
  try {
    outputChannel.appendLine('[License] running');
    const { stdout } = await execP(`"${tool}" --json`, { cwd: ws });
    const data = JSON.parse(stdout);
    for (const [pkg, info] of Object.entries(data)) {
      const ls = info.licenses ? (Array.isArray(info.licenses) ? info.licenses : [info.licenses]) : ['UNKNOWN'];
      const bad = ls.filter(l => forbiddenLicenses.some(f => l.toUpperCase().includes(f)));
      if (bad.length) res.push({ pkg, licenses: bad });
    }
  } catch (e) {
    logError(fn, e);
  }
  if (!res.length) outputChannel.appendLine('[License] none');
  outputChannel.appendLine('[License] done');
  return res;
}

// ─── checkESLint (shell-out to ESLint CLI) ───────────────────────────────────
async function checkESLint(ws) {
  const fn = 'checkESLint';
  outputChannel.appendLine('[ESLint] start');

  // 1) Glob patterns and ignore folders
  const patterns = ['**/*.{js,jsx,ts,tsx}'];
  const ignore   = ['node_modules/**', 'dist/**', 'report/**', 'coverage/**', 'deptrack/**', 'media/**', 'cleaned/**'];
  outputChannel.appendLine(`[ESLint] glob patterns: ${patterns}`);
  outputChannel.appendLine(`[ESLint] ignores: ${ignore}`);

  let files;
  try {
    files = await fg(patterns, { cwd: ws, onlyFiles: true, absolute: true, ignore });
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[ESLint] error resolving files');
    outputChannel.appendLine('[ESLint] done');
    return [];
  }

  if (!files.length) {
    outputChannel.appendLine('[ESLint] no files to scan');
    outputChannel.appendLine('[ESLint] done');
    return [];
  }
  files.forEach(f => outputChannel.appendLine(`[ESLint] will lint: ${path.relative(ws, f)}`));

  // 2) Locate ESLint binary
  const binName   = process.platform === 'win32' ? 'eslint.cmd' : 'eslint';
  const localBin  = path.join(ws, 'node_modules', '.bin', binName);
  const eslintBin = fs.existsSync(localBin) ? `"${localBin}"` : 'eslint';
  outputChannel.appendLine(`[ESLint] using binary: ${eslintBin}`);

  // 3) Build and run CLI command pointing at our CJS config
  const configFile = path.join(ws, 'eslint.config.cjs');
  const args = [
    `-c "${configFile}"`,   // CommonJS config
    '-f json',
    ...files.map(f => `"${f}"`)
  ].join(' ');
  const cmd = `${eslintBin} ${args}`;
  outputChannel.appendLine(`[ESLint] running: ${cmd}`);

  let raw = '';
  try {
    const { stdout, stderr } = await execP(cmd, { cwd: ws, maxBuffer: 20 * 1024 * 1024 });
    raw = (stdout || '').trim() || (stderr || '').trim();
  } catch (e) {
    raw = (e.stdout || '').trim() || (e.stderr || '').trim();
  }

  if (!raw) {
    outputChannel.appendLine('[ESLint] no output received');
    outputChannel.appendLine('[ESLint] done');
    return [];
  }

  // 4) Extract JSON and parse
  const first = raw.indexOf('[');
  const last  = raw.lastIndexOf(']');
  const jsonText = first >= 0 && last > first ? raw.slice(first, last + 1) : '';
  if (!jsonText) {
    outputChannel.appendLine('[ESLint] no valid JSON block found');
    outputChannel.appendLine('[ESLint] done');
    return [];
  }

  let results;
  try {
    results = JSON.parse(jsonText);
  } catch (pe) {
    logError(fn, pe);
    outputChannel.appendLine('[ESLint] JSON parse failed');
    outputChannel.appendLine('[ESLint] done');
    return [];
  }

  // 5) Flatten results for the dashboard
  const res = [];
  for (const fileResult of results) {
    const rel = path.relative(ws, fileResult.filePath);
    if (/^(node_modules|dist|report|coverage|deptrack)[\/\\]/.test(rel)) continue;
    outputChannel.appendLine(`[ESLint] checked: ${rel}, issues: ${fileResult.messages.length}`);
    for (const msg of fileResult.messages) {
      res.push({
        file:    rel,
        line:    msg.line,
        rule:    msg.ruleId,
        message: msg.message
      });
    }
  }

  if (!res.length) outputChannel.appendLine('[ESLint] none detected');
  outputChannel.appendLine('[ESLint] done');
  return res;
}


async function checkSonar(ws) {
  // 1) Run SonarLint
  const lintBin = resolveCmd(ws, 'sonarlint');
  const srcDir  = path.join(ws, 'src');
  if (!lintBin || !fs.existsSync(srcDir)) {
    outputChannel.appendLine('[SonarLint] skipped — SonarLint or src/ missing');
    return { passed: true, summary: 'Skipped', metrics: {} };
  }

  outputChannel.appendLine('[SonarLint] start');
  let stdout = '';
  try {
    ({ stdout } = await execP(
      `"${lintBin}" analyze --src "${srcDir}"`,
      { cwd: ws, maxBuffer: 200 * 1024 * 1024, env: { ...process.env } }
    ));
  } catch (e) {
    stdout = e.stdout || '';
  }

  // 2) Parse only the “INFO: […]” lines
  const issues = stdout
    .split(/\r?\n/)
    .filter(l => /^\s*INFO: \[/.test(l))
    .map(l => {
      const txt = l.replace(/^\s*INFO:\s*/, '');
      const m = txt.match(
        /^\[([^\]]+)\]\s+(.+?):(\d+)(?::\d+)?\s+(\S+)\s*[-–]\s*(.*)$/
      );
      return m && { severity: m[1].toUpperCase() };
    })
    .filter(Boolean);

  const counts = issues.reduce((acc, { severity }) => {
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  // 3) Run jscpd for duplication
let dupPct = '—';
try {
  const { stdout } = await execP(
    `npx jscpd --silent --format json src`,
    { cwd: ws, env: { ...process.env }, maxBuffer: 200 * 1024 * 1024 }
  );

  // Safely extract only the JSON
  const firstBrace = stdout.indexOf('{');
  const lastBrace  = stdout.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace !== -1) {
    const jsonPart = stdout.slice(firstBrace, lastBrace + 1);
    const dupReport = JSON.parse(jsonPart);
    dupPct = dupReport.statistics?.total?.percentage ?? '—';
  } else {
    outputChannel.appendLine('[SonarLint] jscpd: no JSON found');
  }
} catch (err) {
  outputChannel.appendLine(`[SonarLint] jscpd failed: ${err.message}`);
}

  // 4) Determine pass/fail
  const high = (counts.BLOCKER||0) + (counts.CRITICAL||0) + (counts.MAJOR||0);
  const passed  = high === 0;
  const summary = passed
    ? '✅ No BLOCKER/CRITICAL/MAJOR issues'
    : `❌ ${high} high-severity issue${high>1?'s':''} found`;

  outputChannel.appendLine(`[SonarLint] total issues: ${issues.length}`);
  outputChannel.appendLine(`[SonarLint] ${summary}`);
  outputChannel.appendLine('[SonarLint] done');

  return {
    passed,
    summary,
    metrics: {
      bugs:                      counts.BLOCKER        || 0,
      vulnerabilities:           counts.CRITICAL       || 0,
      code_smells:               counts.MAJOR          || 0,
      duplicated_lines_density:  dupPct
    }
  };
}




async function checkComplexity(ws) {
  const fn = 'checkComplexity';
  outputChannel.appendLine('[Complexity] start');

  // 1) find the plato binary
  const tool = resolveCmd(ws, 'plato');
  if (!tool) {
    outputChannel.appendLine(
      "[Complexity] skipped — 'plato' not found; install with 'npm install --save-dev plato'"
    );
    outputChannel.appendLine('[Complexity] done');
    return [];
  }

  // 2) prepare the report directory
  const reportDir = path.join(ws, 'report', 'plato');
  fs.mkdirSync(reportDir, { recursive: true });

  // 3) run plato
  const cmd = `"${tool}" -r -d "${reportDir}" src`;
  try {
    await execP(cmd, { cwd: ws, maxBuffer: 209715200 });

    const reportFile = path.join(reportDir, 'report.json');
    if (!fs.existsSync(reportFile)) {
      outputChannel.appendLine(
        "[Complexity] no report.json found — did Plato actually run?"
      );
      outputChannel.appendLine('[Complexity] done');
      return [];
    }

    // 4) parse the JSON
    const raw  = fs.readFileSync(reportFile, 'utf8');
    const data = JSON.parse(raw);

    // 5) map over data.reports (always an array)
    const reports = Array.isArray(data.reports) ? data.reports : [];
    const results = reports.map(r => {
      const comp = r.complexity || {};
      const sloc = comp.sloc || {};

      // pick the logical SLOC if present, else physical, else 0
      const logicalSLOC =
        typeof sloc.logical === 'number'
          ? sloc.logical
          : typeof sloc.physical === 'number'
          ? sloc.physical
          : 0;

      return {
        path: path.relative(ws, r.info.file || ''),
        aggregate: {
          cyclomatic:      typeof comp.cyclomatic     === 'number' ? comp.cyclomatic     : 0,
          sloc:            logicalSLOC,
          maintainability: typeof comp.maintainability === 'number' ? comp.maintainability : 0
        }
      };
    });

    if (!results.length) {
      outputChannel.appendLine('[Complexity] none detected');
    }

    return results;
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine(
      "[Complexity] failed — check that 'plato' is installed and your source directory exists"
    );
    return [];
  } finally {
    outputChannel.appendLine('[Complexity] done');
  }
}
	
// ─── DUPLICATION SCAN ───────────────────────────────────────────────────────────


async function checkDuplication(ws) {
  const fn = 'checkDuplication';
  outputChannel.appendLine('[Duplication] start');

  // 1) Normalize to forward-slashes
  const projectRoot = ws.replace(/\\/g, '/');

  // 2) Build glob patterns against that
  const patterns = [
    `${projectRoot}/*.js`,
    `${projectRoot}/*.ts`,
    `${projectRoot}/src/**/*.js`,
    `${projectRoot}/src/**/*.ts`
  ];
  outputChannel.appendLine(`[Duplication] glob patterns: ${patterns.join(', ')}`);

  let files;
  try {
    files = await fg(patterns, { absolute: true, onlyFiles: true });
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[Duplication] error resolving files');
    outputChannel.appendLine('[Duplication] done');
    return [];
  }

  if (!files.length) {
    outputChannel.appendLine('[Duplication] no files to scan');
    outputChannel.appendLine('[Duplication] done');
    return [];
  }

  // 3) Log each file
  files.forEach(f => {
    const rel = path.relative(ws, f);
    outputChannel.appendLine(`[Duplication] checking file: ${rel}`);
  });

  // 4) Run jsinspect
  const inspector = resolveCmd(ws, 'jsinspect') || 'npx jsinspect';
  const threshold = 3;
  const fileArgs  = files.map(f => `"${f}"`).join(' ');
  const cmd       = `${inspector} --identical --threshold ${threshold} --reporter json ${fileArgs}`;

  let raw = '';
  try {
    outputChannel.appendLine(`[Duplication] running: ${cmd}`);
    const { stdout, stderr } = await execP(cmd, { cwd: ws, maxBuffer: 524288000 });
    raw = (stdout || '').trim() || (stderr || '').trim();
  } catch (e) {
    raw = (e.stdout || '').trim() || (e.stderr || '').trim();
  }

  outputChannel.appendLine(`[Duplication] raw output:\n${raw}`);

  // 5) Parse JSON
  const idx      = raw.indexOf('[');
  const jsonText = idx >= 0 ? raw.slice(idx) : raw;
  let matches;
  try {
    matches = JSON.parse(jsonText);
  } catch (pe) {
    logError(fn, pe);
    outputChannel.appendLine('[Duplication] parse failed');
    outputChannel.appendLine('[Duplication] done');
    return [];
  }

  // 6) Format results
  const res = [];
  for (const m of matches) {
    const inst = m.instances || [];
    for (let i = 0; i < inst.length; i++) {
      for (let j = i + 1; j < inst.length; j++) {
        res.push({
          fileA: path.relative(ws, inst[i].path),
          lineA: inst[i].lines[0],
          fileB: path.relative(ws, inst[j].path),
          lineB: inst[j].lines[0]
        });
      }
    }
  }

  if (!res.length) outputChannel.appendLine('[Duplication] none');
  outputChannel.appendLine('[Duplication] done');
  return res;
}

async function handleChat(text) {
  chatHistory.push({ from: 'You', text });
  const cfg    = vscode.workspace.getConfiguration('deptrack.chatbot');
  const apiKey = cfg.get('apiKey');
  const model  = cfg.get('model') || 'gpt-3.5-turbo';
  let reply = '';
  if (!apiKey) {
    reply = '❌ Set API key';
  } else {
    try {
      const res = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        { model, messages: [{ role: 'user', content: text }] },
        { headers: { Authorization: `Bearer ${apiKey}` } }
      );
      reply = res.data.choices[0].message.content.trim();
    } catch (e) {
      logError('handleChat', e);
      reply = '❌ Chat error';
    }
  }
  chatHistory.push({ from: 'Bot', text: reply });
  panel && panel.webview.postMessage({ command: 'chatResponse', payload: { text: reply } });
}

async function getSuggestedFixes({
  outdated = {},
  vuln = {},
  licenseIssues = [],
  eslintDetails = [],
  duplicationDetails = [],
  secrets = []
}) {
  const fixes = [];

  // 1) Outdated packages
  for (const [pkg, info] of Object.entries(outdated)) {
    fixes.push({
      pkg,
      fix: `Update to ${info.latest}`
    });
  }

  // 2) Vulnerabilities
  for (const [pkg, list] of Object.entries(vuln)) {
    list.forEach(v => {
      // if Snyk already suggests "patch" or "upgrade", use that; otherwise offer generic advice
      const suggestion = /upgrade to ([\d.]+)/i.exec(v.title)
        ? `Upgrade to ${RegExp.$1}`
        : v.title.startsWith('Insecure')
          ? `Review & patch vulnerability`
          : `Review vulnerability: "${v.title}"`;
      fixes.push({ pkg, fix: suggestion });
    });
  }

  // 3) Forbidden‐license issues
  licenseIssues.forEach(x => {
    fixes.push({
      pkg: x.pkg,
      fix: `Consider replacing or upgrading (forbidden: ${x.licenses.join(', ')})`
    });
  });

  // 4) ESLint issues
  // Group by file: if any errors exist, recommend full auto‐fix; else suggest specific rule
  const eslintByFile = eslintDetails.reduce((acc, e) => {
    (acc[e.file] ||= []).push(e);
    return acc;
  }, {});
  for (const [file, msgs] of Object.entries(eslintByFile)) {
    fixes.push({
      pkg: file,
      fix: msgs.some(m => m.rule && m.rule !== 'semi')
        ? `Run \`eslint --fix "${file}"\``
        : `Add missing semicolons (rule: semi)`
    });
  }

  // 5) Secret leaks
  secrets.forEach(s => {
    fixes.push({
      pkg: s.file,
      fix: `Remove hard‐coded ${s.rule} and inject via secure env variable`
    });
  });

  // 6) Code duplication
  // For each pair, suggest function extraction
  duplicationDetails.forEach(d => {
    fixes.push({
      pkg: `${d.fileA} & ${d.fileB}`,
      fix: `Extract common logic at lines ${d.lineA}/${d.lineB} into shared function`
    });
  });

  // 7) (Optional) Complexity
  // If you want to flag super‐complex files, e.g. cyclomatic > 10, you could:
  // complexity.forEach(c => { ... });

  return fixes;
}




let webviewPanel; // you’ll need to set this when you create your WebviewPanel

async function sendEmailNotification(subject, text, overrideTo, attachments = []) {
  const cfg = vscode.workspace.getConfiguration('deptrack.email');
  const user = cfg.get('auth.user');
  const pass = cfg.get('auth.pass');
  const defaultTo = cfg.get('to');
  const service = cfg.get('service') || 'gmail';
  const to = overrideTo || defaultTo;

  console.log('[DepTrack] sendEmailNotification config →', {
    service, user, hasPass: !!pass, to, subject, text, attachments
  });

  if (!user || !pass || !to) {
    const msg = 'Missing email configuration: auth.user, auth.pass, and to must all be set.';
    console.error('[DepTrack] ' + msg);
    webviewPanel?.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: msg
    });
    return;
  }

  const transporter = nodemailer.createTransport({ service, auth: { user, pass } });
  try {
    const mailOptions = { from: user, to, subject, text };
    if (attachments.length) mailOptions.attachments = attachments;
    const info = await transporter.sendMail(mailOptions);
    console.log('[DepTrack] Email sent:', info.messageId);
    webviewPanel.webview.postMessage({ command: 'emailStatus', success: true });
  } catch (err) {
    console.error('[DepTrack] sendMail error:', err);
    webviewPanel.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: err.message
    });
  }
}

/**
 * Helper to run a check with an AbortSignal
 */
function withAbort(viewName, checkFn) {
  const controller = new AbortController();
  abortControllers[viewName] = controller;
  return checkFn(controller.signal);
}
// Example: hook up your message handler so that `sendEmail` command invokes this
function registerMessageListener(panel) {
  webviewPanel = panel;  // capture your WebviewPanel instance
panel.webview.onDidReceiveMessage(async message => {
  try {
    if (message.command === 'sendEmail') {
      const subject = 'DepTrack Scan Results';
      const text    = 'Your dependency scan has completed.';
      await sendEmailNotification(subject, text, message.email);
    }
    // …other commands…
  } catch (err) {
    console.error('[DepTrack] handler error:', err);
    panel.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: err.message
    });
  }
});

}

module.exports = {
  activate(context) {
    // ... create your WebviewPanel, then:
    const panel = vscode.window.createWebviewPanel(/* … */);
    registerMessageListener(panel);
    // …
  }
};

function exportCsv() {
  if (!latestPayload) return;
  try {
    const ws  = vscode.workspace.workspaceFolders[0].uri.fsPath;
    let csv    = 'Category,Name,Details\n';

    // Outdated packages
    Object.entries(latestPayload.outdated   || {}).forEach(([pkg, info]) => {
      csv += `Outdated,${pkg},"${info.current}→${info.latest}"\n`;
    });

    // Vulnerabilities
    Object.entries(latestPayload.vuln       || {}).forEach(([pkg, list]) =>
      list.forEach(v => {
        csv += `Vulnerability,${pkg},"${v.severity}: ${v.title.replace(/"/g,'""')}"\n`;
      })
    );

    // License issues
    (latestPayload.licenseIssues            || []).forEach(x => {
      csv += `License,${x.pkg},"${x.licenses.join(',')}"\n`;
    });

    // ESLint warnings/errors
    (latestPayload.eslintDetails            || []).forEach(e => {
      csv += `ESLint,${e.file}:${e.line},"${e.rule}: ${e.message.replace(/"/g,'""')}"\n`;
    });

    // Duplication
    (latestPayload.duplicationDetails       || []).forEach(d => {
      csv += `Duplication,${d.fileA}:${d.lineA},${d.fileB}:${d.lineB}\n`;
    });

    // Complexity metrics
    (latestPayload.complexity               || []).forEach(c => {
      csv += `Complexity,${c.path},"Cyclomatic ${c.aggregate.cyclomatic}, SLOC ${c.aggregate.sloc}, Maintainability ${c.aggregate.maintainability}"\n`;
    });

    // Secrets found
    (latestPayload.secrets                  || []).forEach(s => {
      csv += `Secret,${s.file}:${s.line},"${s.rule}: ${s.match.replace(/"/g,'""')}"\n`;
    });

    // Dependency graph (major versions)
    Object.entries(latestPayload.depGraph    || {}).forEach(([name, info]) => {
      csv += `Dependency,${name},"v${info.version}"\n`;
    });

    // Sonar summary
    if (latestPayload.sonarResult?.summary) {
      csv += `Sonar Summary, , "${latestPayload.sonarResult.summary.replace(/"/g,'""')}"\n`;
    }

    // Sonar metrics
    const metrics = latestPayload.sonarResult?.metrics || {};
    Object.entries(metrics).forEach(([key, val]) => {
      csv += `Sonar Metric,${key},"${val}"\n`;
    });

    // Suggested fixes
    (latestPayload.suggestedFixes          || []).forEach(f => {
      csv += `Suggested Fix,${f.pkg},"${f.fix.replace(/"/g,'""')}"\n`;
    });

    // Chat history
    (latestPayload.chatHistory              || []).forEach(c => {
      const text = c.text.replace(/"/g, '""');
      csv += `Chat,${c.from},"${text}"\n`;
    });

    // Any test files (if you populate latestPayload.testFiles)
    (latestPayload.testFiles                || []).forEach(f => {
      csv += `Test File, , "${f}"\n`;
    });

    // Write out
    const uri = vscode.Uri.file(path.join(ws, 'deptrack-report.csv'));
    vscode.workspace.fs.writeFile(uri, Buffer.from(csv, 'utf8'));
    vscode.window.showInformationMessage('DepTrack CSV report written to deptrack-report.csv');
  } catch (e) {
    logError('exportCsv', e);
  }
}

function withAbort(viewName, checkFn) {
  const controller = new AbortController();
  abortControllers[viewName] = controller;
  return checkFn(controller.signal);
}

function exportPdf() {
  if (!latestPayload) return;
  try {
    const ws  = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const out = path.join(ws,'deptrack-report.pdf');
    const doc = new PDFDocument({ margin: 40 });
    doc.pipe(fs.createWriteStream(out));
    doc.fontSize(20).text('DepTrack Report').moveDown(1);
    const section = t => doc.fontSize(16).text(t,{ underline:true }).moveDown(0.5);
    const item    = t => doc.fontSize(12).text(`• ${t}`).moveDown(0.2);
    section('Outdated Packages');
    Object.entries(latestPayload.outdated || {}).forEach(([p,i]) => item(`${p}: ${i.current}→${i.latest}`));
    section('Vulnerabilities');
    Object.entries(latestPayload.vuln || {}).forEach(([p,list]) => list.forEach(v => item(`${p}: [${v.severity}] ${v.title}`)));
    if (latestPayload.vulnError) item(`Error: ${latestPayload.vulnError}`);
    section('Forbidden Licenses');
    (latestPayload.licenseIssues || []).forEach(x => item(`${x.pkg}: ${x.licenses.join(', ')}`));
    section('ESLint Issues');
    (latestPayload.eslintDetails || []).forEach(e => item(`${e.file}:${e.line}[${e.rule}] ${e.message}`));
    section('Sonar Summary');
    item(latestPayload.sonarResult.summary);
    section('Sonar Metrics');
    const m = latestPayload.sonarResult.metrics || {};
    item(`Bugs: ${m.bugs}`);
    item(`Vulnerabilities: ${m.vulnerabilities}`);
    item(`Code Smells: ${m.code_smells}`);
    item(`Coverage: ${m.coverage}`);
    item(`Duplication %: ${m.duplicated_lines_density}`);
    section('Code Duplication');
    (latestPayload.duplicationDetails || []).forEach(d => item(`${d.fileA}:${d.lineA} ↔ ${d.fileB}:${d.lineB}`));
    section('Secrets');
    (latestPayload.secrets || []).forEach(s => item(`${s.file}:${s.line}[${s.rule}] ${s.match}`));
    section('Test Files');
    (latestPayload.testFiles || []).forEach(f => item(f));
    section('Chat History');
    (latestPayload.chatHistory || []).forEach(c => item(`${c.from}: ${c.text}`));
    doc.end();
  } catch (e) {
    logError('exportPdf', e);
  }
}

module.exports = { activate, deactivate };
