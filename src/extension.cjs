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
const { Configuration, OpenAIApi } = require('openai');
const fetch = require('node-fetch');
const { Linter } = require("eslint");

// defaults to “all files”:
let latestEslintScope = 'src';


const HF_HUB_TOKEN = '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';

if (!HF_HUB_TOKEN) {
  console.warn('⚠️  HF_HUB_TOKEN is not set! Check your .env.');
}
const HF_MODEL      = 'microsoft/DialoGPT-medium';
const HF_URL        = `https://api-inference.huggingface.co/models/${HF_MODEL}`;
// keep the user’s last selection for the industry-standard check
let latestEslintIndustryScope = '.';


  
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

let sessionHistory = [];

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
  suggestedFixes: [],
  
};

function logError(fnName, err) {
  if (err && err.name === 'AbortError') return;	
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

const abortControllers = {};


let extensionContext;
async function activate(context) {
 const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  extensionContext = context;

  // 1) Create and wrap your output channel for logging
  outputChannel = vscode.window.createOutputChannel('DepTrack');
  const origAppend = outputChannel.appendLine.bind(outputChannel);
  outputChannel.appendLine = line => {
    const entry = `[${new Date().toLocaleTimeString()}] ${stripAnsi(line)}`;
    origAppend(entry);
    logLines.push(entry);
    panel?.webview.postMessage({ command: 'logUpdate', payload: logLines });
  };
  outputChannel.appendLine('activate start');


  // 3) Open the Dashboard panel (creation & message handling)
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.openDashboard', async () => {
      if (panel) {
        panel.reveal();
        return;
      }

      panel = vscode.window.createWebviewPanel(
        'deptrackDashboard',
        'DepTrack Dashboard',
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, 'src'))]
        }
      );
      webviewPanel = panel;

      panel.webview.html = fs.readFileSync(
        path.join(context.extensionPath, 'src', 'dashboard.html'),
        'utf8'
      );

      // Debug test message
      outputChannel.appendLine('⏪ Sending test to webview');
      panel.webview.postMessage({ command: 'chatResponse', text: '🔥 Test message!' });

      // Handle incoming messages
   panel.webview.onDidReceiveMessage(async m => {
  outputChannel.appendLine(`Received command: ${m.command}`);
  try {
    switch (m.command) {
      case 'refresh':
      case 'scanAll':
        return withAbort('all', runAllChecks);

      case 'scanView':
        return runView(m.view);


      // ─── Send a plain “scan results” email ───────────────────────────────────
      case 'sendEmail': {
        // If the user typed a custom “to:”, we’ll still honor it; otherwise
        // sendEmailNotification will fall back to your hard-coded address.
        const overrideTo = m.email;  
        return sendEmailNotification(
          'DepTrack Scan Results',
          'Your dependency scan has completed. See your dashboard for details.',
          overrideTo
        );
      }

      // ─── Send the PDF report as an attachment ────────────────────────────────
  case 'sendReportEmail': {
      const overrideTo = m.email;
      const wf = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!wf) {
        panel.webview.postMessage({ command: 'emailStatus', success: false, error: 'No workspace open' });
        break;
      }
      const pdfPath = path.join(wf, 'deptrack-report.pdf');
      if (!fs.existsSync(pdfPath)) {
        panel.webview.postMessage({ command: 'emailStatus', success: false, error: 'PDF not found' });
        break;
      }
      return sendEmailNotification(
        'DepTrack PDF Report',
        'Attached is the latest DepTrack PDF report.',
        overrideTo,
        [{ filename: 'deptrack-report.pdf', path: pdfPath }]
      );
    }

    case 'sendCsvReportEmail': {
      const overrideTo = m.email;
      const wf = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!wf) {
        panel.webview.postMessage({ command: 'emailStatus', success: false, error: 'No workspace open' });
        break;
      }
      const csvPath = path.join(wf, 'deptrack-report.csv');
      if (!fs.existsSync(csvPath)) {
        panel.webview.postMessage({ command: 'emailStatus', success: false, error: 'CSV not found' });
        break;
      }
      return sendEmailNotification(
        'DepTrack CSV Report',
        'Attached is the latest DepTrack CSV report.',
        overrideTo,
        [{ filename: 'deptrack-report.csv', path: csvPath }]
      );
    }	  
      case 'exportCSV':
        return exportCsv();

      case 'exportPDF':
        return exportPdf();

  case 'updatePackage': {
  const pkg = m.pkg;
  if (!workspaceRoot) {
    outputChannel.appendLine(`❌ Cannot update ${pkg}: no workspace open`);
    break;
  }
  try {
    const { stdout, stderr } = await execP(
      `npm install ${pkg}@latest`,
      { cwd: workspaceRoot }
    );
    outputChannel.appendLine(`✅ Updated ${pkg}:\n${stdout}`);
    if (stderr) outputChannel.appendLine(stderr);

    // <-- NEW: immediately re‐run the outdated scan
    await withAbort('outdated', runOutdated);
  } catch (err) {
    const msg = err.stderr || err.message || err;
    outputChannel.appendLine(`❌ Failed to update ${pkg}: ${msg}`);
    panel.webview.postMessage({
      command: 'updateFailed',
      pkg,
      error: msg
    });
  }
  break;
}


      case 'chat': {
        const text = m.text?.trim();
        if (!text) {
          panel.webview.postMessage({ command: 'chatResponse', text: 'Please enter a message.' });
          break;
        }
        try {
          const botText = await getFreeChatResponse(text);
          panel.webview.postMessage({ command: 'chatResponse', text: botText });
        } catch (err) {
          console.error('Chat error:', err);
          panel.webview.postMessage({ command: 'chatResponse', text: '😞 Something went wrong.' });
        }
        break;
      }

      case 'applyDuplicationThreshold': {
        const threshold = m.threshold;
        extensionContext.workspaceState.update('dupThreshold', threshold);
        runDuplicationScanWithThreshold(threshold);
        break;
      }

      case 'refreshOutdated':
        return withAbort('outdated', runOutdated);

      case 'refreshVuln':
        return withAbort('vuln', runVuln);

      case 'refreshLicense':
        return withAbort('license', runLicenses);


      // ─── refreshEslint handler ───────────────────────────────────────────────────
    case 'refreshEslint': {
      // pull the scope from the dropdown (either 'src' or '.')
       // remember the user’s latest choice
    latestEslintScope = m.scope || '.';

    const scope = latestEslintScope;
      outputChannel.appendLine(`[refreshEslint] scope=${scope}`);

      // delegate to runESLint, passing scope through
      return withAbort('eslint', signal =>
        runESLint(signal, scope)
      );
    }
	
	
	   // ─── refreshEslintIndustry handler ────────────────────────────────────────────
    case 'refreshEslintIndustry': {
      // pull the scope from the dropdown (either 'src' or '.')
      latestEslintIndustryScope = m.scope || '.';

      const scope = latestEslintIndustryScope;
      outputChannel.appendLine(`[refreshEslintIndustry] scope=${scope}`);

      // delegate to runIndustryESLint, passing scope through
      return withAbort('eslintIndustry', signal =>
        runIndustryESLint(signal, scope)
      );
    }
	
      case 'refreshDuplication':
        return withAbort('duplication', runDuplication);

      case 'refreshComplexity':
        return withAbort('complexity', runComplexity);

      case 'refreshSecret':
        return withAbort('secret', runSecrets);

      case 'refreshDepgraph':
        return withAbort('depgraph', runDepGraph);

      case 'refreshFixes':
        return withAbort('fixes', runFixes);

case 'refreshSonar': {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  return withAbort('sonar', (signal) => runSonar(ws, signal));
}



      case 'cancelAll':
        abortControllers.all?.abort();
        break;

      case 'cancelOutdated':
        abortControllers.outdated?.abort();
        break;

      case 'cancelVuln':
        abortControllers.vuln?.abort();
        break;

      case 'cancelLicense':
        abortControllers.license?.abort();
        break;

      case 'cancelEslint':
        abortControllers.eslint?.abort();
        break;

      case 'cancelDuplication':
        abortControllers.duplication?.abort();
        break;

      case 'cancelComplexity':
        abortControllers.complexity?.abort();
        break;

      case 'cancelSecret':
        abortControllers.secret?.abort();
        break;

      case 'cancelDepgraph':
        abortControllers.depgraph?.abort();
        break;

      case 'cancelFixes':
        abortControllers.fixes?.abort();
        break;

      case 'cancelSonar':
        abortControllers.sonar?.abort();
        break;

	

      default:
        outputChannel.appendLine(`Unknown command: ${m.command}`);
    }
  } catch (err) {
    console.error('[DepTrack] handler error:', err);
    panel.webview.postMessage({ command: 'emailStatus', success: false, error: err.message });
  }
});

      panel.onDidDispose(() => {
        panel = null;
        webviewPanel = null;
      }, null, context.subscriptions);
    })
  );

  // 4) Register other top-level commands
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.refresh', () =>
      withAbort('all', runAllChecks)
    ),
    vscode.commands.registerCommand('Aman.deptrack.sendReportEmail', () =>
      vscode.commands.executeCommand('Aman.deptrack.openDashboard').then(() =>
        panel.webview.postMessage({ command: 'sendReportEmail' })
      )
    ),
    vscode.commands.registerCommand('Aman.deptrack.sendCsvReportEmail', () =>
      vscode.commands.executeCommand('Aman.deptrack.openDashboard').then(() =>
        panel.webview.postMessage({ command: 'sendCsvReportEmail' })
      )
    )
  );

  // 5) Launch the dashboard on startup
  vscode.commands
    .executeCommand('Aman.deptrack.openDashboard')
    .then(() => outputChannel.appendLine('activate done'))
    .catch(err => outputChannel.appendLine('activate error: ' + err.message));
}

exports.activate = activate;


function deactivate() {
  panel = null;
  webviewPanel = null;
}


// WARNING: Hard-coding secrets in source is insecure! 
// Anyone with access to your repo can see and misuse this token.


async function getFreeChatResponse(prompt) {
  console.log('🕵️ Sending to HF API:', prompt);
  const res = await fetch(HF_URL, {
    method:  'POST',
    headers: {
      Authorization: `Bearer ${HF_HUB_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ inputs: prompt }),
  });
  if (!res.ok) throw new Error(`Service error: ${res.statusText}`);
  const json = await res.json();
  return Array.isArray(json) && json[0]?.generated_text
    ? json[0].generated_text
    : "Sorry, I didn't get that.";
}


async function runAllChecks(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }

  logLines = [];
  outputChannel.show(true);
  outputChannel.appendLine('runAllChecks start');


  // 1) Outdated packages
  outputChannel.appendLine('-> checkOutdated');
  try {
    outdated = await checkOutdated(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkOutdated', e);
  }

  // 2) Vulnerabilities
  outputChannel.appendLine('-> checkVuln');
  try {
    vulnPayload = await checkVuln(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkVuln', e);
  }

  // 3) License issues
  outputChannel.appendLine('-> checkLicenses');
  try {
    licenseIssues = await checkLicenses(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkLicenses', e);
  }

  // 4) Generic ESLint
  outputChannel.appendLine(`-> checkESLint (scope=${latestEslintScope})`);
  try {
    eslintDetails = await checkESLint(ws, signal, latestEslintScope);
  } catch (e) {
    logError('runAllChecks.checkESLint', e);
  }

  // 5) Industry-grade ESLint
  outputChannel.appendLine(`-> runIndustryESLint (scope=${latestEslintScope})`);
  try {
  eslintIndustryDetails = await runIndustryESLint(signal, latestEslintScope);
  } catch (e) {
    logError('runAllChecks.checkIndustryESlint', e);
  }

  // 6) Sonar
  outputChannel.appendLine('-> checkSonar');
  try {
    sonarResult = await checkSonar(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkSonar', e);
  }

  // 7) Complexity
  outputChannel.appendLine('-> checkComplexity');
  try {
    complexity = await checkComplexity(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkComplexity', e);
  }

  // 8) Duplication
  outputChannel.appendLine('-> checkDuplication');
  try {
    duplicationDetails = await checkDuplication(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkDuplication', e);
  }

  // 9) Secret scanning
  outputChannel.appendLine('-> scanSecrets');
  try {
    secrets = await scanSecrets(ws, signal);
  } catch (e) {
    logError('runAllChecks.scanSecrets', e);
  }

  // 10) Dependency Graph
  outputChannel.appendLine('-> checkDepGraph');
  try {
    depGraph = await checkDepGraph(ws, signal);
  } catch (e) {
    logError('runAllChecks.checkDepGraph', e);
  }

  // build suggested fixes once all data is available
  const suggestedFixes = await getSuggestedFixes({
    outdated,
    vuln: vulnPayload.data,
    licenseIssues,
    eslintDetails,
    eslintIndustryDetails,
    duplicationDetails,
    secrets
  });

  // 11) Final payload
  latestPayload = {
    outdated,
    vuln: vulnPayload.data,
    vulnError: vulnPayload.error,
    licenseIssues,
    eslintDetails,
    eslintIndustryDetails,    // <-- new!
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
}



async function runOutdated(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runOutdated: aborted before start');
    return;
  }
  outputChannel.appendLine('runOutdated start');
  try {
    const outdated = await checkOutdated(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runOutdated: aborted before UI update');
      return;
    }
    latestPayload.outdated = outdated;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runOutdated', e);
		 if (e.name === 'AbortError') {
      outputChannel.appendLine('runOutdated: aborted');
    } else {
      logError('runOutdated', e);
    }

	
	
	
  }
  outputChannel.appendLine('runOutdated done');
}

async function runVuln(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runVuln: aborted before start');
    return;
  }
  outputChannel.appendLine('runVuln start');
  try {
    const vulnPayload = await checkVuln(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runVuln: aborted before UI update');
      return;
    }
    latestPayload.vuln = vulnPayload.data;
    latestPayload.vulnError = vulnPayload.error;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runVuln', e);
  	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runVuln: aborted');
    } else {
      logError('runVuln', e);
    }

  
  }
  outputChannel.appendLine('runVuln done');
}


async function runLicenses(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runLicenses: aborted before start');
    return;
  }
  outputChannel.appendLine('runLicenses start');
  try {
    const licenseIssues = await checkLicenses(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runLicenses: aborted before UI update');
      return;
    }
    latestPayload.licenseIssues = licenseIssues;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runLicenses', e);
	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runLicenses: aborted');
    } else {
      logError('runLicenses', e);
    }
	
	
  }
  outputChannel.appendLine('runLicenses done');
}

function getWorkspaceRoot() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return undefined;
  }
  return folders[0].uri.fsPath;
}

// ─── 2) runESLint now takes (signal, scope) ──────────────────────────────────
async function runESLint(signal, scope) {
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!wsRoot) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }

  // resolve target folder based on scope
  const target = scope === 'src'
    ? path.join(wsRoot, 'src')
    : wsRoot;

  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine(`runESLint: aborted before start (scope=${scope})`);
    return;
  }
  outputChannel.appendLine(`runESLint start (scope=${scope}, target=${target})`);

  try {
    // pass scope along to checkESLint too (for logging)
    const eslintDetails = await checkESLint(target, signal, scope);

    if (signal.aborted) {
      outputChannel.appendLine(`runESLint: aborted before UI update (scope=${scope})`);
      return;
    }

    latestPayload.eslintDetails = eslintDetails;
    panel.webview.postMessage({
      command: 'updateData',
      payload: latestPayload
    });
  } catch (e) {
    logError('runESLint', e);
    if (e.name === 'AbortError') {
      outputChannel.appendLine(`runESLint: aborted (scope=${scope})`);
    }
  }

  outputChannel.appendLine(`runESLint done (scope=${scope})`);
}


async function runSonar(ws, signal) {
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }

  outputChannel.show(true);

  if (!signal || signal.aborted) {
    outputChannel.appendLine('runSonar: aborted before start');
    return;
  }

  outputChannel.appendLine('runSonar start');

  try {
    // call checkSonar without scope
    const sonarResult = await checkSonar(ws, signal);

    if (signal.aborted) {
      outputChannel.appendLine('runSonar: aborted before UI update');
      return;
    }

    latestPayload.sonarResult = sonarResult;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    if (e?.name === 'AbortError') {
      outputChannel.appendLine('runSonar: aborted');
    } else {
      logError('runSonar', e);
    }
  }

  outputChannel.appendLine('runSonar done');
}

module.exports = { runSonar };


async function runIndustryESLint(signal, scope) {
  try {
    // 1) load the industry config
    const configPath = path.resolve(__dirname, ".eslintrc.industry.cjs");
    const config     = require(configPath);
    const linter     = new Linter();

    // 2) build one glob for both .js and .ts
    const globPattern = scope === "."
      ? "**/*.{js,ts}"
      : `${scope}/**/*.{js,ts}`;

    // 3) exclude your common VCS, build and output folders
    const exclude = '**/{.git,node_modules,dist,report,.scannerwork,cleaned,my-ext,deptrack}/**';

    // 4) expand to actual files, skipping all excludes
    const uris = await vscode.workspace.findFiles(globPattern, exclude);

    // 5) send the raw list of files to the webview
    const files = uris.map(uri =>
      path.relative(vscode.workspace.rootPath, uri.fsPath)
    );
    webviewPanel.webview.postMessage({
      command: "scanningFiles",
      payload: { files }
    });

    // 6) now lint each file
    const details = [];
    for (const uri of uris) {
      const filePath = uri.fsPath;
      const code     = fs.readFileSync(filePath, "utf8");
      const messages = linter.verify(code, config, { filename: filePath });

      for (const m of messages) {
        details.push({
          file:    path.relative(vscode.workspace.rootPath, filePath),
          line:    m.line,
          rule:    m.ruleId || "(unknown)",
          message: m.message
        });
      }
    }

    // 7) finally send results
    webviewPanel.webview.postMessage({
      command: "updateData",
      payload:  { eslintIndustryDetails: details }
    });
	
	outputChannel.appendLine('[runIndustryESLint] done scanning');
  } catch (err) {
    outputChannel.appendLine(`[runIndustryESLint] ERROR: ${err.message}`);
    webviewPanel.webview.postMessage({
      command: "eslintIndustryError",
      payload: { message: err.message }
    });
	
  }
}
	
async function runComplexity(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runComplexity: aborted before start');
    return;
  }
  outputChannel.appendLine('runComplexity start');
  try {
    const complexity = await checkComplexity(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runComplexity: aborted before UI update');
      return;
    }
    latestPayload.complexity = complexity;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runComplexity', e);

	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runComplexity: aborted');
    } else {
      logError('runComplexity', e);
    }



  }
  outputChannel.appendLine('runComplexity done');
}

 async function runDuplication(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runDuplication: aborted before start');
    return;
  }
  outputChannel.appendLine('runDuplication start');
  const threshold = extensionContext.workspaceState.get('dupThreshold', 3);
  
  try {
    const duplicationDetails = await checkDuplication(ws, signal, threshold);
    if (signal.aborted) {
      outputChannel.appendLine('runDuplication: aborted before UI update');
      return;
    }
    latestPayload.duplicationDetails = duplicationDetails;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runDuplication', e);
  	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runDuplication: aborted');
    } else {
      logError('runDuplication', e);
    }

  
  
  }
  outputChannel.appendLine('runDuplication done');
}

function runDuplicationScanWithThreshold(threshold) {
  // persist it
  extensionContext.workspaceState.update('dupThreshold', threshold);

  // now wrap correctly so withAbort passes us just `signal`
  return withAbort('duplication', signal => {
    const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    return checkDuplication(ws, signal, threshold);
  });
}

async function runSecrets(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runSecrets: aborted before start');
    return;
  }
  outputChannel.appendLine('runSecrets start');
  try {
    const secrets = await scanSecrets(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runSecrets: aborted before UI update');
      return;
    }
    latestPayload.secrets = secrets;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runSecrets', e);
  	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runSecrets: aborted');
    } else {
      logError('runSecrets', e);
    }

  }
  outputChannel.appendLine('runSecrets done');
}

async function runDepGraph(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runDepGraph: aborted before start');
    return;
  }
  outputChannel.appendLine('runDepGraph start');
  try {
    const depGraph = await checkDepGraph(ws, signal);
    if (signal.aborted) {
      outputChannel.appendLine('runDepGraph: aborted before UI update');
      return;
    }
    latestPayload.depGraph = depGraph;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runDepGraph', e);
  
  	 if (e.name === 'AbortError') {
      outputChannel.appendLine('runDepGraph: aborted');
    } else {
      logError('runDepGraph', e);
    }

  
  
  }
  outputChannel.appendLine('runDepGraph done');
}

async function runFixes(signal) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) {
    vscode.window.showErrorMessage('Open a workspace first');
    return;
  }
  outputChannel.show(true);
  if (signal.aborted) {
    outputChannel.appendLine('runFixes: aborted before start');
    return;
  }
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
    if (signal.aborted) {
      outputChannel.appendLine('runFixes: aborted before UI update');
      return;
    }
    latestPayload.suggestedFixes = fixes;
    panel.webview.postMessage({ command: 'updateData', payload: latestPayload });
  } catch (e) {
    logError('runFixes', e);
	
		 if (e.name === 'AbortError') {
      outputChannel.appendLine('runFixes: aborted');
    } else {
      logError('runFixes', e);
    }

  }
  outputChannel.appendLine('runFixes done');
}

// Helper functions with AbortSignal support

async function scanSecrets(ws, signal) {
  const fn = 'scanSecrets';
  if (signal.aborted) return [];
  outputChannel.appendLine('[Secrets] start');
  const results = [];
  const ignored = ['.git', 'node_modules', 'dist', 'report', '.scannerwork','cleaned'];

  async function walk(dir) {
    if (signal.aborted) return;
    try {
      const entries = await fs.promises.readdir(dir, { withFileTypes: true });
      for (const ent of entries) {
        if (signal.aborted) return;
        if (ignored.includes(ent.name)) continue;
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          await walk(full);
        } else if (ent.isFile() && /\.(js|ts|py|sh|env|json)$/.test(ent.name)) {
          let txt;
          try { txt = await fs.promises.readFile(full, 'utf8'); } catch { continue; }
          for (const p of patterns) {
            if (signal.aborted) return;
            let m;
            while (!signal.aborted && (m = p.regex.exec(txt)) !== null) {
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
  if (!signal.aborted) {
    outputChannel.appendLine(`[Secrets] found ${results.length} items`);
    outputChannel.appendLine('[Secrets] done');
  }
  return results;
}

async function checkDepGraph(ws, signal) {
  const fn = 'checkDepGraph';
  if (signal.aborted) return {};
  outputChannel.appendLine('[DepGraph] start');

  const npmLock  = path.join(ws, 'package-lock.json');
  const yarnLock = path.join(ws, 'yarn.lock');
  let graph = {};

  try {
    if (signal.aborted) return graph;
    if (fs.existsSync(npmLock)) {
      const lockRaw  = fs.readFileSync(npmLock, 'utf8');
      const lockData = JSON.parse(lockRaw);
      if (lockData.packages) {
        for (const [pkgPath, info] of Object.entries(lockData.packages)) {
          if (signal.aborted) break;
          if (pkgPath === '') continue;
          const name = info.name || pkgPath.split('node_modules/').pop();
          graph[name] = { version: info.version };
        }
      } else if (lockData.dependencies) {
        graph = flattenDeps(lockData);
      }
      if (!signal.aborted) outputChannel.appendLine(`[DepGraph] npm entries: ${Object.keys(graph).length}`);
    } else if (fs.existsSync(yarnLock)) {
      const raw    = fs.readFileSync(yarnLock, 'utf8');
      const parsed = parseYarnLock(raw);
      if (parsed.type === 'success') {
        for (const key of Object.keys(parsed.object)) {
          if (signal.aborted) break;
          const info = parsed.object[key];
          const pkg  = key.replace(/@[^@]+$/, '');
          graph[pkg] = { version: info.version };
        }
        if (!signal.aborted) outputChannel.appendLine(`[DepGraph] yarn entries: ${Object.keys(graph).length}`);
      } else {
        outputChannel.appendLine('[DepGraph] failed — invalid yarn.lock');
      }
    } else {
      outputChannel.appendLine('[DepGraph] skipped — no lockfile found');
    }
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[DepGraph] failed — could not parse lockfile');
  }

  if (!signal.aborted) outputChannel.appendLine('[DepGraph] done');
  return graph;
}



function flattenDeps(tree, acc = {}) {
  for (const [name, info] of Object.entries(tree.dependencies || {})) {
    acc[name] = { version: info.version };
    flattenDeps(info, acc);
  }
  return acc;
}




async function checkOutdated(ws, signal) {
  const fn = 'checkOutdated';
  const npm = resolveCmd(ws, 'npm');
  const res = {};
  const pkgJson = path.join(ws, 'package.json');
  if (!npm || !fs.existsSync(pkgJson) || signal.aborted) return res;

  outputChannel.appendLine('[Outdated] start');
  let raw = '';
  try {
    const { stdout } = await execP(
      `${npm} outdated --json`,
      { cwd: ws, signal, maxBuffer: 52428800 }
    );
    raw = stdout.trim();
  } catch (e) {
    if (signal.aborted) {
      outputChannel.appendLine('[Outdated] aborted during exec');
      return res;
    }
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
    res[pkg] = { current: info.current, latest: info.latest,
      status: diff === 'major' ? 'critical' : diff === 'minor' ? 'warning' : 'good' };
  }

  const count = Object.keys(res).length;
  outputChannel.appendLine(count
    ? `[Outdated] found ${count} outdated package${count>1?'s':''}`
    : '[Outdated] none found'
  );
  outputChannel.appendLine('[Outdated] done');
  return res;
}

async function checkVuln(ws, signal) {
  const fn = 'checkVuln';
  const snyk = resolveCmd(ws, 'snyk');
  const npm  = resolveCmd(ws, 'npm');
  const res  = {};
  let vulnError = null;
  const pkgJson = path.join(ws, 'package.json');
  if (!fs.existsSync(pkgJson) || signal.aborted) return { data: res, error: null };

  const execOpts = { cwd: ws, signal, maxBuffer: 52428800, env: { ...process.env } };
  outputChannel.appendLine('[Vuln] start');
  let payload = null;

  if (snyk && !signal.aborted) {
    try {
      const { stdout } = await execP(`"${snyk}" test --json`, execOpts);
      payload = JSON.parse(stdout);
    } catch (e) {
      if (signal.aborted) {
        outputChannel.appendLine('[Vuln] aborted during Snyk');
      } else {
        const raw = e.stdout || '';
        try { payload = raw && JSON.parse(raw); }
        catch (pe) { vulnError = raw ? `JSON parse failed: ${pe.message}` : `Snyk failed: ${stripAnsi(e.stderr||e.message)}`; }
      }
    }
  }

  if (!payload && npm && !signal.aborted) {
    try {
      const { stdout } = await execP(`"${npm}" audit --json`, execOpts);
      payload = JSON.parse(stdout);
    } catch (e) {
      if (signal.aborted) {
        outputChannel.appendLine('[Vuln] aborted during npm audit');
      } else {
        const raw = e.stdout || '';
        try { payload = raw && JSON.parse(raw); }
        catch (pe) { vulnError = raw ? `JSON parse failed: ${pe.message}` : `npm audit failed: ${stripAnsi(e.stderr||e.message)}`; }
      }
    }
  }

  if (payload && typeof payload === 'object') {
    const list = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : Object.values(payload.vulnerabilities||{});
    outputChannel.appendLine(`[Vuln] total vulnerabilities: ${list.length}`);
    for (const v of list) {
      if (signal.aborted) break;
      const pkgName = v.packageName||v.name||v.module_name;
      const severity= (v.severity||v.cvssScore||'unknown').toString().toLowerCase();
      const title   = v.title||v.overview||'';
      (res[pkgName] ||=[]).push({ severity, title });
    }
  } else if (vulnError) {
    outputChannel.appendLine(`[Vuln] error: ${vulnError}]`);
  }

  if (!signal.aborted) outputChannel.appendLine('[Vuln] done');
  return { data: res, error: vulnError };
}

async function checkLicenses(ws, signal) {
  const fn = 'checkLicenses';
  if (signal.aborted) return [];
  outputChannel.appendLine('[License] start');
  const tool = resolveCmd(ws, 'license-checker');
  if (!tool) { outputChannel.appendLine('[License] skipped'); outputChannel.appendLine('[License] done'); return []; }
  let res = [];
  try {
    if (signal.aborted) return [];
    outputChannel.appendLine('[License] running');
    const { stdout } = await execP(`"${tool}" --json`, { cwd: ws, signal });
    const data = JSON.parse(stdout);
    for (const [pkg, info] of Object.entries(data)) {
      if (signal.aborted) break;
      const ls  = info.licenses? (Array.isArray(info.licenses)? info.licenses:[info.licenses]): ['UNKNOWN'];
      const bad = ls.filter(l=> forbiddenLicenses.some(f=>l.toUpperCase().includes(f)));
      if (bad.length) res.push({ pkg, licenses: bad });
    }
  } catch (e) { logError(fn, e); }
  if (!signal.aborted) outputChannel.appendLine('[License] done');
  return res;
}

// ─── 3) checkESLint now takes (ws, signal, scope) ───────────────────────────
async function checkESLint(ws, signal, scope) {
  const fn = 'checkESLint';
  if (signal.aborted) return [];

  outputChannel.appendLine(`[checkESLint] start (scope=${scope}, ws=${ws})`);

  const patterns = ['**/*.{js,jsx,ts,tsx}'];
  const ignore   = [
    'node_modules/**','dist/**','report/**',
    'coverage/**','deptrack/**','media/**',
    'cleaned/**','my-ext/**'
  ];

  let files;
  try {
    files = await fg(patterns, {
      cwd: ws,
      onlyFiles: true,
      absolute: true,
      ignore
    });
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[checkESLint] done with error');
    return [];
  }

  if (!files.length || signal.aborted) {
    outputChannel.appendLine('[checkESLint] nothing to lint or aborted');
    return [];
  }

  files.forEach(f => {
    if (!signal.aborted)
      outputChannel.appendLine(`[checkESLint] will lint: ${path.relative(ws, f)}`);
  });

  // build ESLint CLI command
  const binName   = process.platform === 'win32' ? 'eslint.cmd' : 'eslint';
  const localBin  = path.join(ws, 'node_modules', '.bin', binName);
  const eslintBin = fs.existsSync(localBin) ? `"${localBin}"` : 'eslint';
  const wsRoot    = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const configF   = path.join(wsRoot, 'eslint.config.cjs');
  const args      = [`-c "${configF}"`, '-f json', ...files.map(f => `"${f}"`)].join(' ');
  const cmd       = `${eslintBin} ${args}`;

  let raw = '';
  try {
    const out = await execP(cmd, {
      cwd: ws,
      signal,
      maxBuffer: 20 * 1024 * 1024
    });
    raw = (out.stdout || '').trim() || (out.stderr || '').trim();
  } catch (e) {
    if (!signal.aborted)
      raw = (e.stdout || '').trim() || (e.stderr || '').trim();
  }

  if (!raw || signal.aborted) {
    outputChannel.appendLine('[checkESLint] done (no output or aborted)');
    return [];
  }

  // safely extract JSON array
  const first = raw.indexOf('[');
  const last  = raw.lastIndexOf(']');
  if (first < 0 || last <= first) {
    outputChannel.appendLine('[checkESLint] no JSON array found, skipping');
    return [];
  }

  let results;
  try {
    results = JSON.parse(raw.slice(first, last + 1));
  } catch (pe) {
    logError(fn, pe);
    outputChannel.appendLine('[checkESLint] JSON parse failed, skipping');
    return [];
  }

  const res = [];
  for (const fileResult of results) {
    if (signal.aborted) break;
    const rel = path.relative(ws, fileResult.filePath);
    // skip unwanted directories
    if (/^(node_modules|dist|report|coverage|deptrack)[\/\\]/.test(rel))
      continue;
    for (const msg of fileResult.messages) {
      res.push({
        file:    rel,
        line:    msg.line,
        rule:    msg.ruleId,
        message: msg.message
      });
    }
  }

  outputChannel.appendLine('[checkESLint] done');
  return res;
}


async function checkSonar(ws, signal) {
  // 0) Early abort
  if (signal?.aborted) {
    return { passed: true, summary: 'Skipped', metrics: {} };
  }

  // 1) Hardcoded credentials
  const token = '5b00f48971c97adc419af174c881cdc909161c67';
  const projectKey = 'AmanKumar636_DepTrack';
  const host = 'https://sonarcloud.io';

  outputChannel.appendLine(
    `[Sonar] token=${token.slice(0,4)}… projectKey=${projectKey} host=${host}`
  );

  // 2) Locate sonar-scanner CLI
  const scanner = resolveCmd(ws, 'sonar-scanner');
  if (!scanner) {
    outputChannel.appendLine('[Sonar] skipped — sonar-scanner not found');
    return { passed: true, summary: 'Skipped', metrics: {} };
  }

  // 3) Build scanner properties
  const props = [
    `-Dsonar.token=${token}`,
    `-Dsonar.projectKey=${projectKey}`,
    `-Dsonar.host.url=${host}`,
    '-Dsonar.qualitygate.wait=true',
    '-Dsonar.scm.disabled=true',
    `-Dsonar.exclusions=**/report/**,**/coverage/**,**/*.html,**/fixtures/**,**/.scannerwork/**,**/node_modules/**,**/dist/**`,
    '-Dsonar.cpd.javascript.minimumTokens=50',
    '-Dsonar.threads=4',
    '-Dsonar.scanner.skipSystemTruststore=true'
  ];

  outputChannel.appendLine('[Sonar] start scan');
  let passed = false;
  let summary = '';

  // 4) Execute scan and await quality gate
  try {
    await execP(`"${scanner}" ${props.join(' ')}`, {
      cwd: ws,
      maxBuffer: 200 * 1024 * 1024,
      env: process.env,
      signal
    });
    passed = true;
    summary = '✅ Quality Gate passed';
  } catch {
    passed = false;
    summary = '❌ Quality Gate failed';
  }

  // 5) Abort check
  if (signal?.aborted) {
    return { passed: true, summary: 'Aborted', metrics: {} };
  }

  // 6) Fetch metrics from SonarCloud API
  let metrics = {};
  try {
    const metricKeys = [
      'bugs',
      'vulnerabilities',
      'code_smells',
      'coverage',
      'duplicated_lines_density'
    ].join(',');

    const url = `${host}/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=${metricKeys}`;
    const resp = await axios.get(url, {
      auth: { username: token, password: '' },
      timeout: 10000
    });
    metrics = resp.data.component.measures.reduce((acc, m) => {
      acc[m.metric] = m.value;
      return acc;
    }, {});
  } catch (apiErr) {
    console.error('[Sonar] API error:', apiErr);
  }

  outputChannel.appendLine(`[Sonar] done — ${summary}`);
  return { passed, summary, metrics };
}

module.exports = { checkSonar };




async function checkComplexity(ws, signal) {
  const fn = 'checkComplexity';
  if (signal.aborted) return [];
  outputChannel.appendLine('[Complexity] start');
  const tool = resolveCmd(ws,'plato');
  if (!tool) { outputChannel.appendLine('[Complexity] done'); return []; }
  const reportDir = path.join(ws,'report','plato'); fs.mkdirSync(reportDir,{recursive:true});

  let results=[];
  try {
    await execP(`"${tool}" -r -d "${reportDir}" src`,{cwd:ws,signal,maxBuffer:209715200});
    if (signal.aborted) return [];
    const reportFile = path.join(reportDir,'report.json');
    if (fs.existsSync(reportFile)) {
      const raw = fs.readFileSync(reportFile,'utf8');
      const data = JSON.parse(raw);
      const reports = Array.isArray(data.reports)? data.reports : [];
      results = reports.map(r=>{
        const comp = r.complexity||{};
        const sloc = comp.sloc||{};
        const logical = typeof sloc.logical==='number'? sloc.logical: typeof sloc.physical==='number'? sloc.physical:0;
        return { path: path.relative(ws,r.info.file||''), aggregate:{cyclomatic:comp.cyclomatic||0,sloc:logical,maintainability:comp.maintainability||0} };
      });
    }
  } catch(e) { logError(fn,e); }
  if (!signal.aborted) outputChannel.appendLine('[Complexity] done');
  return results;
}

async function checkDuplication(ws, signal, threshold = 3) {
  const fn = 'checkDuplication';
  if (signal.aborted) return [];
  outputChannel.appendLine('[Duplication] start');
  const projectRoot = ws.replace(/\\/g,'/');
  const patterns = [`${projectRoot}/*.js`,`${projectRoot}/*.ts`,`${projectRoot}/src/**/*.js`,`${projectRoot}/src/**/*.ts`];
  let files=[];
  try { files = await fg(patterns,{absolute:true,onlyFiles:true}); } catch(e){ logError(fn,e); }
  if (!files.length || signal.aborted) { outputChannel.appendLine('[Duplication] done'); return []; }

  let raw='';
  try {
     const cmd = `${resolveCmd(ws,'jsinspect')||'npx jsinspect'} --identical --threshold ${threshold} --reporter json ${files.map(f=>`"${f}"`).join(' ')}`;
    const out = await execP(cmd,{cwd:ws,signal,maxBuffer:524288000});
    raw = (out.stdout||'').trim()||(out.stderr||'').trim();
  } catch(e){ if (!signal.aborted) raw=(e.stdout||'').trim()||(e.stderr||'').trim(); }
  if (signal.aborted) return [];

  const idx = raw.indexOf('[');
  const jsonText = idx>=0 ? raw.slice(idx) : raw;
  let matches=[];
  try { matches = JSON.parse(jsonText); } catch(pe){ logError(fn,pe); }

  const res=[];
  for (const m of matches) {
    if (signal.aborted) break;
    const inst = m.instances||[];
    for (let i=0;i<inst.length;i++) for (let j=i+1;j<inst.length;j++) {
      res.push({ fileA:path.relative(ws,inst[i].path), lineA:inst[i].lines[0], fileB:path.relative(ws,inst[j].path), lineB:inst[j].lines[0] });
    }
  }
  if (!signal.aborted) outputChannel.appendLine('[Duplication] done');
  return res;
}

async function getSuggestedFixes(
  {
    outdated = {},
    vuln = {},
    licenseIssues = [],
    eslintDetails = [],
    duplicationDetails = [],
    secrets = []
  },
  signal
) {
  // 0) If the user cancelled, bail out immediately
  if (signal?.aborted) return [];

  const fixes = [];

  // 1) Outdated packages
  for (const [pkg, info] of Object.entries(outdated)) {
    if (signal?.aborted) return fixes;
    fixes.push({
      pkg,
      fix: `Update to ${info.latest}`
    });
  }

  // 2) Vulnerabilities
  for (const [pkg, list] of Object.entries(vuln)) {
    if (signal?.aborted) return fixes;
    list.forEach(v => {
      let suggestion;
      if (/upgrade to ([\d.]+)/i.test(v.title)) {
        suggestion = `Upgrade to ${RegExp.$1}`;
      } else if (v.title.startsWith('Insecure')) {
        suggestion = 'Review & patch vulnerability';
      } else {
        suggestion = `Review vulnerability: "${v.title}"`;
      }
      fixes.push({ pkg, fix: suggestion });
    });
  }

  // 3) License issues
  for (const x of licenseIssues) {
    if (signal?.aborted) return fixes;
    fixes.push({
      pkg: x.pkg,
      fix: `Consider replacing or upgrading (forbidden: ${x.licenses.join(', ')})`
    });
  }

  // 4) ESLint issues by file
  if (signal?.aborted) return fixes;
  const eslintByFile = eslintDetails.reduce((acc, e) => {
    (acc[e.file] ||= []).push(e);
    return acc;
  }, {});
  for (const [file, msgs] of Object.entries(eslintByFile)) {
    if (signal?.aborted) break;
    // if any rule other than semi, suggest auto-fix
    const hasAutoFixable = msgs.some(m => m.rule && m.rule !== 'semi');
    fixes.push({
      pkg: file,
      fix: hasAutoFixable
        ? `eslint --fix "${file}"`
        : 'Add missing semicolons'
    });
  }

  // 5) Secrets
  for (const s of secrets) {
    if (signal?.aborted) return fixes;
    fixes.push({
      pkg: s.file,
      fix: `Remove hard‐coded ${s.rule} and inject via secure env var`
    });
  }

  // 6) Duplication
  for (const d of duplicationDetails) {
    if (signal?.aborted) return fixes;
    fixes.push({
      pkg: `${d.fileA} & ${d.fileB}`,
      fix: `Extract common logic at lines ${d.lineA}/${d.lineB}`
    });
  }

  return fixes;
}



async function sendEmailNotification(subject, text, overrideTo, attachments = []) {
  // HARDCODED values
  const user = 'cs24m114@iittp.ac.in';
  const pass = 'alqw frfl bwmc cbdm'; // App-specific password, not your Gmail login
  const to   = overrideTo || 'amankmr636@gmail.com';
  const service = 'gmail';

  console.log('[DepTrack] sendEmailNotification config →', {
    service, user, hasPass: !!pass, to, subject, text, attachments
  });

  if (!user || !pass || !to) {
    const msg = 'Missing hardcoded email configuration';
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
    webviewPanel?.webview.postMessage({ command: 'emailStatus', success: true });
  } catch (err) {
    console.error('[DepTrack] sendMail error:', err);
    webviewPanel?.webview.postMessage({
      command: 'emailStatus',
      success: false,
      error: err.message
    });
  }
}

/**
 * Helper to run a check with an AbortSignal
 */
 async function withAbort(viewName, checkFn) {
  if (abortControllers[viewName]) {
    abortControllers[viewName].abort();
  }
  const controller = new AbortController();
  abortControllers[viewName] = controller;

  try {
    await checkFn(controller.signal);
  } catch (err) {
    if (controller.signal.aborted) {
      outputChannel.appendLine(`[${viewName}] aborted`);
    } else {
      throw err;
    }
  } finally {
    delete abortControllers[viewName];
  }
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
