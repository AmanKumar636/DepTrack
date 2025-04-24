const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec: execCb, execSync } = require('child_process');
const execP = util.promisify(execCb);
const axios = require('axios');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const semver = require('semver');
const stripAnsi = require('strip-ansi').default || require('strip-ansi');
const { ESLint } = require('eslint');
const fg = require('fast-glob');

const patterns = [
  { name: 'AWS Key',    regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private Key', regex: /-----BEGIN PRIVATE KEY-----/g }
];
const forbiddenLicenses = ['GPL','AGPL','LGPL','PROPRIETARY','UNKNOWN'];

let panel;
let refreshInterval;
let latestPayload = null;
let chatHistory = [];
let outputChannel;
let logLines = [];
const toolExists = {};
let isScanning = false;

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

async function activate(context) {
  outputChannel = vscode.window.createOutputChannel('DepTrack');
  const orig = outputChannel.appendLine.bind(outputChannel);
  outputChannel.appendLine = line => {
    const time = new Date().toLocaleTimeString();
    const entry = `[${time}] ${stripAnsi(line)}`;
    orig(entry);
    logLines.push(entry);
    panel?.webview.postMessage({ command: 'logUpdate', payload: logLines });
  };
  outputChannel.appendLine('activate start');

  // Open Dashboard command: creates panel and runs a single scan
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.openDashboard', () => {
      outputChannel.appendLine('command openDashboard');
      if (!panel) {
        panel = vscode.window.createWebviewPanel(
          'deptrackDashboard',
          'DepTrack Dashboard',
          vscode.ViewColumn.One,
          { enableScripts: true, localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, 'src'))] }
        );
        panel.webview.html = fs.readFileSync(path.join(context.extensionPath, 'src', 'dashboard.html'), 'utf8');
        panel.webview.onDidReceiveMessage(onWebviewMessage, null, context.subscriptions);
        panel.onDidDispose(() => { panel = null; }, null, context.subscriptions);
      }
      // Run all checks once when the dashboard is opened
      runAllChecks();
    })
  );

  // Manual refresh command
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.refresh', runAllChecks)
  );

  // Other commands (healthCheck, sendEmail, exportCSV, exportPDF, chat)
  context.subscriptions.push(
    vscode.commands.registerCommand('Aman.deptrack.healthCheck', runHealthCheck),
    vscode.commands.registerCommand('Aman.deptrack.sendEmail', args => sendEmailNotification('DepTrack Alert', 'See report.', args)),
    vscode.commands.registerCommand('Aman.deptrack.exportCSV', exportCsv),
    vscode.commands.registerCommand('Aman.deptrack.exportPDF', exportPdf),
    vscode.commands.registerCommand('Aman.deptrack.chat', args => handleChat(args))
  );

  // Open the dashboard (runs one scan via openDashboard handler)
  vscode.commands.executeCommand('Aman.deptrack.openDashboard');
  outputChannel.appendLine('activate done');
}

async function onWebviewMessage(msg) {
  outputChannel.appendLine(`onWebviewMessage ${msg.command}`);
  switch (msg.command) {
    case 'refresh': return runAllChecks();
    case 'scanView': return runAllChecks();
    case 'scanAll': return runAllChecks();
    case 'healthCheck': return runHealthCheck();
    case 'sendEmail': return sendEmailNotification('DepTrack Alert', 'See report.', msg.email);
    case 'exportCSV': return exportCsv();
    case 'exportPDF': return exportPdf();
    case 'chat': return handleChat(msg.text);
    default: outputChannel.appendLine(`[onWebviewMessage] unknown: ${msg.command}`);
  }
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

  // Initialize result placeholders
  let outdated = {};
  let vulnPayload = { data: {}, error: null };
  let licenseIssues = [];
  let eslintDetails = [];
  let sonarResult = {};
  let complexity = [];
  let duplicationDetails = [];
  let secrets = [];
  let depGraph = {};

  // 1) Outdated Packages
  outputChannel.appendLine('-> checkOutdated');
  try { outdated = await checkOutdated(ws); }
  catch (e) { logError('runAllChecks.checkOutdated', e); }

  // 2) Vulnerabilities
  outputChannel.appendLine('-> checkVuln');
  try { vulnPayload = await checkVuln(ws); }
  catch (e) { logError('runAllChecks.checkVuln', e); }

  // 3) License Issues
  outputChannel.appendLine('-> checkLicenses');
  try { licenseIssues = await checkLicenses(ws); }
  catch (e) { logError('runAllChecks.checkLicenses', e); }

  // 4) ESLint
  outputChannel.appendLine('-> checkESLint');
  try { eslintDetails = await checkESLint(ws); }
  catch (e) { logError('runAllChecks.checkESLint', e); }

  // 5) Sonar
  outputChannel.appendLine('-> checkSonar');
  try { sonarResult = await checkSonar(ws); }
  catch (e) { logError('runAllChecks.checkSonar', e); }

  // 6) Complexity
  outputChannel.appendLine('-> checkComplexity');
  try { complexity = await checkComplexity(ws); }
  catch (e) { logError('runAllChecks.checkComplexity', e); }

  // 7) Duplication
  outputChannel.appendLine('-> checkDuplication');
  try { duplicationDetails = await checkDuplication(ws); }
  catch (e) { logError('runAllChecks.checkDuplication', e); }

  // 8) Secret Scan
  outputChannel.appendLine('-> scanSecrets');
  try { secrets = await scanSecrets(ws); }
  catch (e) { logError('runAllChecks.scanSecrets', e); }

  // 9) Dependency Graph
  outputChannel.appendLine('-> checkDepGraph');
  try { depGraph = await checkDepGraph(ws); }
  catch (e) { logError('runAllChecks.checkDepGraph', e); }

  // Store latest payload for exports and dashboard
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
    chatHistory
  };

  // Send data to the dashboard webview
  if (panel?.webview) {
    panel.webview.postMessage({
      command: 'updateData',
      payload: latestPayload
    });
  }

  outputChannel.appendLine('runAllChecks done');
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
  const fn = 'checkVuln';
  const snyk = resolveCmd(ws, 'snyk');
  const npm  = resolveCmd(ws, 'npm');
  const res  = {};
  let vulnError = null;
  const pkgJson = path.join(ws, 'package.json');

  if (!fs.existsSync(pkgJson)) {
    outputChannel.appendLine('[Vuln] skipped — no package.json');
    return { data: res, error: null };
  }

  outputChannel.appendLine('[Vuln] start');
  let payload = null;

  if (snyk) {
    try {
      const { stdout } = await execP(`"${snyk}" test --json`, { cwd: ws, maxBuffer: 52428800 });
      payload = JSON.parse(stdout);
    } catch (e) {
      const raw = e.stdout || '';
      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch (pe) {
          vulnError = `Snyk JSON parse failed: ${pe.message}`;
        }
      } else {
        vulnError = `Snyk failed: ${stripAnsi(e.stderr || e.message)}`;
      }
    }
  }

  if (!payload && npm) {
    try {
      const { stdout } = await execP(`"${npm}" audit --json`, { cwd: ws, maxBuffer: 52428800 });
      payload = JSON.parse(stdout);
    } catch (e) {
      const raw = e.stdout || '';
      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch (pe) {
          vulnError = `npm audit JSON parse failed: ${pe.message}`;
        }
      } else {
        vulnError = `npm audit failed: ${stripAnsi(e.stderr || e.message)}`;
      }
    }
  }

  if (payload && typeof payload === 'object') {
    const list = Array.isArray(payload.vulnerabilities)
               ? payload.vulnerabilities
               : Object.values(payload.vulnerabilities || {});
    outputChannel.appendLine(`[Vuln] total vulnerabilities: ${list.length}`);
    for (const v of list) {
      const pkgName = v.packageName || v.name || v.module_name;
      const severity = (v.severity || v.cvssScore || 'unknown').toString().toLowerCase();
      const title    = v.title || v.overview || '';
      (res[pkgName] ||= []).push({ severity, title });
    }
  } else if (vulnError) {
    outputChannel.appendLine(`[Vuln] error: ${vulnError}`);
  }

  if (!Object.keys(res).length && !vulnError) {
    outputChannel.appendLine('[Vuln] none found');
  }
  outputChannel.appendLine('[Vuln] done');
  return { data: res, error: vulnError };
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

async function checkESLint(ws) {
  const fn = 'checkESLint';
  outputChannel.appendLine('[ESLint] start');

  // Only lint our src folder
  const patterns = ['src/**/*.{js,ts}'];
  let res = [];

  try {
    const eslint = new ESLint({
      cwd: ws,
      // Merge in our rule override. Other config files (eslintrc, ignore) are respected.
      overrideConfig: {
        rules: {
          'semi': ['error', 'always']
        }
      }
    });

    const results = await eslint.lintFiles(patterns);
    for (const r of results) {
      const relativePath = path.relative(ws, r.filePath);
      for (const m of r.messages) {
        res.push({
          file:    relativePath,
          line:    m.line,
          rule:    m.ruleId,
          message: m.message
        });
      }
    }
  } catch (e) {
    logError(fn, e);
  }

  if (!res.length) {
    outputChannel.appendLine('[ESLint] none detected');
  }
  outputChannel.appendLine('[ESLint] done');
  return res;
}

async function checkSonar(ws) {
  const fn = 'checkSonar';
  const rootConfig = vscode.workspace.getConfiguration();
  const token = rootConfig.get('deptrack.sonar.token')?.trim();
  const projectKey = rootConfig.get('deptrack.sonar.projectKey')?.trim();
  outputChannel.appendLine(`[Sonar] token=${token?.slice(0,4)}…, projectKey=${projectKey}`);
  const host = (rootConfig.get('deptrack.sonar.hostUrl') || 'https://sonarcloud.io').replace(/\/$/, '');
  if (!token || !projectKey) {
    outputChannel.appendLine(`[Sonar] skipped — configure both 'deptrack.sonar.token' and 'deptrack.sonar.projectKey' in settings`);
    outputChannel.appendLine('[Sonar] done');
    return {};
  }

  const scanner = resolveCmd(ws, 'sonar-scanner');
  if (!scanner) {
    outputChannel.appendLine('[Sonar] skipped — sonar-scanner not found');
    outputChannel.appendLine('[Sonar] done');
    return {};
  }

  outputChannel.appendLine('[Sonar] start');
  let summary = '';
  let metrics = {};

  // Build scanner properties, including exclusions for generated reports
  const props = [
    `-Dsonar.token=${token}`,
    `-Dsonar.projectKey=${projectKey}`,
    `-Dsonar.host.url=${host}`,
    '-Dsonar.qualitygate.wait=true',
    '-Dsonar.scm.disabled=true',
    '-Dsonar.sources=.',
    '-Dsonar.exclusions=**/report/**,**/.scannerwork/**,**/node_modules/**,**/dist/**'
  ];

  try {
    await execP(`"${scanner}" ${props.join(' ')}`, { cwd: ws, maxBuffer: 209715200 });
    summary = '✅ Quality Gate passed';
  } catch (err) {
    logError(fn, err);
    summary = '❌ Sonar scan failed';
  }

  // Fetch quality metrics from SonarCloud API
  try {
    const metricKeys = ['bugs','vulnerabilities','code_smells','coverage','duplicated_lines_density'].join(',');
    const url = `${host}/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=${metricKeys}`;
    const resp = await axios.get(url, { auth: { username: token, password: '' }, timeout: 10000 });
    metrics = resp.data.component.measures.reduce((acc, m) => {
      acc[m.metric] = m.value;
      return acc;
    }, {});
  } catch (apiErr) {
    logError(`${fn} API`, apiErr);
  }

  outputChannel.appendLine('[Sonar] done');
  return { passed: summary.startsWith('✅'), summary, metrics };
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
	
async function checkDuplication(ws) {
  const fn = 'checkDuplication';
  outputChannel.appendLine('[Duplication] start');

  const inspector = resolveCmd(ws, 'jsinspect') || 'npx jsinspect';
  const targetDir = process.platform === 'win32'
    ? ws.replace(/\\/g, '/')
    : ws;

  // Skip all generated dirs AND src/extension.js
  const ignorePattern = '(node_modules|dist|report|\\.scannerwork|src[\\\\/]extension\\.js)';

  const cmd = `${inspector} --identical --threshold 1 --reporter json --ignore "${ignorePattern}" "${targetDir}"`;

  try {
    outputChannel.appendLine(`[Duplication] running: ${cmd}`);
    const { stdout } = await execP(cmd, { cwd: ws, maxBuffer: 524288000 });
    const matches = JSON.parse(stdout);

    const res = [];
    matches.forEach(match => {
      const instances = match.instances;
      for (let i = 0; i < instances.length; i++) {
        for (let j = i + 1; j < instances.length; j++) {
          const a = instances[i];
          const b = instances[j];
          res.push({
            fileA: a.path,
            lineA: a.lines[0],
            fileB: b.path,
            lineB: b.lines[0]
          });
        }
      }
    });

    if (!res.length) outputChannel.appendLine('[Duplication] none');
    return res;
  } catch (e) {
    logError(fn, e);
    outputChannel.appendLine('[Duplication] failed');
    return [];
  } finally {
    outputChannel.appendLine('[Duplication] done');
  }
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

async function runHealthCheck() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) return;
  try {
    await Promise.all([
      toolExists.npm    && execP(`${resolveCmd(ws,'npm')} outdated --json`, { cwd: ws }),
      toolExists.snyk   && execP(`${resolveCmd(ws,'snyk')} test --json`, { cwd: ws }),
      execP('eslint . -f json', { cwd: ws })
    ]);
    vscode.window.showInformationMessage('DepTrack: All systems go');
  } catch (e) {
    logError('runHealthCheck', e);
  }
}

async function sendEmailNotification(subject, text, overrideTo) {
  const cfg = vscode.workspace.getConfiguration('deptrack.email');
  const transporter = nodemailer.createTransport({
    service: cfg.get('service') || 'gmail',
    auth: { user: cfg.get('auth.user'), pass: cfg.get('auth.pass') }
  });
  const to = overrideTo || cfg.get('to');
  if (!cfg.get('auth.user') || !cfg.get('auth.pass') || !to) return;
  try {
    await transporter.sendMail({ from: cfg.get('auth.user'), to, subject, text });
  } catch (e) {
    logError('sendEmailNotification', e);
  }
}

function exportCsv() {
  if (!latestPayload) return;
  try {
    const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
    let csv = 'Category,Name,Details\n';
    Object.entries(latestPayload.outdated   || {}).forEach(([p,i]) => { csv += `Outdated,${p},"${i.current}→${i.latest}"\n`; });
    Object.entries(latestPayload.vuln       || {}).forEach(([p,list]) => list.forEach(v => { csv+=`Vulnerability,${p},"${v.severity}"\n`; }));
    (latestPayload.licenseIssues            || []).forEach(x => { csv += `License,${x.pkg},"${x.licenses.join(',')}"\n`; });
    (latestPayload.eslintDetails            || []).forEach(e => { csv += `ESLint,${e.file}:${e.line},"${e.rule}: ${e.message}"\n`; });
    (latestPayload.duplicationDetails       || []).forEach(d => { csv += `Duplication,${d.fileA}:${d.lineA},${d.fileB}:${d.lineB}\n`; });
    (latestPayload.complexity               || []).forEach(c => { csv += `Complexity,${c.path},"${c.aggregate.cyclomatic}"\n`; });
    (latestPayload.secrets                  || []).forEach(s => { csv += `Secret,${s.file}:${s.line},${s.rule}\n`; });
    Object.entries(latestPayload.depGraph    || {}).forEach(([n,i]) => { csv += `Dependency,${n},"${i.version}"\n`; });
    (latestPayload.chatHistory              || []).forEach(c => { const t = c.text.replace(/"/g,'""'); csv+=`Chat,${c.from},"${t}"\n`; });
    (latestPayload.testFiles                || []).forEach(f => { csv += `TestFile,,${f}\n`; });
    const uri = vscode.Uri.file(path.join(ws,'deptrack-report.csv'));
    vscode.workspace.fs.writeFile(uri, Buffer.from(csv,'utf8'));
  } catch (e) {
    logError('exportCsv', e);
  }
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
