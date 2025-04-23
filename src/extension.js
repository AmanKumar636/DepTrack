const vscode        = require('vscode');
const { execSync }  = require('child_process');
const path          = require('path');
const fs            = require('fs');
const fetch         = require('node-fetch');
const nodemailer    = require('nodemailer');
const PDFDocument   = require('pdfkit');
const semver        = require('semver');
const stripAnsiMod  = require('strip-ansi');
const stripAnsi     = stripAnsiMod.default || stripAnsiMod;
const { ESLint }    = require('eslint');

// Secret‐scan patterns
const patterns = [
  { name: 'AWS Key',     regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private Key', regex: /-----BEGIN PRIVATE KEY-----/g },
];

let panel, refreshInterval, latestPayload = null, chatHistory = [];
let outputChannel, logLines = [];
const toolExists = {};

function resolveCmd(ws, tool) {
  const bin   = process.platform === 'win32' ? `${tool}.cmd` : tool;
  const local = path.join(ws, 'node_modules', '.bin', bin);
  if (fs.existsSync(local)) {
    toolExists[tool] = true;
    return local;
  }
  try {
    execSync(`${tool} --version`, { stdio:'ignore' });
    toolExists[tool] = true;
    return tool;
  } catch {
    toolExists[tool] = false;
    return null;
  }
}

async function scanSecrets(ws) {
  const results = [];
  async function walk(dir) {
    for (const e of await fs.promises.readdir(dir, { withFileTypes:true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory() && !['.git','node_modules'].includes(e.name)) {
        await walk(full);
      } else if (e.isFile() && /\.(js|ts|py|sh|env|json)$/.test(e.name)) {
        const txt = await fs.promises.readFile(full,'utf8');
        patterns.forEach(p => {
          let m;
          while ((m = p.regex.exec(txt)) !== null) {
            results.push({
              file: path.relative(ws, full),
              line: txt.slice(0, m.index).split('\n').length,
              rule: p.name,
              match: m[0]
            });
          }
        });
      }
    }
  }
  await walk(ws);
  return results;
}

function flattenDeps(tree, acc = {}) {
  Object.entries(tree.dependencies || {}).forEach(([k, v]) => {
    acc[k] = { version: v.version };
    flattenDeps(v, acc);
  });
  return acc;
}

function activate(context) {
  outputChannel = vscode.window.createOutputChannel('DepTrack');
  const orig = outputChannel.appendLine.bind(outputChannel);
  outputChannel.appendLine = l => {
    orig(l);
    logLines.push(l);
    if (panel) panel.webview.postMessage({ command:'logUpdate', payload: logLines });
  };

  context.subscriptions.push(
    vscode.commands.registerCommand('deptrack.openDashboard', () => {
      if (!panel) {
        panel = vscode.window.createWebviewPanel(
          'deptrackDashboard',
          'DepTrack Dashboard',
          vscode.ViewColumn.One,
          {
            enableScripts: true,
            localResourceRoots: [ vscode.Uri.file(path.join(context.extensionPath,'src')) ]
          }
        );
        const html = fs.readFileSync(
          path.join(context.extensionPath,'src','dashboard.html'),
          'utf8'
        );
        panel.webview.html = html;
        panel.webview.onDidReceiveMessage(onWebviewMessage, null, context.subscriptions);
        panel.onDidDispose(() => { panel = null; clearInterval(refreshInterval); }, null, context.subscriptions);
      }
      runAllChecks();
      if (!refreshInterval) {
        refreshInterval = setInterval(runAllChecks, 5 * 60 * 1000);
      }
    })
  );
}

async function onWebviewMessage(msg) {
  switch (msg.command) {
    case 'refresh':     return runAllChecks();
    case 'healthCheck': return runHealthCheck();
    case 'sendEmail':   return sendEmailNotification('DepTrack Alert','See report.',msg.email);
    case 'exportCSV':   return exportCsv();
    case 'exportPDF':   return exportPdf();
    case 'chat':        return handleChat(msg.text);
  }
}

async function runAllChecks() {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!ws) { vscode.window.showErrorMessage('Open a workspace first'); return; }

  const tools = {};
  ['npm','snyk','escomplex','eslint','jscpd','license-checker','sonar-scanner']
    .forEach(t => tools[t] = resolveCmd(ws, t));

  logLines = [];
  outputChannel.show(true);
  outputChannel.appendLine('=== DepTrack: starting checks ===');

  // 1) Outdated
  const outdated = {};
  if (tools.npm) {
    outputChannel.appendLine('[Outdated] start');
    let raw = '';
    try {
      raw = execSync(
        `"${tools.npm}" outdated --json`,
        { cwd: ws, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }
      );
    } catch (e) {
      raw = (e.stdout || '').toString();
      if (!raw) {
        outputChannel.appendLine(`[Outdated] warning: ${e.message}`);
      }
    }
    try {
      const data = raw.trim() ? JSON.parse(raw) : {};
      Object.entries(data).forEach(([pkg,info]) => {
        const diff = semver.diff(info.current, info.latest);
        outdated[pkg] = {
          current: info.current,
          latest:  info.latest,
          status:  diff==='major'?'critical':diff==='minor'?'warning':'good'
        };
      });
    } catch (parseErr) {
      outputChannel.appendLine(`[Outdated] parse error: ${parseErr.message}`);
    }
    outputChannel.appendLine('[Outdated] done');
  }

  // 2) Vulnerabilities
  const vuln = {};
  if (tools.snyk || tools.npm) {
    outputChannel.appendLine('[Vuln] start via snyk');
    let auditJson = null;

    // Try Snyk first
    if (tools.snyk) {
      try {
        const raw = execSync(
          `"${tools.snyk}" test --json`,
          { cwd: ws, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }
        );
        auditJson = JSON.parse(raw);
      } catch (e) {
        outputChannel.appendLine(`[Vuln] snyk error: ${e.message}`);
      }
    }

    // Fallback to npm audit
    if (!auditJson && tools.npm) {
      outputChannel.appendLine('[Vuln] fallback to npm audit');
      try {
        const raw = execSync(
          `"${tools.npm}" audit --json`,
          { cwd: ws, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }
        );
        auditJson = JSON.parse(raw);
      } catch (e2) {
        const out = (e2.stdout || '').toString().trim();
        if (out) {
          try { auditJson = JSON.parse(out); }
          catch (pe) { outputChannel.appendLine(`[Vuln] npm audit parse error: ${pe.message}`); }
        } else {
          outputChannel.appendLine(`[Vuln] npm audit error: ${e2.message}`);
        }
      }
    }

    // Now extract vulnerabilities from either schema:
    if (auditJson) {
      // Snyk format: auditJson.vulnerabilities is an array
      if (Array.isArray(auditJson.vulnerabilities)) {
        auditJson.vulnerabilities.forEach(v => {
          const pkg = v.packageName || v.name || v.module_name;
          vuln[pkg] = { severity: v.severity, title: v.title || '' };
        });
      }
      // npm audit format: auditJson.vulnerabilities is an object
      else if (typeof auditJson.vulnerabilities === 'object') {
        Object.entries(auditJson.vulnerabilities).forEach(([pkg, info]) => {
          vuln[pkg] = {
            severity: info.severity,
            title:    info.title || info.name || ''
          };
        });
      }
    }

    outputChannel.appendLine('[Vuln] done');
  }


  // 3) License
  const licenseIssues = [];
  if (tools['license-checker']) {
    outputChannel.appendLine('[License] start');
    try {
      const raw = execSync(
        `"${tools['license-checker']}" --json`,
        { cwd: ws, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
      const lc = JSON.parse(raw);
      Object.entries(lc).forEach(([pkg,info]) => {
        const lic    = Array.isArray(info.licenses)?info.licenses:[info.licenses];
        const issues = lic.some(l=>/AGPL|GPL/.test(l)) ? ['Restrictive'] : [];
        if (issues.length) licenseIssues.push({ pkg, licenses:lic, issues });
      });
    } catch (e) {
      outputChannel.appendLine(`[License] error: ${e.message}`);
    }
    outputChannel.appendLine('[License] done');
  }

  // 4) ESLint
  const eslintCounts = {};
  if (tools.eslint) {
    outputChannel.appendLine('[ESLint] start');
    const configPath = path.join(ws, '.eslintrc.json');
    try {
      const engine  = new ESLint({ cwd:ws, overrideConfigFile:configPath });
      const results = await engine.lintFiles(['src/**/*.js','src/**/*.ts']);
      results.forEach(r => { eslintCounts[path.relative(ws,r.filePath)] = r.messages.length; });
    } catch (apiErr) {
      outputChannel.appendLine(`[ESLint] API error: ${apiErr.message}`);
      outputChannel.appendLine('[ESLint] fallback to CLI');
      try {
        const raw = execSync(
          `"${tools.eslint}" . -f json --config .eslintrc.json`,
          { cwd: ws, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }
        );
        JSON.parse(raw).forEach(r => {
          eslintCounts[path.relative(ws,r.filePath)] = r.messages.length;
        });
      } catch (cliErr) {
        outputChannel.appendLine(`[ESLint] CLI error: ${cliErr.message}`);
      }
    }
    outputChannel.appendLine('[ESLint] done');
  }

  // 5) Sonar
  const sonar = { qualityGate:'NA', error:null };
  if (tools['sonar-scanner'] && fs.existsSync(path.join(ws,'sonar-project.properties'))) {
    outputChannel.appendLine('[Sonar] start');
    try {
      const out = execSync(
        `"${tools['sonar-scanner']}" -Dsonar.qualitygate.wait=true`,
        { cwd: ws, encoding:'utf8', maxBuffer:50*1024*1024 }
      );
      const m = out.match(/Quality gate status:\s+(\w+)/);
      sonar.qualityGate = m?m[1]:'UNKNOWN';
    } catch (e) {
      sonar.error = e.message;
      outputChannel.appendLine(`[Sonar] error: ${e.message}`);
    }
    outputChannel.appendLine('[Sonar] done');
  }

  // 6) Complexity
  let complexity = [];
  if (tools.escomplex) {
    outputChannel.appendLine('[Complexity] start');
    try {
      const raw    = execSync(
        `"${tools.escomplex}" . --json`,
        { cwd: ws, encoding:'utf8', maxBuffer:10*1024*1024 }
      );
      const parsed = JSON.parse(raw);
      complexity = Array.isArray(parsed)?parsed:(parsed.reports||[]);
    } catch (e) {
      outputChannel.appendLine(`[Complexity] error: ${e.message}`);
    }
    outputChannel.appendLine('[Complexity] done');
  }

  // 7) Duplication
  let duplicationDetails = [];
  if (tools.jscpd) {
    outputChannel.appendLine('[Duplication] start');
    try {
      const raw = execSync(
        `"${tools.jscpd}" --reporters json --min-lines 2 src`,
        { cwd: ws, encoding:'utf8', maxBuffer:10*1024*1024 }
      );
      const clean      = stripAnsi(raw.toString());
      const firstBrace = clean.indexOf('{');
      if (firstBrace < 0) {
        outputChannel.appendLine('[Duplication] warning: no JSON output from jscpd');
      } else {
        const data = JSON.parse(clean.slice(firstBrace));
        (data.matches||[]).forEach(m => {
          const [a,b] = m.instances;
          duplicationDetails.push({
            fileA: a.sourceId, lineA: a.start.line,
            fileB: b.sourceId, lineB: b.start.line
          });
        });
      }
    } catch (e) {
      outputChannel.appendLine(`[Duplication] error: ${e.message}`);
    }
    outputChannel.appendLine('[Duplication] done');
  }

  // 8) Secrets
  let secrets = [];
  outputChannel.appendLine('[Secrets] start');
  try { secrets = await scanSecrets(ws); }
  catch (e) { outputChannel.appendLine(`[Secrets] error: ${e.message}`); }
  outputChannel.appendLine('[Secrets] done');

  // 9) Dependency Graph
  let depGraph = {};
  if (tools.npm) {
    outputChannel.appendLine('[DepGraph] start');
    try {
      const raw = execSync(
        `"${tools.npm}" ls --all --json`,
        { cwd: ws, encoding:'utf8', maxBuffer:50*1024*1024 }
      );
      depGraph = flattenDeps(JSON.parse(raw));
    } catch {
      outputChannel.appendLine('[DepGraph] npm ls failed, fallback to package.json');
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(ws,'package.json'),'utf8'));
        depGraph = Object.fromEntries(
          Object.entries(pkg.dependencies||{}).map(([k,v])=>[k,{version:v}])
            .concat(Object.entries(pkg.devDependencies||{}).map(([k,v])=>[k,{version:v}]))
        );
      } catch (e) {
        outputChannel.appendLine(`[DepGraph] fallback error: ${e.message}`);
      }
    }
    outputChannel.appendLine('[DepGraph] done');
  }

  const suggestions = makeSuggestions(outdated,vuln,licenseIssues,eslintCounts);
  latestPayload = { outdated,vuln,licenseIssues,eslintCounts,sonar,complexity,duplicationDetails,secrets,depGraph,suggestions,chatHistory };
  if (panel) panel.webview.postMessage({ command:'updateData', payload:latestPayload });

  outputChannel.appendLine('=== DepTrack: checks complete ===');
}

function makeSuggestions(o,v,l,e){
  const list = [];
  Object.keys(o).forEach(p => list.push({category:'Outdated', suggestion:`npm install ${p}@latest`}));
  if (Object.keys(v).length) list.push({category:'Vulnerabilities', suggestion:'npm audit fix'});
  l.forEach(x => list.push({category:'License', suggestion:`Review ${x.pkg}`}));
  if (Object.values(e).reduce((a,b)=>a+b,0)>0) list.push({category:'ESLint', suggestion:'Fix ESLint issues'});
  return list;
}

async function handleChat(text){
  chatHistory.push({from:'You',text});
  let reply = '';
  try{
    const res  = await fetch('https://api.affiliateplus.xyz/api/chat?message='+encodeURIComponent(text));
    const json = await res.json();
    reply      = json.response||json.message||'❌ No response';
  }catch(e){
    reply=`❌ Chat error: ${e.message}`;
  }
  chatHistory.push({from:'Bot',text:reply});
  if(panel) panel.webview.postMessage({command:'chatResponse',payload:{text:reply}});
}

async function runHealthCheck(){
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if(!ws) return;
  try{
    await Promise.all([
      toolExists.npm  && Promise.resolve(execSync(`${resolveCmd(ws,'npm')} outdated --json`,{cwd:ws})),
      toolExists.snyk && Promise.resolve(execSync(`${resolveCmd(ws,'snyk')} test --json`,{cwd:ws})),
      Promise.resolve(execSync('eslint . -f json',{cwd:ws,maxBuffer:20*1024*1024}))
    ]);
    vscode.window.showInformationMessage('DepTrack: All systems go');
  }catch{
    vscode.window.showWarningMessage('DepTrack: Issues detected');
  }
}

async function sendEmailNotification(subject,text,overrideTo){
  const cfg  = vscode.workspace.getConfiguration('deptrack.email');
  const user = cfg.get('auth.user'), pass = cfg.get('auth.pass'),
        to   = overrideTo||cfg.get('to');
  if(!user||!pass||!to){
    return vscode.window.showWarningMessage('Configure deptrack.email.auth or recipient.');
  }
  const transporter = nodemailer.createTransport({
    service: cfg.get('service')||'gmail',
    auth:    { user, pass }
  });
  try{
    await transporter.sendMail({ from:user, to, subject, text });
    vscode.window.showInformationMessage(`DepTrack: Email sent to ${to}`);
  }catch(e){
    outputChannel.appendLine(`[Email] error: ${e.message}`);
    vscode.window.showErrorMessage(`Email failed: ${e.message}`);
  }
}

function exportCsv(){
  if(!latestPayload) return;
  const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
  let csv = 'Category,Name,Details\n';
  Object.entries(latestPayload.outdated).forEach(([p,i])=>{
    csv+=`Outdated,${p},"${i.current}→${i.latest}"\n`;
  });
  Object.entries(latestPayload.vuln).forEach(([p,v])=>{
    csv+=`Vulnerability,${p},"${v.severity}"\n`;
  });
  latestPayload.suggestions.forEach(s=>{
    csv+=`Suggestion,${s.category},"${s.suggestion}"\n`;
  });
  latestPayload.licenseIssues.forEach(x=>{
    csv+=`License,${x.pkg},"${x.licenses.join(', ')}: ${x.issues.join('; ')}"\n`;
  });
  Object.entries(latestPayload.eslintCounts).forEach(([f,c])=>{
    csv+=`ESLint,${f},"${c} issues"\n`;
  });
  latestPayload.duplicationDetails.forEach(d=>{
    csv+=`Duplication,${d.fileA}:${d.lineA},${d.fileB}:${d.lineB}\n`;
  });
  latestPayload.secrets.forEach(s=>{
    csv+=`Secret,${s.file},${s.line},${s.rule}\n`;
  });
  Object.entries(latestPayload.depGraph).forEach(([n,i])=>{
    csv+=`Dependency,${n},"${i.version}"\n`;
  });
  latestPayload.chatHistory.forEach(c=>{
    const t=c.text.replace(/"/g,'""');
    csv+=`Chat,${c.from},"${t}"\n`;
  });
  const uri = vscode.Uri.file(path.join(ws,'deptrack-report.csv'));
  vscode.workspace.fs.writeFile(uri,Buffer.from(csv,'utf8'))
    .then(()=>vscode.window.showInformationMessage('DepTrack: CSV exported'))
    .catch(e=>outputChannel.appendLine(`[CSV] error: ${e.message}`));
}

function exportPdf(){
  if(!latestPayload) return;
  const ws  = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const out = path.join(ws,'deptrack-report.pdf');
  const doc = new PDFDocument({ margin:40 });
  doc.pipe(fs.createWriteStream(out));

  const section = t=>doc.fontSize(16).text(t,{underline:true}).moveDown(0.5);
  const item    = t=>doc.fontSize(12).text(`• ${t}`).moveDown(0.2);

  doc.fontSize(20).text('DepTrack Report').moveDown(1);
  section('Outdated Packages');
  Object.entries(latestPayload.outdated).forEach(([p,i])=>item(`${p}: ${i.current} → ${i.latest}`));
  section('Vulnerabilities');
  Object.entries(latestPayload.vuln).forEach(([p,v])=>item(`${p}: [${v.severity}] ${v.title}`));
  section('Fix Suggestions');
  latestPayload.suggestions.forEach(s=>item(`[${s.category}] ${s.suggestion}`));
  section('License Issues');
  latestPayload.licenseIssues.forEach(x=>item(`${x.pkg}: ${x.licenses.join(', ')} → ${x.issues.join('; ')}`));
  section('ESLint Issues');
  Object.entries(latestPayload.eslintCounts).forEach(([f,c])=>item(`${f}: ${c} issues`));
  section('Code Duplication');
  latestPayload.duplicationDetails.forEach(d=>item(`${d.fileA}:${d.lineA} ↔ ${d.fileB}:${d.lineB}`));
  section('Secret Findings');
  latestPayload.secrets.forEach(s=>item(`${s.file}:${s.line} [${s.rule}]`));
  section('Complexity');
  latestPayload.complexity.forEach(r=>item(`${r.path}: cyclomatic ${r.aggregate?.cyclomatic}`));
  section('Dependency Graph');
  Object.entries(latestPayload.depGraph).forEach(([n,i])=>item(`${n}@${i.version}`));
  section('Sonar Quality Gate');
  item(`Status: ${latestPayload.sonar.qualityGate}`);
  section('Chat History');
  latestPayload.chatHistory.forEach(c=>item(`${c.from}: ${c.text}`));

  doc.end();
  doc.on('finish',()=>vscode.window.showInformationMessage(`DepTrack: PDF exported to ${out}`));
}

function deactivate(){ clearInterval(refreshInterval); }
module.exports = { activate, deactivate };
