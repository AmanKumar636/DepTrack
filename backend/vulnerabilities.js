// vulnerable.js
const express = require('express');
const { exec } = require('child_process');
const _ = require('lodash'); // Demonstrates prototype pollution (use an outdated version in package.json)
const app = express();

// Vulnerability 1: Unsafe Eval
// This endpoint takes a query parameter "code" and evaluates it.
// An attacker could send malicious code to execute arbitrary JavaScript.
app.get('/eval', (req, res) => {
  const code = req.query.code;
  try {
    // UNSAFE: Evaluates untrusted input.
    const result = eval(code);
    res.send(`Result: ${result}`);
  } catch (e) {
    res.status(500).send(`Error: ${e.message}`);
  }
});

// Vulnerability 2: Command Injection
// This endpoint takes a query parameter "cmd" and appends it to a shell command.
// Without proper sanitization, an attacker could inject arbitrary commands.
app.get('/exec', (req, res) => {
  const cmd = req.query.cmd;
  // UNSAFE: Directly concatenates user input into a shell command.
  exec('ls ' + cmd, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(`Error: ${error.message}`);
      return;
    }
    res.send(`Output: ${stdout}`);
  });
});

// Vulnerability 3: Hard-Coded Credentials
// The credentials below are hard-coded and exposed in the source code.
const dbUser = "admin";
const dbPass = "password123"; // Sensitive credentials should never be hard-coded!
console.log(`Connecting to database with user: ${dbUser} and password: ${dbPass}`);

// Vulnerability 4: Prototype Pollution
// This endpoint accepts a JSON payload as a query parameter "payload"
// and merges it into an empty object using lodash's merge.
// An attacker may pollute Object.prototype if passing something like '{"__proto__": {"polluted": "yes"}}'
app.get('/pollute', (req, res) => {
  const payload = req.query.payload;
  try {
    const parsed = JSON.parse(payload);
    // UNSAFE: Merges user input into an object, potentially polluting prototypes.
    const obj = _.merge({}, parsed);
    res.send(obj);
  } catch (e) {
    res.status(500).send(`Error: ${e.message}`);
  }
});

// Start the vulnerable app on port 3000
app.listen(3000, () => {
  console.log('Vulnerable app running on port 3000');
});
