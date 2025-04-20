#!/usr/bin/env node
// scripts/standard-checker.js
// A dummy JSON output for testing standards violations:
const violations = [
  {
    file: "src/standards-violation.txt",
    standard: "no-tabs",
    issue: "Found tab character at start of line"
  },
  {
    file: "src/standards-violation.txt",
    standard: "line-max-length",
    issue: "Line exceeds 80 characters"
  }
];
console.log(JSON.stringify(violations, null, 2));
