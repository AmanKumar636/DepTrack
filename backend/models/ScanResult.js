// models/ScanResult.js
const mongoose = require("mongoose");

const ScanResultSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  summary: String,
  vulnerabilities: Array,
  outdated: Array,       // For outdated dependencies
  licenseIssues: Array,  // For license issues
  snyk: Object           // For Snyk data
});

module.exports = mongoose.model("ScanResult", ScanResultSchema);
