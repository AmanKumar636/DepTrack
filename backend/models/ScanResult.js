// models/ScanResult.js
const mongoose = require("mongoose");

const ScanResultSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  summary: String,
  vulnerabilities: Array,
  outdated: Array,
  licenseIssues: Array,
  snyk: Object
});

module.exports = mongoose.model("ScanResult", ScanResultSchema);
