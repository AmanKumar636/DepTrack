// routes/scan.js
const express = require("express");
const router = express.Router();
const { runFullScan } = require("../scanner");
const ScanResult = require("../models/ScanResult");
const { sendEmailNotification, sendSlackNotification } = require("../notifier");

router.get("/", async (req, res) => {
  try {
    const scanData = await runFullScan();

    // Save scan results to the database
    const scanResultDoc = new ScanResult(scanData);
    await scanResultDoc.save();

    // Send notifications if vulnerabilities exist (dummy condition)
    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
      const subject = "DepTrack Alert: Vulnerabilities Detected";
      const message = `Scan Summary: ${scanData.summary}`;
      sendEmailNotification(subject, message);
      sendSlackNotification(message);
    }

    res.json(scanData);
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({ error: "Scan failed" });
  }
});

module.exports = router;
