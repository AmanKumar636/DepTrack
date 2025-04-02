// routes/scan.js
const express = require("express");
const router = express.Router();
const { runScan } = require("../scanner"); // Import the asynchronous runScan function
const ScanResult = require("../models/ScanResult");
const { sendEmailNotification, sendSlackNotification } = require("../notifier");

// POST endpoint to scan a file (triggered by the VS Code extension)
router.post("/", async (req, res) => {
  console.log("POST /api/scan received with body:", req.body);
  const { filename, content } = req.body;
  if (!filename || !content) {
    console.error("Filename or content missing in POST body.");
    return res.status(400).json({ error: "Filename and content are required." });
  }

  // Log a snippet of the file content to verify the scanned file
  console.log("File content snippet:", content.slice(0, 100));

  try {
    // Run the scan function and await its result.
    const scanData = await runScan(filename, content);
    console.log("Scan data produced:", scanData);

    // Save the scan result to MongoDB.
    const scanResultDoc = new ScanResult(scanData);
    await scanResultDoc.save();
    console.log("Scan result saved to MongoDB.");

    // Send notifications if vulnerabilities were found.
    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
      const subject = "DepTrack Alert: Vulnerabilities Detected";
      const message = `Scan Summary: ${scanData.summary}`;
      sendEmailNotification(subject, message);
      sendSlackNotification(message);
      console.log("Notifications sent for vulnerabilities found.");
    }

    res.json(scanData);
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({ error: "Scan failed" });
  }
});

// GET endpoint to fetch the latest scan result (for the dashboard)
// Sorting by _id in descending order returns the most recently inserted document.
router.get("/", async (req, res) => {
  try {
    const latestResult = await ScanResult.findOne().sort({ _id: -1 });
    console.log("Returning scan result:", latestResult);
    res.json(latestResult);
  } catch (err) {
    console.error("Error fetching latest scan result:", err);
    res.status(500).json({ error: "Failed to fetch latest scan result." });
  }
});

module.exports = router;
