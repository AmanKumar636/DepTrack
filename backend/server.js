require('dotenv').config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch"); // Install with: npm install node-fetch@2
require("./db"); // Connect to MongoDB
const scanRouter = require("./routes/scan");

const app = express();
const PORT = process.env.PORT || 3001;

const mongoose = require('mongoose');

// Set strictQuery to false (or true, depending on your needs)
mongoose.set('strictQuery', false);
// Middleware
app.use(cors());
app.use(express.json());

// Root endpoint
app.get("/", (req, res) => {
  res.send("Welcome to DepTrack backend API");
});

// Scan endpoint
app.use("/api/scan", scanRouter);

// Endpoint to retrieve historical scan results
app.get("/api/history", async (req, res) => {
  const ScanResult = require("./models/ScanResult");
  try {
    const history = await ScanResult.find().sort({ timestamp: -1 }).limit(20);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// Endpoint to fetch Snyk project data
app.get('/api/snyk/project-data/:projectId', async (req, res) => {
  const { projectId } = req.params;
  
  // Retrieve Snyk API credentials from environment variables
  const SNYK_API_TOKEN = process.env.SNYK_API_TOKEN;
  // Default to "cs24m114" if SNYK_ORG_ID isn't provided
  const SNYK_ORG_ID = process.env.SNYK_ORG_ID || "cs24m114";  
  const SNYK_API_URL = 'https://snyk.io/api/v1';

  if (!SNYK_API_TOKEN) {
    return res.status(500).json({ error: 'Snyk API token not configured.' });
  }

  try {
    // Construct the URL to fetch data for the given project ID
    const response = await fetch(`${SNYK_API_URL}/org/${SNYK_ORG_ID}/project/${projectId}`, {
      headers: {
        'Authorization': `token ${SNYK_API_TOKEN}`
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: 'Failed to fetch data from Snyk API', details: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error fetching Snyk project data:', error);
    res.status(500).json({ error: 'An error occurred fetching Snyk project data' });
  }
});

app.listen(PORT, () => {
  console.log(`DepTrack backend running at http://localhost:${PORT}`);
});
