// snykIntegration.js
const fetch = require('node-fetch');

/**
 * Fetch Snyk project data using Snyk's API.
 * 
 * @param {string} projectId - The Snyk project ID you want to fetch data for.
 * @returns {Promise<object>} - The Snyk project data.
 * @throws {Error} - If the API call fails.
 */
async function fetchSnykProjectData(projectId) {
  const SNYK_API_TOKEN = process.env.SNYK_API_TOKEN;
  const SNYK_ORG_ID = process.env.SNYK_ORG_ID;
  const SNYK_API_URL = 'https://snyk.io/api/v1';

  if (!SNYK_API_TOKEN) {
    throw new Error("Snyk API token not configured.");
  }

  const url = `${SNYK_API_URL}/org/${SNYK_ORG_ID}/project/${projectId}`;
  const response = await fetch(url, {
    headers: { 'Authorization': `token ${SNYK_API_TOKEN}` }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Snyk API error: ${response.status} ${text}`);
  }

  const data = await response.json();
  return data;
}

module.exports = { fetchSnykProjectData };
