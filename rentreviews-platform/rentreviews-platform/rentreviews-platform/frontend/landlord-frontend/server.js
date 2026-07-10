'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8000;
const AUTH_API_BASE_URL = process.env.AUTH_API_BASE_URL || process.env.API_BASE_URL || 'http://localhost:8080';
const PROPERTY_API_BASE_URL = process.env.PROPERTY_API_BASE_URL || AUTH_API_BASE_URL;
const REVIEW_API_BASE_URL = process.env.REVIEW_API_BASE_URL || AUTH_API_BASE_URL;

// Regenerate config.js from environment on every boot so a Railway env var
// change + redeploy is enough to repoint the frontend — no rebuild step.
const configJs = `// Generated at container startup from environment variables. Do not edit directly.
window.APP_CONFIG = window.APP_CONFIG || {
  API_BASE_URL: ${JSON.stringify(AUTH_API_BASE_URL)},
  AUTH_API_BASE_URL: ${JSON.stringify(AUTH_API_BASE_URL)},
  PROPERTY_API_BASE_URL: ${JSON.stringify(PROPERTY_API_BASE_URL)},
  REVIEW_API_BASE_URL: ${JSON.stringify(REVIEW_API_BASE_URL)}
};
`;
fs.writeFileSync(path.join(__dirname, 'config.js'), configJs);

const app = express();
app.use(express.static(__dirname, { extensions: ['html'] }));

app.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'landlord-frontend' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🖥️  Frontend static server running on port ${PORT}`);
  console.log(`   AUTH_API_BASE_URL: ${AUTH_API_BASE_URL}`);
  console.log(`   PROPERTY_API_BASE_URL: ${PROPERTY_API_BASE_URL}`);
});
