require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    message: 'Authentication service is running!'
  });
});

// Simple test endpoint
app.get('/test', (req, res) => {
  res.json({
    message: 'Test endpoint working!',
    database: process.env.DATABASE_URL ? 'Connected' : 'Not configured'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Auth service running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});