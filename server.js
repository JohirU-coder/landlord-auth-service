require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
// Railway sets the PORT environment variable - use it!
const PORT = process.env.PORT || 3000;

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
    message: 'Authentication service is running!',
    port: PORT,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Landlord Auth Service API',
    status: 'running',
    endpoints: {
      health: '/health',
      test: '/test'
    }
  });
});

// Simple test endpoint
app.get('/test', (req, res) => {
  res.json({
    message: 'Test endpoint working!',
    database: process.env.DATABASE_URL ? 'Connected' : 'Not configured',
    port: PORT
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Auth service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});