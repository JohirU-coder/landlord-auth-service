require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    database: 'connected'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Landlord Auth Service API',
    status: 'running',
    endpoints: {
      health: '/health',
      'setup-database': '/setup-database (POST)',
      register: '/register (POST)',
      test: '/test'
    }
  });
});

// Create tables endpoint
app.post('/setup-database', async (req, res) => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'renter',
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        email_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    // Create verification tokens table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS verification_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        type VARCHAR(50) DEFAULT 'email_verification',
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    res.json({ 
      message: 'Database tables created successfully!',
      tables: ['users', 'verification_tokens'],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Database setup error:', error);
    res.status(500).json({ 
      error: 'Failed to create tables', 
      details: error.message 
    });
  }
});

// Test database connection
app.get('/test', (req, res) => {
  res.json({
    message: 'Test endpoint working!',
    database: process.env.DATABASE_URL ? 'Connected' : 'Not configured',
    port: PORT
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Auth service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});