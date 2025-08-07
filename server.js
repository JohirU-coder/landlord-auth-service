require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;

// JWT Secret (add this to your Railway environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate Limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts',
    message: 'Please try again in 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Please try again later'
  }
});

app.use('/login', authLimiter);
app.use('/register', authLimiter);
app.use(generalLimiter);

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Input Validation Schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required().max(255),
  password: Joi.string().min(8).max(128).required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .message('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  firstName: Joi.string().required().min(1).max(50).pattern(/^[a-zA-Z\s]+$/),
  lastName: Joi.string().required().min(1).max(50).pattern(/^[a-zA-Z\s]+$/),
  role: Joi.string().valid('renter', 'landlord').required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().max(255),
  password: Joi.string().required().max(128)
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid authentication token'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: 'Invalid token',
        message: 'Your session has expired. Please log in again.'
      });
    }
    req.user = user;
    next();
  });
};

// Utility Functions
const sanitizeUser = (user) => {
  const { password_hash, ...sanitizedUser } = user;
  return sanitizedUser;
};

const generateToken = (user) => {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
    firstName: user.first_name,
    lastName: user.last_name
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    security: 'JWT enabled'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'RentReviews Authentication Service',
    status: 'running',
    version: '2.0.0',
    endpoints: {
      health: '/health',
      register: '/register (POST)',
      login: '/login (POST)',
      profile: '/profile (GET) - Auth required',
      refresh: '/refresh (POST) - Auth required',
      'setup-database': '/setup-database (GET)'
    },
    security: {
      rateLimit: 'Enabled',
      helmet: 'Enabled',
      jwt: 'Enabled',
      cors: 'Configured'
    }
  });
});

// Database setup endpoint
app.get('/setup-database', async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'renter' CHECK (role IN ('renter', 'landlord')),
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email_verified BOOLEAN DEFAULT FALSE,
        account_status VARCHAR(20) DEFAULT 'active' CHECK (account_status IN ('active', 'suspended', 'deleted')),
        last_login TIMESTAMP,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

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

    // Create indexes for performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_user_id ON verification_tokens(user_id);
    `);

    res.json({
      message: 'Database tables created successfully',
      tables: ['users', 'verification_tokens'],
      indexes: ['idx_users_email', 'idx_users_role', 'idx_verification_tokens_token', 'idx_verification_tokens_user_id'],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Database setup error:', error);
    res.status(500).json({
      error: 'Failed to create database tables',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    // Validate input
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details.map(detail => detail.message)
      });
    }

    const { email, password, firstName, lastName, role } = value;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: 'User already exists',
        message: 'An account with this email address already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, role) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, email, first_name, last_name, role, created_at`,
      [email.toLowerCase(), passwordHash, firstName.trim(), lastName.trim(), role]
    );

    const newUser = result.rows[0];
    const token = generateToken(newUser);

    res.status(201).json({
      message: 'User created successfully',
      user: sanitizeUser(newUser),
      token,
      expiresIn: JWT_EXPIRES_IN
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to create user account'
    });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    // Validate input
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details.map(detail => detail.message)
      });
    }

    const { email, password } = value;

    // Get user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND account_status = $2',
      [email.toLowerCase(), 'active']
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }

    const user = result.rows[0];

    // Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      return res.status(423).json({
        error: 'Account locked',
        message: 'Too many failed login attempts. Please try again later.'
      });
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordValid) {
      // Increment failed attempts
      await pool.query(
        `UPDATE users SET 
         failed_login_attempts = failed_login_attempts + 1,
         locked_until = CASE 
           WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
           ELSE NULL 
         END
         WHERE id = $1`,
        [user.id]
      );

      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }

    // Reset failed attempts and update last login
    await pool.query(
      `UPDATE users SET 
       failed_login_attempts = 0, 
       locked_until = NULL, 
       last_login = NOW() 
       WHERE id = $1`,
      [user.id]
    );

    const token = generateToken(user);

    res.json({
      message: 'Login successful',
      user: sanitizeUser(user),
      token,
      expiresIn: JWT_EXPIRES_IN
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to authenticate user'
    });
  }
});

// Get User Profile (Protected Route)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, first_name, last_name, role, email_verified, last_login, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account does not exist'
      });
    }

    res.json({
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to fetch user profile'
    });
  }
});

// Refresh Token
app.post('/refresh', authenticateToken, (req, res) => {
  try {
    const newToken = generateToken(req.user);
    
    res.json({
      message: 'Token refreshed successfully',
      token: newToken,
      expiresIn: JWT_EXPIRES_IN
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to refresh token'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'The requested resource was not found'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔒 Secure Auth service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`JWT: ${JWT_SECRET ? 'Configured' : 'Warning: Using default secret'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});