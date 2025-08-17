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

// Validate required environment variables
if (!process.env.JWT_SECRET || !process.env.DATABASE_URL) {
  console.error('❌ Required environment variables missing (JWT_SECRET, DATABASE_URL)');
  process.exit(1);
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Database connection validation
pool.on('connect', () => {
  console.log('✅ Database connected successfully');
});

pool.on('error', (err) => {
  console.error('❌ Database connection error:', err);
  process.exit(1);
});

// Trust Railway's reverse proxy
app.set('trust proxy', 1);

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
  max: 50, // Limit each IP to 50 auth requests per windowMs
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

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// CORS Configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Hardcoded allowed origins
    const allowedOrigins = [
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:3000', 
      'http://127.0.0.1:3000',
      'http://localhost:8080',
      'http://127.0.0.1:8080'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// Enhanced Input Validation Schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required().trim().max(255).lowercase(),
  password: Joi.string().min(8).max(128).required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .message('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  firstName: Joi.string().required().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
  lastName: Joi.string().required().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
  role: Joi.string().valid('renter', 'landlord').required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().trim().max(255).lowercase(),
  password: Joi.string().required().max(128)
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid authentication token',
      timestamp: new Date().toISOString()
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: 'Invalid token',
        message: 'Your session has expired. Please log in again.',
        timestamp: new Date().toISOString()
      });
    }
    req.user = user;
    next();
  });
};

// Standardized response helpers
const sendErrorResponse = (res, statusCode, error, message, details = null) => {
  const response = {
    error,
    message,
    timestamp: new Date().toISOString()
  };
  
  if (details) {
    response.details = details;
  }
  
  return res.status(statusCode).json(response);
};

const sendSuccessResponse = (res, statusCode, data, message = null) => {
  const response = {
    success: true,
    timestamp: new Date().toISOString(),
    ...data
  };
  
  if (message) {
    response.message = message;
  }
  
  return res.status(statusCode).json(response);
};

// Utility Functions
const sanitizeUser = (user) => {
  const { password_hash, ...sanitizedUser } = user;
  return sanitizedUser;
};

// ✅ OPTIMIZED JWT PAYLOAD - Smaller and more secure
const generateToken = (user) => {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role
    // ✅ Removed firstName and lastName - fetch from /profile when needed
    // This reduces JWT size by ~40-60 characters per token
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    
    res.json({
      status: 'OK',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
      version: '3.0.0',
      security: 'JWT enabled with optimized payload',
      cors: 'Hardcoded origins',
      database: 'Connected'
    });
  } catch (error) {
    console.error('Health check failed:', error);
    sendErrorResponse(res, 503, 'Service Unavailable', 'Database connection failed');
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'RentReviews Authentication Service',
    status: 'running',
    version: '3.0.0',
    endpoints: {
      health: '/health (GET)',
      register: '/register (POST)',
      login: '/login (POST)',
      profile: '/profile (GET) - Auth required',
      refresh: '/refresh (POST) - Auth required',
      'update-profile': '/profile (PUT) - Auth required',
      'change-password': '/change-password (POST) - Auth required',
      'setup-database': '/setup-database (GET)',
      migrate: '/migrate (GET)',
      'check-schema': '/check-schema (GET)'
    },
    security: {
      rateLimit: 'Enabled',
      helmet: 'Enabled',
      jwt: 'Enabled with optimized payload',
      cors: 'Hardcoded - Secure origins only',
      validation: 'Enhanced with sanitization'
    }
  });
});

// Database Migration Endpoint
app.get('/migrate', async (req, res) => {
    try {
        console.log('Starting database migration...');
        
        // Check if account_status column exists
        const checkColumnQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'account_status';
        `;
        
        const columnExists = await pool.query(checkColumnQuery);
        
        if (columnExists.rows.length === 0) {
            console.log('account_status column does not exist, creating it...');
            
            // Add the missing account_status column
            const addColumnQuery = `
                ALTER TABLE users 
                ADD COLUMN account_status VARCHAR(50) DEFAULT 'active';
            `;
            
            await pool.query(addColumnQuery);
            console.log('account_status column added successfully');
            
            // Update existing users to have 'active' status
            const updateExistingUsers = `
                UPDATE users 
                SET account_status = 'active' 
                WHERE account_status IS NULL;
            `;
            
            await pool.query(updateExistingUsers);
            console.log('Updated existing users with active status');
            
            sendSuccessResponse(res, 200, {
                changes: [
                    'Added account_status column to users table',
                    'Set default value to "active"',
                    'Updated existing users'
                ]
            }, 'Database migration completed successfully');
        } else {
            console.log('account_status column already exists');
            sendSuccessResponse(res, 200, {}, 'Database migration not needed - account_status column already exists');
        }
        
    } catch (error) {
        console.error('Migration error:', error);
        sendErrorResponse(res, 500, 'Migration failed', 'Database migration failed', error.message);
    }
});

// Additional endpoint to check current table structure
app.get('/check-schema', async (req, res) => {
    try {
        const schemaQuery = `
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_name = 'users'
            ORDER BY ordinal_position;
        `;
        
        const result = await pool.query(schemaQuery);
        
        sendSuccessResponse(res, 200, {
            table: 'users',
            columns: result.rows
        });
        
    } catch (error) {
        console.error('Schema check error:', error);
        sendErrorResponse(res, 500, 'Schema check failed', 'Failed to check database schema', error.message);
    }
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
        phone VARCHAR(20),
        bio TEXT,
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
      CREATE INDEX IF NOT EXISTS idx_users_account_status ON users(account_status);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_user_id ON verification_tokens(user_id);
    `);

    sendSuccessResponse(res, 200, {
      tables: ['users', 'verification_tokens'],
      indexes: ['idx_users_email', 'idx_users_role', 'idx_users_account_status', 'idx_verification_tokens_token', 'idx_verification_tokens_user_id']
    }, 'Database tables and indexes created successfully');

  } catch (error) {
    console.error('Database setup error:', error);
    sendErrorResponse(res, 500, 'Database setup failed', 'Failed to create database tables', 
      process.env.NODE_ENV === 'development' ? error.message : 'Internal server error');
  }
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    console.log('Registration attempt:', { email: req.body.email, role: req.body.role });
    
    // Validate input
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      console.log('Validation error:', error.details);
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid registration data',
        error.details.map(detail => detail.message));
    }

    const { email, password, firstName, lastName, role } = value;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      console.log('User already exists:', email);
      return sendErrorResponse(res, 409, 'User already exists', 'An account with this email address already exists');
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, role) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, email, first_name, last_name, role, created_at`,
      [email, passwordHash, firstName, lastName, role]
    );

    const newUser = result.rows[0];
    const token = generateToken(newUser);

    console.log('User created successfully:', { id: newUser.id, email: newUser.email });

    sendSuccessResponse(res, 201, {
      user: sanitizeUser(newUser),
      token,
      expiresIn: JWT_EXPIRES_IN
    }, 'User created successfully');

  } catch (error) {
    console.error('Registration error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to create user account');
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    console.log('Login attempt:', { email: req.body.email });
    
    // Validate input
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      console.log('Login validation error:', error.details);
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid login data',
        error.details.map(detail => detail.message));
    }

    const { email, password } = value;

    // Get user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND account_status = $2',
      [email, 'active']
    );

    if (result.rows.length === 0) {
      console.log('User not found or inactive:', email);
      return sendErrorResponse(res, 401, 'Invalid credentials', 'Email or password is incorrect');
    }

    const user = result.rows[0];

    // Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      console.log('Account locked:', email);
      return sendErrorResponse(res, 423, 'Account locked', 'Too many failed login attempts. Please try again later.');
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordValid) {
      console.log('Invalid password for user:', email);
      
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

      return sendErrorResponse(res, 401, 'Invalid credentials', 'Email or password is incorrect');
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

    console.log('Login successful:', { id: user.id, email: user.email });

    sendSuccessResponse(res, 200, {
      user: sanitizeUser(user),
      token,
      expiresIn: JWT_EXPIRES_IN
    }, 'Login successful');

  } catch (error) {
    console.error('Login error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to authenticate user');
  }
});

// Get User Profile (Protected Route) - ✅ NOW INCLUDES NAMES SINCE JWT DOESN'T
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, first_name, last_name, role, phone, bio, 
              email_verified, last_login, created_at, updated_at 
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return sendErrorResponse(res, 404, 'User not found', 'User account does not exist');
    }

    const user = result.rows[0];

    sendSuccessResponse(res, 200, {
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,    // ✅ Names available via /profile
        last_name: user.last_name,      // ✅ Not in JWT anymore
        role: user.role,
        phone: user.phone,
        bio: user.bio,
        email_verified: user.email_verified,
        last_login: user.last_login,
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    });

  } catch (error) {
    console.error('Profile fetch error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch user profile');
  }
});

// Update User Profile (Protected Route) - ✅ NEW ENDPOINT
app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const updateProfileSchema = Joi.object({
      first_name: Joi.string().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
      last_name: Joi.string().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
      phone: Joi.string().trim().pattern(/^[\d\s\-\+\(\)]+$/).max(20).allow(''),
      bio: Joi.string().trim().max(500).allow('')
    }).min(1);

    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid profile data',
        error.details.map(detail => detail.message));
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];
    let paramCount = 0;

    Object.keys(value).forEach(key => {
      if (value[key] !== undefined) {
        paramCount++;
        updateFields.push(`${key} = $${paramCount}`);
        updateValues.push(value[key]);
      }
    });

    // Add updated_at and user ID
    paramCount++;
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(new Date());
    
    paramCount++;
    updateValues.push(req.user.id);

    const updateQuery = `
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, email, first_name, last_name, role, phone, bio, updated_at
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedUser = result.rows[0];

    console.log(`✅ Profile updated for user ${req.user.id}`);

    sendSuccessResponse(res, 200, {
      user: updatedUser
    }, 'Profile updated successfully');

  } catch (error) {
    console.error('Profile update error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to update profile');
  }
});

// Change Password (Protected Route) - ✅ NEW ENDPOINT
app.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const changePasswordSchema = Joi.object({
      current_password: Joi.string().required().max(128),
      new_password: Joi.string().min(8).max(128).required()
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .message('New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character')
    });

    const { error, value } = changePasswordSchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid password data',
        error.details.map(detail => detail.message));
    }

    const { current_password, new_password } = value;

    // Get current user with password
    const userResult = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return sendErrorResponse(res, 404, 'User not found', 'User account does not exist');
    }

    const user = userResult.rows[0];

    // Verify current password
    const passwordValid = await bcrypt.compare(current_password, user.password_hash);
    if (!passwordValid) {
      return sendErrorResponse(res, 401, 'Invalid current password', 'Current password is incorrect');
    }

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(new_password, saltRounds);

    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [newPasswordHash, req.user.id]
    );

    console.log(`✅ Password changed for user ${req.user.id}`);

    sendSuccessResponse(res, 200, {}, 'Password changed successfully');

  } catch (error) {
    console.error('Password change error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to change password');
  }
});

// Refresh Token - ✅ USES OPTIMIZED PAYLOAD
app.post('/refresh', authenticateToken, (req, res) => {
  try {
    // Generate new token with same optimized payload
    const newToken = generateToken(req.user);
    
    sendSuccessResponse(res, 200, {
      token: newToken,
      expiresIn: JWT_EXPIRES_IN
    }, 'Token refreshed successfully');

  } catch (error) {
    console.error('Token refresh error:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to refresh token');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  sendErrorResponse(res, 500, 'Internal server error', 'Something went wrong');
});

// 404 handler
app.use('*', (req, res) => {
  sendErrorResponse(res, 404, 'Not found', 'The requested resource was not found');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔐 Secure Auth service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`JWT: ${process.env.JWT_SECRET ? 'Configured with optimized payload' : 'Warning: Missing secret'}`);
  console.log(`CORS: Hardcoded origins configured`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  console.log(`Security: Enhanced validation and sanitization enabled`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});