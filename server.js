require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { Pool } = require('pg');
// Resend is an optional production dependency — server starts fine without it
let Resend;
try {
  ({ Resend } = require('resend'));
} catch {
  console.warn('⚠️  resend package not found — emails will be logged to console (dev mode)');
}

const app = express();
const PORT = process.env.PORT || 8080;

if (!process.env.JWT_SECRET || !process.env.DATABASE_URL) {
  console.error('❌ Required environment variables missing (JWT_SECRET, DATABASE_URL)');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.on('connect', () => console.log('✅ Database connected'));
pool.on('error', (err) => { console.error('❌ Database error:', err); process.exit(1); });

// Resend — requires both the package and RESEND_API_KEY; otherwise emails are logged to console
const resendClient = (Resend && process.env.RESEND_API_KEY) ? new Resend(process.env.RESEND_API_KEY) : null;

// Trust Railway's reverse proxy
app.set('trust proxy', 1);

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

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts', message: 'Please try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests', message: 'Please try again later' }
});

app.use('/login', authLimiter);
app.use('/register', authLimiter);
app.use('/forgot-password', authLimiter);
app.use('/reset-password', authLimiter);
app.use(generalLimiter);

// CORS
const ALLOWED_ORIGINS = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : [])
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
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

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// Validation schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required().max(255).lowercase().trim(),
  password: Joi.string().min(8).max(128).required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .message('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character (@$!%*?&)'),
  firstName: Joi.string().required().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
  lastName: Joi.string().required().trim().min(1).max(50).pattern(/^[a-zA-Z\s'-]+$/),
  role: Joi.string().valid('renter', 'landlord').required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().max(255).lowercase().trim(),
  password: Joi.string().required().max(128)
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().max(255).lowercase().trim()
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().hex().length(64).required(),
  new_password: Joi.string().min(8).max(128).required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .message('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character (@$!%*?&)')
});

const verifyEmailSchema = Joi.object({
  token: Joi.string().hex().length(64).required()
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required', message: 'Please provide a valid authentication token' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token', message: 'Your session has expired. Please log in again.' });
    }
    req.user = user;
    next();
  });
};

// Admin-only middleware
const requireAdminSecret = (req, res, next) => {
  const secret = req.headers['x-admin-secret'];
  if (!process.env.ADMIN_SECRET || secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden', message: 'Admin access required' });
  }
  next();
};

// Utility functions
const sanitizeUser = (user) => {
  const { password_hash, ...sanitized } = user;
  return sanitized;
};

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.first_name,
      lastName: user.last_name,
      email_verified: user.email_verified || false
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

const generateSecureToken = () => crypto.randomBytes(32).toString('hex');

// Email helpers
const sendEmail = async (to, subject, html) => {
  if (!resendClient) {
    // Dev mode: log instead of sending
    console.log(`\n📧 [DEV EMAIL] To: ${to} | Subject: ${subject}`);
    const urlMatch = html.match(/href="(https?:\/\/[^"]+)"/);
    if (urlMatch) console.log(`📧 [DEV EMAIL] Link: ${urlMatch[1]}`);
    console.log('');
    return;
  }
  const { error } = await resendClient.emails.send({
    from: process.env.FROM_EMAIL || 'RentReviews <noreply@rentreviews.com>',
    to,
    subject,
    html
  });
  if (error) {
    console.error('Email send error:', error);
    throw new Error('Failed to send email');
  }
};

const sendVerificationEmail = async (email, token) => {
  const verifyUrl = `${process.env.FRONTEND_URL || 'http://localhost:5500'}/verify-email.html?token=${token}`;
  await sendEmail(email, 'Verify your RentReviews email', `
    <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:40px 32px;text-align:center">
        <h1 style="color:#fff;margin:0;font-size:24px;font-weight:700">RentReviews</h1>
        <p style="color:rgba(255,255,255,.85);margin:8px 0 0;font-size:14px">Rental Property Reviews</p>
      </div>
      <div style="padding:40px 32px">
        <h2 style="margin:0 0 16px;font-size:20px;color:#111">Verify your email address</h2>
        <p style="color:#555;line-height:1.6;margin:0 0 24px">Thanks for signing up! Click the button below to verify your email address. This link expires in 24 hours.</p>
        <a href="${verifyUrl}" style="display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:15px">Verify Email</a>
        <p style="color:#888;font-size:12px;margin:24px 0 0">If you didn't create a RentReviews account, you can safely ignore this email.</p>
      </div>
    </div>
  `);
};

const sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5500'}/reset-password.html?token=${token}`;
  await sendEmail(email, 'Reset your RentReviews password', `
    <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:40px 32px;text-align:center">
        <h1 style="color:#fff;margin:0;font-size:24px;font-weight:700">RentReviews</h1>
        <p style="color:rgba(255,255,255,.85);margin:8px 0 0;font-size:14px">Rental Property Reviews</p>
      </div>
      <div style="padding:40px 32px">
        <h2 style="margin:0 0 16px;font-size:20px;color:#111">Reset your password</h2>
        <p style="color:#555;line-height:1.6;margin:0 0 24px">We received a request to reset your password. Click the button below to choose a new one. This link expires in 15 minutes.</p>
        <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:15px">Reset Password</a>
        <p style="color:#888;font-size:12px;margin:24px 0 0">If you didn't request a password reset, you can safely ignore this email. Your password won't change.</p>
      </div>
    </div>
  `);
};

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT NOW()');
    res.json({
      status: 'OK',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
      version: '3.0.0',
      database: 'Connected',
      email: resendClient ? 'Resend configured' : 'Dev mode (console logging)'
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({ error: 'Service Unavailable', message: 'Database connection failed' });
  }
});

app.get('/', (req, res) => {
  res.json({
    message: 'RentReviews Authentication Service',
    status: 'running',
    version: '3.0.0',
    endpoints: {
      health: '/health (GET)',
      register: '/register (POST)',
      login: '/login (POST)',
      'forgot-password': '/forgot-password (POST)',
      'reset-password': '/reset-password (POST)',
      'verify-email': '/verify-email (POST)',
      'resend-verification': '/resend-verification (POST) — Auth required',
      profile: '/profile (GET) — Auth required',
      refresh: '/refresh (POST) — Auth required'
    }
  });
});

// Admin-only database management endpoints
app.get('/setup-database', requireAdminSecret, async (req, res) => {
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
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
      CREATE INDEX IF NOT EXISTS idx_users_account_status ON users(account_status);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token);
      CREATE INDEX IF NOT EXISTS idx_verification_tokens_user_id ON verification_tokens(user_id);
    `);
    res.json({ success: true, message: 'Database tables and indexes created', tables: ['users', 'verification_tokens'] });
  } catch (error) {
    console.error('Database setup error:', error);
    res.status(500).json({
      error: 'Database setup failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.get('/migrate', requireAdminSecret, async (req, res) => {
  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status VARCHAR(20) DEFAULT 'active'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`);
    res.json({ success: true, message: 'Migration completed' });
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({
      error: 'Migration failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.get('/check-schema', requireAdminSecret, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns WHERE table_name = 'users' ORDER BY ordinal_position
    `);
    res.json({ success: true, table: 'users', columns: result.rows });
  } catch (error) {
    console.error('Schema check error:', error);
    res.status(500).json({
      error: 'Schema check failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// POST /register
app.post('/register', async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Validation failed', details: error.details.map(d => d.message) });
    }

    const { email, password, firstName, lastName, role } = value;

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists', message: 'An account with this email address already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, first_name, last_name, role, email_verified, created_at`,
      [email, passwordHash, firstName, lastName, role]
    );

    const newUser = result.rows[0];

    // Generate and store verification token
    const verifyToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await pool.query(
      'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, $4)',
      [newUser.id, verifyToken, 'email_verification', expiresAt]
    );

    // Send verification email (non-blocking — don't fail registration if email fails)
    sendVerificationEmail(email, verifyToken).catch(err =>
      console.error('Verification email failed to send:', err)
    );

    const token = generateToken(newUser);
    console.log('User created:', { id: newUser.id, email: newUser.email });

    res.status(201).json({
      success: true,
      message: 'Account created. Please check your email to verify your address.',
      user: sanitizeUser(newUser),
      token,
      expiresIn: JWT_EXPIRES_IN,
      email_verification_sent: true
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to create user account' });
  }
});

// POST /login
app.post('/login', async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Validation failed', details: error.details.map(d => d.message) });
    }

    const { email, password } = value;
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND account_status = $2',
      [email, 'active']
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials', message: 'Email or password is incorrect' });
    }

    const user = result.rows[0];

    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      return res.status(423).json({ error: 'Account locked', message: 'Too many failed login attempts. Please try again later.' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      await pool.query(
        `UPDATE users SET
         failed_login_attempts = failed_login_attempts + 1,
         locked_until = CASE WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes' ELSE NULL END
         WHERE id = $1`,
        [user.id]
      );
      return res.status(401).json({ error: 'Invalid credentials', message: 'Email or password is incorrect' });
    }

    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id]
    );

    const token = generateToken(user);
    console.log('Login successful:', { id: user.id, email: user.email });

    res.json({
      success: true,
      message: 'Login successful',
      user: sanitizeUser(user),
      token,
      expiresIn: JWT_EXPIRES_IN,
      email_verified: user.email_verified
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to authenticate user' });
  }
});

// POST /forgot-password
app.post('/forgot-password', async (req, res) => {
  try {
    const { error, value } = forgotPasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Validation failed', details: error.details.map(d => d.message) });
    }

    const { email } = value;

    // Always return success to prevent email enumeration
    const result = await pool.query(
      'SELECT id, email FROM users WHERE email = $1 AND account_status = $2',
      [email, 'active']
    );

    if (result.rows.length > 0) {
      const user = result.rows[0];

      // Invalidate existing reset tokens
      await pool.query(
        "UPDATE verification_tokens SET used = true WHERE user_id = $1 AND type = 'password_reset' AND used = false",
        [user.id]
      );

      const resetToken = generateSecureToken();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      await pool.query(
        'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, $4)',
        [user.id, resetToken, 'password_reset', expiresAt]
      );

      sendPasswordResetEmail(user.email, resetToken).catch(err =>
        console.error('Password reset email failed to send:', err)
      );
    }

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent. Check your inbox (and spam folder).'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to process request' });
  }
});

// POST /reset-password
app.post('/reset-password', async (req, res) => {
  try {
    const { error, value } = resetPasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Validation failed', details: error.details.map(d => d.message) });
    }

    const { token, new_password } = value;

    const tokenResult = await pool.query(
      "SELECT id, user_id, expires_at, used FROM verification_tokens WHERE token = $1 AND type = 'password_reset'",
      [token]
    );

    if (
      tokenResult.rows.length === 0 ||
      tokenResult.rows[0].used ||
      new Date() > new Date(tokenResult.rows[0].expires_at)
    ) {
      return res.status(400).json({ error: 'Invalid or expired token', message: 'This password reset link is invalid or has expired. Please request a new one.' });
    }

    const { user_id, id: tokenId } = tokenResult.rows[0];
    const newPasswordHash = await bcrypt.hash(new_password, 12);

    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newPasswordHash, user_id]);
    await pool.query('UPDATE verification_tokens SET used = true WHERE id = $1', [tokenId]);

    console.log(`✅ Password reset for user ${user_id}`);

    res.json({ success: true, message: 'Password reset successfully. You can now log in with your new password.' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to reset password' });
  }
});

// POST /verify-email
app.post('/verify-email', async (req, res) => {
  try {
    const { error, value } = verifyEmailSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Validation failed', details: error.details.map(d => d.message) });
    }

    const { token } = value;

    const tokenResult = await pool.query(
      "SELECT id, user_id, expires_at, used FROM verification_tokens WHERE token = $1 AND type = 'email_verification'",
      [token]
    );

    if (
      tokenResult.rows.length === 0 ||
      tokenResult.rows[0].used ||
      new Date() > new Date(tokenResult.rows[0].expires_at)
    ) {
      return res.status(400).json({ error: 'Invalid or expired token', message: 'This verification link is invalid or has expired. Request a new one from your dashboard.' });
    }

    const { user_id, id: tokenId } = tokenResult.rows[0];

    await pool.query('UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1', [user_id]);
    await pool.query('UPDATE verification_tokens SET used = true WHERE id = $1', [tokenId]);

    console.log(`✅ Email verified for user ${user_id}`);

    res.json({ success: true, message: 'Email verified successfully. Your account is now fully active.' });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to verify email' });
  }
});

// POST /resend-verification
app.post('/resend-verification', authenticateToken, authLimiter, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, email, email_verified FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found', message: 'User account does not exist' });
    }

    const user = userResult.rows[0];

    if (user.email_verified) {
      return res.status(400).json({ error: 'Already verified', message: 'Your email address is already verified.' });
    }

    // Invalidate old verification tokens
    await pool.query(
      "UPDATE verification_tokens SET used = true WHERE user_id = $1 AND type = 'email_verification' AND used = false",
      [user.id]
    );

    const verifyToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await pool.query(
      'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, $4)',
      [user.id, verifyToken, 'email_verification', expiresAt]
    );

    await sendVerificationEmail(user.email, verifyToken);

    res.json({ success: true, message: 'Verification email sent. Please check your inbox.' });

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to send verification email' });
  }
});

// GET /profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, first_name, last_name, role, email_verified, last_login, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found', message: 'User account does not exist' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to fetch user profile' });
  }
});

// POST /refresh
app.post('/refresh', authenticateToken, (req, res) => {
  try {
    const newToken = generateToken(req.user);
    res.json({ success: true, message: 'Token refreshed', token: newToken, expiresIn: JWT_EXPIRES_IN });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'Failed to refresh token' });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', message: 'Something went wrong' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Not found', message: 'The requested resource was not found' });
});

process.on('SIGTERM', () => { pool.end(() => process.exit(0)); });
process.on('SIGINT', () => { pool.end(() => process.exit(0)); });

// Only bind to port when run directly — tests use supertest with request(app)
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔒 Auth service running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Email: ${resendClient ? 'Resend configured' : 'Dev mode (console logging)'}`);
    console.log(`CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);
  });
}

module.exports = { app, pool };
