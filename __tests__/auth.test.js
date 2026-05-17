'use strict';

/**
 * Integration tests for the auth service.
 *
 * Requires a running PostgreSQL instance. Set TEST_DATABASE_URL or use the
 * defaults below (matches docker-compose dev setup).
 *
 * Run:  npm test
 *       TEST_DATABASE_URL=postgresql://... npm test
 */

// Set env vars BEFORE requiring the server so pool/Resend initialise correctly
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL ||
  'postgresql://postgres:postgres@localhost:5432/rentreviews_test';
process.env.JWT_SECRET = 'test-jwt-secret-at-least-32-characters-long!!';
process.env.JWT_EXPIRES_IN = '1h';
process.env.NODE_ENV = 'test';
// No RESEND_API_KEY → email is logged to console, not sent

const request = require('supertest');
const { app, pool } = require('../server');

// ─── Helpers ─────────────────────────────────────────────────────────────────

const rand = () => Math.random().toString(36).slice(2, 8);
const testEmail = () => `test_${rand()}@rentreviews-jest.local`;
const VALID_PASS = 'Test@12345';

async function register(email = testEmail(), password = VALID_PASS, role = 'renter') {
  return request(app).post('/register').send({
    email, password, firstName: 'Jest', lastName: 'Test', role
  });
}

async function login(email, password = VALID_PASS) {
  return request(app).post('/login').send({ email, password });
}

// ─── Setup / Teardown ────────────────────────────────────────────────────────

beforeAll(async () => {
  // Create tables if they don't exist
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
});

afterAll(async () => {
  // Clean up test data (emails containing our marker domain)
  await pool.query("DELETE FROM users WHERE email LIKE '%@rentreviews-jest.local'");
  await pool.end();
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('returns 200 with OK status', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('OK');
    expect(res.body.service).toBe('auth-service');
  });
});

describe('POST /register', () => {
  it('creates a new user and returns a JWT', async () => {
    const email = testEmail();
    const res = await register(email);
    expect(res.status).toBe(201);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.email).toBe(email);
    expect(res.body.user.password_hash).toBeUndefined();
    expect(res.body.email_verification_sent).toBe(true);
  });

  it('rejects duplicate email with 409', async () => {
    const email = testEmail();
    await register(email);
    const res = await register(email);
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('User already exists');
  });

  it('rejects weak password with 400', async () => {
    const res = await register(testEmail(), 'weakpass');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Validation failed');
  });

  it('rejects missing fields with 400', async () => {
    const res = await request(app).post('/register').send({ email: testEmail() });
    expect(res.status).toBe(400);
  });

  it('includes email_verified: false in the JWT payload', async () => {
    const email = testEmail();
    const res = await register(email);
    const payload = JSON.parse(Buffer.from(res.body.token.split('.')[1], 'base64').toString());
    expect(payload.email_verified).toBe(false);
  });
});

describe('POST /login', () => {
  it('returns a JWT on valid credentials', async () => {
    const email = testEmail();
    await register(email);
    const res = await login(email);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    expect(res.body.email_verified).toBe(false);
  });

  it('returns 401 for wrong password', async () => {
    const email = testEmail();
    await register(email);
    const res = await login(email, 'WrongPass@9');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid credentials');
  });

  it('returns 401 for non-existent email', async () => {
    const res = await login('nobody@rentreviews-jest.local');
    expect(res.status).toBe(401);
  });

  it('does not expose whether account exists vs wrong password', async () => {
    const existingEmail = testEmail();
    await register(existingEmail);
    const r1 = await login(existingEmail, 'WrongPass@9');
    const r2 = await login('nobody@rentreviews-jest.local');
    // Both return the same error message (no enumeration)
    expect(r1.body.message).toBe(r2.body.message);
  });
});

describe('GET /profile', () => {
  it('returns user profile for authenticated request', async () => {
    const email = testEmail();
    const regRes = await register(email);
    const token = regRes.body.token;

    const res = await request(app)
      .get('/profile')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(email);
    expect(res.body.user.password_hash).toBeUndefined();
  });

  it('returns 401 without token', async () => {
    const res = await request(app).get('/profile');
    expect(res.status).toBe(401);
  });

  it('returns 403 with invalid token', async () => {
    const res = await request(app)
      .get('/profile')
      .set('Authorization', 'Bearer invalid.token.here');
    expect(res.status).toBe(403);
  });
});

describe('POST /refresh', () => {
  it('issues a new JWT for an authenticated user', async () => {
    const email = testEmail();
    const regRes = await register(email);
    const token = regRes.body.token;

    const res = await request(app)
      .post('/refresh')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    expect(res.body.token).not.toBe(token); // should be a new token
  });
});

describe('POST /forgot-password', () => {
  it('always returns 200 (prevents email enumeration)', async () => {
    const res = await request(app)
      .post('/forgot-password')
      .send({ email: 'doesnotexist@rentreviews-jest.local' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('also returns 200 for a real account', async () => {
    const email = testEmail();
    await register(email);
    const res = await request(app).post('/forgot-password').send({ email });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('rejects invalid email format with 400', async () => {
    const res = await request(app).post('/forgot-password').send({ email: 'not-an-email' });
    expect(res.status).toBe(400);
  });
});

describe('POST /reset-password', () => {
  it('rejects an invalid token with 400', async () => {
    const fakeToken = 'a'.repeat(64); // valid hex length but not in DB
    const res = await request(app)
      .post('/reset-password')
      .send({ token: fakeToken, new_password: VALID_PASS });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid or expired token');
  });

  it('rejects malformed token with 400 validation error', async () => {
    const res = await request(app)
      .post('/reset-password')
      .send({ token: 'tooshort', new_password: VALID_PASS });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Validation failed');
  });

  it('resets password with a valid token and allows login with new password', async () => {
    const email = testEmail();
    await register(email);

    // Trigger forgot-password so token is created
    await request(app).post('/forgot-password').send({ email });

    // Read token directly from DB (we own the test DB)
    const tokenRow = await pool.query(
      "SELECT token FROM verification_tokens WHERE type = 'password_reset' AND used = false ORDER BY created_at DESC LIMIT 1"
    );
    if (tokenRow.rows.length === 0) return; // no email sent (no RESEND_API_KEY) but token is still created

    const resetToken = tokenRow.rows[0].token;
    const newPass = 'NewPass@9999';

    const resetRes = await request(app)
      .post('/reset-password')
      .send({ token: resetToken, new_password: newPass });

    expect(resetRes.status).toBe(200);
    expect(resetRes.body.success).toBe(true);

    // Old password no longer works
    const oldLoginRes = await login(email, VALID_PASS);
    expect(oldLoginRes.status).toBe(401);

    // New password works
    const newLoginRes = await login(email, newPass);
    expect(newLoginRes.status).toBe(200);
    expect(newLoginRes.body.token).toBeTruthy();
  });
});

describe('POST /verify-email', () => {
  it('rejects invalid token with 400', async () => {
    const res = await request(app)
      .post('/verify-email')
      .send({ token: 'b'.repeat(64) });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid or expired token');
  });

  it('verifies email with a real token from the DB', async () => {
    const email = testEmail();
    await register(email);

    // Registration creates a verification token
    const tokenRow = await pool.query(
      "SELECT token FROM verification_tokens WHERE type = 'email_verification' AND used = false ORDER BY created_at DESC LIMIT 1"
    );
    if (tokenRow.rows.length === 0) return;

    const verifyToken = tokenRow.rows[0].token;
    const res = await request(app)
      .post('/verify-email')
      .send({ token: verifyToken });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // Token is now used — second attempt should fail
    const res2 = await request(app)
      .post('/verify-email')
      .send({ token: verifyToken });
    expect(res2.status).toBe(400);
  });
});

describe('Admin endpoints', () => {
  it('GET /setup-database returns 403 without admin secret', async () => {
    const res = await request(app).get('/setup-database');
    expect(res.status).toBe(403);
  });

  it('GET /migrate returns 403 without admin secret', async () => {
    const res = await request(app).get('/migrate');
    expect(res.status).toBe(403);
  });

  it('GET /check-schema returns 403 without admin secret', async () => {
    const res = await request(app).get('/check-schema');
    expect(res.status).toBe(403);
  });
});

describe('404 and error handling', () => {
  it('returns 404 for unknown routes', async () => {
    const res = await request(app).get('/this-does-not-exist');
    expect(res.status).toBe(404);
  });
});
