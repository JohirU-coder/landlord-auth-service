const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway's managed Postgres presents a self-signed cert on this proxy
  // endpoint, so rejectUnauthorized: true fails every connection (verified
  // directly against production). Traffic is still encrypted -- this is
  // Railway's standard connection posture, not a rollback of TLS entirely.
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const connectDB = async () => {
  try {
    await pool.query('SELECT NOW()');
    return pool;
  } catch (error) {
    throw error;
  }
};

module.exports = {
  pool,
  connectDB
};