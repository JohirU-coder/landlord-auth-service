const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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