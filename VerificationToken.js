const { pool } = require('../config/database');
const { v4: uuidv4 } = require('uuid');

class VerificationToken {
  static async create(userId, type = 'email_verification') {
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // 24 hour expiry

    const query = `
      INSERT INTO verification_tokens (user_id, token, type, expires_at, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING token, expires_at
    `;

    const result = await pool.query(query, [userId, token, type, expiresAt]);
    return result.rows[0];
  }

  static async findByToken(token) {
    const query = `
      SELECT vt.*, u.email, u.id as user_id
      FROM verification_tokens vt
      JOIN users u ON vt.user_id = u.id
      WHERE vt.token = $1 AND vt.expires_at > NOW() AND vt.used = false
    `;
    
    const result = await pool.query(query, [token]);
    return result.rows[0];
  }

  static async markAsUsed(token) {
    const query = `
      UPDATE verification_tokens 
      SET used = true, used_at = NOW()
      WHERE token = $1
    `;
    
    await pool.query(query, [token]);
  }
}

module.exports = VerificationToken;