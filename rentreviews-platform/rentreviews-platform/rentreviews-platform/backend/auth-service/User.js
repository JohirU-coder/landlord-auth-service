const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
  static async create({ email, password, role = 'renter', firstName, lastName }) {
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const query = `
      INSERT INTO users (email, password_hash, role, first_name, last_name, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING id, email, role, first_name, last_name, created_at, email_verified
    `;
    
    const result = await pool.query(query, [email, hashedPassword, role, firstName, lastName]);
    return result.rows[0];
  }

  static async findByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    return result.rows[0];
  }

  static async findById(id) {
    const query = `
      SELECT id, email, role, first_name, last_name, email_verified, 
             landlord_verified, created_at 
      FROM users WHERE id = $1
    `;
    const result = await pool.query(query, [id]);
    return result.rows[0];
  }

  static async verifyEmail(userId) {
    const query = `
      UPDATE users 
      SET email_verified = true, email_verified_at = NOW() 
      WHERE id = $1
      RETURNING id, email, email_verified
    `;
    const result = await pool.query(query, [userId]);
    return result.rows[0];
  }

  static async verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  static async updateProfile(userId, updates) {
    const allowedFields = ['first_name', 'last_name', 'phone', 'bio'];
    const fields = [];
    const values = [];
    let paramCount = 1;

    Object.keys(updates).forEach(key => {
      if (allowedFields.includes(key) && updates[key] !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(updates[key]);
        paramCount++;
      }
    });

    if (fields.length === 0) {
      throw new Error('No valid fields to update');
    }

    values.push(userId);
    const query = `
      UPDATE users 
      SET ${fields.join(', ')}, updated_at = NOW()
      WHERE id = $${paramCount}
      RETURNING id, email, role, first_name, last_name, phone, bio
    `;

    const result = await pool.query(query, values);
    return result.rows[0];
  }
}

module.exports = User;