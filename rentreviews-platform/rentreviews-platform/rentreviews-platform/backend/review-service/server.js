require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3003;

// Validate required environment variables
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  console.error('❌ Required environment variables missing (DATABASE_URL, JWT_SECRET)');
  process.exit(1);
}

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

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid authentication token'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
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

// Role-based authorization middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Please log in to access this resource'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `This endpoint requires ${roles.join(' or ')} role`
      });
    }

    next();
  };
};

// Rate limiting middleware
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const createReviewLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit review creation to 5 per hour
  message: {
    error: 'Too many review submissions',
    message: 'Maximum 5 reviews can be created per hour'
  }
});

const responseCreateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit landlord responses to 20 per hour
  message: {
    error: 'Too many responses',
    message: 'Maximum 20 responses can be created per hour'
  }
});

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// Security and CORS middleware
app.use(helmet());
app.use(generalLimiter);
app.use(cors({
  origin: [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// Enhanced validation schema for review creation
const createReviewSchema = Joi.object({
  property_id: Joi.number().integer().required(),
  overall_rating: Joi.number().integer().min(1).max(5).required(),
  communication_rating: Joi.number().integer().min(1).max(5).required(),
  maintenance_rating: Joi.number().integer().min(1).max(5).required(),
  property_condition_rating: Joi.number().integer().min(1).max(5).required(),
  value_rating: Joi.number().integer().min(1).max(5).required(),
  title: Joi.string().required().trim().min(10).max(200),
  review_text: Joi.string().required().trim().min(50).max(2000),
  move_in_date: Joi.date().max('now').allow(null),
  move_out_date: Joi.date().min(Joi.ref('move_in_date')).allow(null),
  would_recommend: Joi.boolean().required(),
  anonymous: Joi.boolean().default(false)
});

// Enhanced validation schema for landlord response
const landlordResponseSchema = Joi.object({
  response_text: Joi.string().required().trim().min(20).max(1000)
});

// Enhanced validation schema for review search
const searchReviewsSchema = Joi.object({
  property_id: Joi.number().integer(),
  landlord_id: Joi.number().integer(),
  reviewer_id: Joi.number().integer(),
  min_rating: Joi.number().integer().min(1).max(5),
  max_rating: Joi.number().integer().min(1).max(5).min(Joi.ref('min_rating')),
  sort_by: Joi.string().valid('newest', 'oldest', 'rating_high', 'rating_low', 'most_helpful'),
  limit: Joi.number().integer().min(1).max(50).default(20),
  offset: Joi.number().integer().min(0).default(0),
  include_responses: Joi.boolean().default(true)
});

// Standardized error response helper
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

// Standardized success response helper
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

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    
    res.json({
      status: 'OK',
      service: 'review-service',
      timestamp: new Date().toISOString(),
      version: '2.0.0',
      database: 'Connected',
      authentication: 'Enabled'
    });
  } catch (error) {
    console.error('Health check failed:', error);
    sendErrorResponse(res, 503, 'Service Unavailable', 'Database connection failed');
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'RentReviews Review Service API',
    status: 'running',
    version: '2.0.0',
    endpoints: {
      health: '/health (GET)',
      'setup-database': '/setup-database (GET)',
      'create-review': '/reviews (POST) - Auth required',
      'get-reviews': '/reviews (GET)',
      'get-review': '/reviews/:id (GET)',
      'update-review': '/reviews/:id (PUT) - Auth required',
      'delete-review': '/reviews/:id (DELETE) - Auth required',
      'my-reviews': '/reviews/my (GET) - Auth required',
      'landlord-response': '/reviews/:id/response (POST) - Auth required',
      'review-stats': '/reviews/stats (GET)',
      'mark-helpful': '/reviews/:id/helpful (POST) - Auth required',
      test: '/test (GET)'
    },
    security: {
      authentication: 'JWT required for protected endpoints',
      rateLimit: 'Enabled',
      cors: 'Configured for localhost origins'
    }
  });
});

// Test endpoint
app.get('/test', (req, res) => {
  res.json({
    message: 'Review service test endpoint working!',
    database: process.env.DATABASE_URL ? 'Connected' : 'Not configured',
    jwt_secret: process.env.JWT_SECRET ? 'Configured' : 'Missing',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Database setup endpoint
app.get('/setup-database', async (req, res) => {
  try {
    // Create reviews table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
        reviewer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        overall_rating INTEGER NOT NULL CHECK (overall_rating >= 1 AND overall_rating <= 5),
        communication_rating INTEGER NOT NULL CHECK (communication_rating >= 1 AND communication_rating <= 5),
        maintenance_rating INTEGER NOT NULL CHECK (maintenance_rating >= 1 AND maintenance_rating <= 5),
        property_condition_rating INTEGER NOT NULL CHECK (property_condition_rating >= 1 AND property_condition_rating <= 5),
        value_rating INTEGER NOT NULL CHECK (value_rating >= 1 AND value_rating <= 5),
        title VARCHAR(200) NOT NULL,
        review_text TEXT NOT NULL,
        move_in_date DATE,
        move_out_date DATE,
        would_recommend BOOLEAN NOT NULL,
        anonymous BOOLEAN DEFAULT FALSE,
        verified BOOLEAN DEFAULT FALSE,
        helpful_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(property_id, reviewer_id)
      );
    `);

    // Create landlord responses table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS landlord_responses (
        id SERIAL PRIMARY KEY,
        review_id INTEGER REFERENCES reviews(id) ON DELETE CASCADE,
        landlord_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        response_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(review_id)
      );
    `);

    // Create review helpfulness table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS review_helpfulness (
        id SERIAL PRIMARY KEY,
        review_id INTEGER REFERENCES reviews(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        is_helpful BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(review_id, user_id)
      );
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reviews_property_id ON reviews(property_id);
      CREATE INDEX IF NOT EXISTS idx_reviews_reviewer_id ON reviews(reviewer_id);
      CREATE INDEX IF NOT EXISTS idx_reviews_overall_rating ON reviews(overall_rating);
      CREATE INDEX IF NOT EXISTS idx_reviews_created_at ON reviews(created_at);
      CREATE INDEX IF NOT EXISTS idx_landlord_responses_review_id ON landlord_responses(review_id);
      CREATE INDEX IF NOT EXISTS idx_review_helpfulness_review_id ON review_helpfulness(review_id);
    `);

    sendSuccessResponse(res, 200, { 
      tables: ['reviews', 'landlord_responses', 'review_helpfulness'],
      indexes: ['idx_reviews_property_id', 'idx_reviews_reviewer_id', 'idx_reviews_overall_rating', 'idx_reviews_created_at', 'idx_landlord_responses_review_id', 'idx_review_helpfulness_review_id']
    }, 'Review service database tables and indexes created successfully');
    
  } catch (error) {
    console.error('Database setup error:', error);
    sendErrorResponse(res, 500, 'Database setup failed', 'Failed to create review tables', error.message);
  }
});

// POST /reviews - Create a new review (PROTECTED)
app.post('/reviews', authenticateToken, requireRole(['renter']), createReviewLimiter, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = createReviewSchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid review data',
        error.details.map(detail => detail.message));
    }

    const {
      property_id, overall_rating, communication_rating, maintenance_rating,
      property_condition_rating, value_rating, title, review_text,
      move_in_date, move_out_date, would_recommend, anonymous
    } = value;

    // Use authenticated user's ID as reviewer_id
    const reviewer_id = req.user.id;

    // Verify property exists
    const propertyCheck = await pool.query(
      'SELECT id, landlord_id FROM properties WHERE id = $1',
      [property_id]
    );

    if (propertyCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Property not found', 'The specified property does not exist');
    }

    const property = propertyCheck.rows[0];

    // Prevent landlords from reviewing their own properties
    if (property.landlord_id === reviewer_id) {
      return sendErrorResponse(res, 403, 'Cannot review own property', 'You cannot review your own property');
    }

    // Check for duplicate review (same reviewer + property)
    const duplicateCheck = await pool.query(
      'SELECT id FROM reviews WHERE property_id = $1 AND reviewer_id = $2',
      [property_id, reviewer_id]
    );

    if (duplicateCheck.rows.length > 0) {
      return sendErrorResponse(res, 409, 'Review already exists', 'You have already reviewed this property',
        { existing_review_id: duplicateCheck.rows[0].id });
    }

    // Insert the new review
    const insertQuery = `
      INSERT INTO reviews (
        property_id, reviewer_id, overall_rating, communication_rating, 
        maintenance_rating, property_condition_rating, value_rating,
        title, review_text, move_in_date, move_out_date, would_recommend, anonymous
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `;

    const result = await pool.query(insertQuery, [
      property_id, reviewer_id, overall_rating, communication_rating,
      maintenance_rating, property_condition_rating, value_rating,
      title, review_text, move_in_date, move_out_date, would_recommend, anonymous
    ]);

    const newReview = result.rows[0];

    console.log(`✅ Review created by user ${reviewer_id} for property ${property_id}`);

    sendSuccessResponse(res, 201, {
      review: {
        id: newReview.id,
        property_id: newReview.property_id,
        overall_rating: newReview.overall_rating,
        ratings: {
          communication: newReview.communication_rating,
          maintenance: newReview.maintenance_rating,
          property_condition: newReview.property_condition_rating,
          value: newReview.value_rating
        },
        title: newReview.title,
        review_text: newReview.review_text,
        move_in_date: newReview.move_in_date,
        move_out_date: newReview.move_out_date,
        would_recommend: newReview.would_recommend,
        anonymous: newReview.anonymous,
        verified: newReview.verified,
        helpful_count: newReview.helpful_count,
        created_at: newReview.created_at
      }
    }, 'Review created successfully');

  } catch (error) {
    console.error('Error creating review:', error);
    
    // Handle specific database errors
    if (error.code === '23505') { // Unique constraint violation
      return sendErrorResponse(res, 409, 'Review already exists', 'You have already reviewed this property');
    }
    if (error.code === '23503') { // Foreign key violation
      return sendErrorResponse(res, 400, 'Invalid reference', 'Property or user does not exist');
    }
    
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to create review');
  }
});

// PUT /reviews/:id - Update a review (PROTECTED)
app.put('/reviews/:id', authenticateToken, requireRole(['renter']), async (req, res) => {
  try {
    const reviewId = parseInt(req.params.id);
    
    if (isNaN(reviewId)) {
      return sendErrorResponse(res, 400, 'Invalid review ID', 'Review ID must be a number');
    }

    // Validate request body (allow partial updates)
    const updateSchema = createReviewSchema.fork(
      ['property_id'], // Remove property_id from updates
      (schema) => schema.forbidden()
    ).fork(
      Object.keys(createReviewSchema.describe().keys).filter(key => key !== 'property_id'),
      (schema) => schema.optional()
    ).min(1);

    const { error, value } = updateSchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid update data',
        error.details.map(detail => detail.message));
    }

    // Check if review exists and belongs to the authenticated user
    const reviewCheck = await pool.query(
      'SELECT id, reviewer_id, property_id FROM reviews WHERE id = $1',
      [reviewId]
    );

    if (reviewCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Review not found', 'No review found with the specified ID');
    }

    const review = reviewCheck.rows[0];
    if (review.reviewer_id !== req.user.id) {
      return sendErrorResponse(res, 403, 'Unauthorized', 'You can only update your own reviews');
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

    // Add updated_at and review ID
    paramCount++;
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(new Date());
    
    paramCount++;
    updateValues.push(reviewId);

    const updateQuery = `
      UPDATE reviews 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedReview = result.rows[0];

    console.log(`✅ Review ${reviewId} updated by user ${req.user.id}`);

    sendSuccessResponse(res, 200, {
      review: {
        id: updatedReview.id,
        property_id: updatedReview.property_id,
        overall_rating: updatedReview.overall_rating,
        ratings: {
          communication: updatedReview.communication_rating,
          maintenance: updatedReview.maintenance_rating,
          property_condition: updatedReview.property_condition_rating,
          value: updatedReview.value_rating
        },
        title: updatedReview.title,
        review_text: updatedReview.review_text,
        move_in_date: updatedReview.move_in_date,
        move_out_date: updatedReview.move_out_date,
        would_recommend: updatedReview.would_recommend,
        anonymous: updatedReview.anonymous,
        verified: updatedReview.verified,
        helpful_count: updatedReview.helpful_count,
        created_at: updatedReview.created_at,
        updated_at: updatedReview.updated_at
      }
    }, 'Review updated successfully');

  } catch (error) {
    console.error('Error updating review:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to update review');
  }
});

// DELETE /reviews/:id - Delete a review (PROTECTED)
app.delete('/reviews/:id', authenticateToken, requireRole(['renter']), async (req, res) => {
  try {
    const reviewId = parseInt(req.params.id);
    
    if (isNaN(reviewId)) {
      return sendErrorResponse(res, 400, 'Invalid review ID', 'Review ID must be a number');
    }

    // Check if review exists and belongs to the authenticated user
    const reviewCheck = await pool.query(
      'SELECT id, reviewer_id, title FROM reviews WHERE id = $1',
      [reviewId]
    );

    if (reviewCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Review not found', 'No review found with the specified ID');
    }

    const review = reviewCheck.rows[0];
    if (review.reviewer_id !== req.user.id) {
      return sendErrorResponse(res, 403, 'Unauthorized', 'You can only delete your own reviews');
    }

    // Delete the review (cascades to responses and helpfulness)
    await pool.query('DELETE FROM reviews WHERE id = $1', [reviewId]);

    console.log(`✅ Review ${reviewId} deleted by user ${req.user.id}: ${review.title}`);

    sendSuccessResponse(res, 200, {}, 'Review deleted successfully');

  } catch (error) {
    console.error('Error deleting review:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to delete review');
  }
});

// GET /reviews/my - Get current user's reviews (PROTECTED)
app.get('/reviews/my', authenticateToken, requireRole(['renter']), async (req, res) => {
  try {
    const query = `
      SELECT 
        r.*,
        p.address,
        p.city,
        p.state,
        lr.response_text as landlord_response,
        lr.created_at as response_created_at
      FROM reviews r
      JOIN properties p ON r.property_id = p.id
      LEFT JOIN landlord_responses lr ON r.id = lr.review_id
      WHERE r.reviewer_id = $1
      ORDER BY r.created_at DESC
    `;

    const result = await pool.query(query, [req.user.id]);
    const reviews = result.rows;

    const formattedReviews = reviews.map(review => ({
      id: review.id,
      property: {
        id: review.property_id,
        address: review.address,
        city: review.city,
        state: review.state
      },
      ratings: {
        overall: review.overall_rating,
        communication: review.communication_rating,
        maintenance: review.maintenance_rating,
        property_condition: review.property_condition_rating,
        value: review.value_rating
      },
      title: review.title,
      review_text: review.review_text,
      move_in_date: review.move_in_date,
      move_out_date: review.move_out_date,
      would_recommend: review.would_recommend,
      anonymous: review.anonymous,
      verified: review.verified,
      helpful_count: review.helpful_count,
      created_at: review.created_at,
      updated_at: review.updated_at,
      landlord_response: review.landlord_response ? {
        text: review.landlord_response,
        created_at: review.response_created_at
      } : null
    }));

    sendSuccessResponse(res, 200, {
      reviews: formattedReviews,
      total_count: reviews.length
    });

  } catch (error) {
    console.error('Error fetching user reviews:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch your reviews');
  }
});

// GET /reviews/:id - Get a specific review by ID (PUBLIC)
app.get('/reviews/:id', async (req, res) => {
  try {
    const reviewId = parseInt(req.params.id);
    
    if (isNaN(reviewId)) {
      return sendErrorResponse(res, 400, 'Invalid review ID', 'Review ID must be a number');
    }

    const query = `
      SELECT 
        r.*,
        p.address,
        p.city,
        p.state,
        u.first_name as reviewer_first_name,
        u.last_name as reviewer_last_name,
        lr.response_text as landlord_response,
        lr.created_at as response_created_at,
        lu.first_name as landlord_first_name,
        lu.last_name as landlord_last_name
      FROM reviews r
      JOIN properties p ON r.property_id = p.id
      LEFT JOIN users u ON r.reviewer_id = u.id AND r.anonymous = false
      LEFT JOIN landlord_responses lr ON r.id = lr.review_id
      LEFT JOIN users lu ON lr.landlord_id = lu.id
      WHERE r.id = $1
    `;

    const result = await pool.query(query, [reviewId]);

    if (result.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Review not found', 'No review found with the specified ID');
    }

    const review = result.rows[0];

    sendSuccessResponse(res, 200, {
      review: {
        id: review.id,
        property: {
          id: review.property_id,
          address: review.address,
          city: review.city,
          state: review.state
        },
        reviewer: review.anonymous ? null : {
          first_name: review.reviewer_first_name,
          last_name: review.reviewer_last_name
        },
        ratings: {
          overall: review.overall_rating,
          communication: review.communication_rating,
          maintenance: review.maintenance_rating,
          property_condition: review.property_condition_rating,
          value: review.value_rating
        },
        title: review.title,
        review_text: review.review_text,
        move_in_date: review.move_in_date,
        move_out_date: review.move_out_date,
        would_recommend: review.would_recommend,
        anonymous: review.anonymous,
        verified: review.verified,
        helpful_count: review.helpful_count,
        created_at: review.created_at,
        updated_at: review.updated_at,
        landlord_response: review.landlord_response ? {
          text: review.landlord_response,
          created_at: review.response_created_at,
          landlord: {
            first_name: review.landlord_first_name,
            last_name: review.landlord_last_name
          }
        } : null
      }
    });

  } catch (error) {
    console.error('Error fetching review:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch review');
  }
});

// GET /reviews - Search and filter reviews (PUBLIC)
app.get('/reviews', async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = searchReviewsSchema.validate(req.query);
    if (error) {
      return sendErrorResponse(res, 400, 'Invalid search parameters', 'Invalid search parameters',
        error.details.map(detail => detail.message));
    }

    const {
      property_id, landlord_id, reviewer_id, min_rating, max_rating,
      sort_by = 'newest', limit = 20, offset = 0, include_responses = true
    } = value;

    // Build dynamic WHERE clause
    let whereConditions = [];
    let queryParams = [];
    let paramCount = 0;

    if (property_id) {
      paramCount++;
      whereConditions.push(`r.property_id = $${paramCount}`);
      queryParams.push(property_id);
    }

    if (landlord_id) {
      paramCount++;
      whereConditions.push(`p.landlord_id = $${paramCount}`);
      queryParams.push(landlord_id);
    }

    if (reviewer_id) {
      paramCount++;
      whereConditions.push(`r.reviewer_id = $${paramCount}`);
      queryParams.push(reviewer_id);
    }

    if (min_rating) {
      paramCount++;
      whereConditions.push(`r.overall_rating >= $${paramCount}`);
      queryParams.push(min_rating);
    }

    if (max_rating) {
      paramCount++;
      whereConditions.push(`r.overall_rating <= $${paramCount}`);
      queryParams.push(max_rating);
    }

    const whereClause = whereConditions.length > 0 
      ? `WHERE ${whereConditions.join(' AND ')}`
      : '';

    // Build ORDER BY clause
    let orderClause;
    switch (sort_by) {
      case 'oldest':
        orderClause = 'ORDER BY r.created_at ASC';
        break;
      case 'rating_high':
        orderClause = 'ORDER BY r.overall_rating DESC, r.created_at DESC';
        break;
      case 'rating_low':
        orderClause = 'ORDER BY r.overall_rating ASC, r.created_at DESC';
        break;
      case 'most_helpful':
        orderClause = 'ORDER BY r.helpful_count DESC, r.created_at DESC';
        break;
      case 'newest':
      default:
        orderClause = 'ORDER BY r.created_at DESC';
        break;
    }

    // Add pagination parameters
    paramCount++;
    const limitParam = `$${paramCount}`;
    queryParams.push(limit);
    
    paramCount++;
    const offsetParam = `$${paramCount}`;
    queryParams.push(offset);

    // Main search query
    const responseJoin = include_responses 
      ? 'LEFT JOIN landlord_responses lr ON r.id = lr.review_id LEFT JOIN users lu ON lr.landlord_id = lu.id'
      : '';
    
    const responseFields = include_responses
      ? ', lr.response_text as landlord_response, lr.created_at as response_created_at, lu.first_name as landlord_first_name, lu.last_name as landlord_last_name'
      : '';

    const searchQuery = `
      SELECT 
        r.*,
        p.address,
        p.city,
        p.state,
        u.first_name as reviewer_first_name,
        u.last_name as reviewer_last_name
        ${responseFields}
      FROM reviews r
      JOIN properties p ON r.property_id = p.id
      LEFT JOIN users u ON r.reviewer_id = u.id AND r.anonymous = false
      ${responseJoin}
      ${whereClause}
      ${orderClause}
      LIMIT ${limitParam} OFFSET ${offsetParam}
    `;

    // Count query for pagination
    const countQuery = `
      SELECT COUNT(*) as total
      FROM reviews r
      JOIN properties p ON r.property_id = p.id
      ${whereClause}
    `;

    const [searchResult, countResult] = await Promise.all([
      pool.query(searchQuery, queryParams),
      pool.query(countQuery, queryParams.slice(0, -2))
    ]);

    const reviews = searchResult.rows;
    const totalCount = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(totalCount / limit);
    const currentPage = Math.floor(offset / limit) + 1;

    // Format response
    const formattedReviews = reviews.map(review => ({
      id: review.id,
      property: {
        id: review.property_id,
        address: review.address,
        city: review.city,
        state: review.state
      },
      reviewer: review.anonymous ? null : {
        first_name: review.reviewer_first_name,
        last_name: review.reviewer_last_name
      },
      ratings: {
        overall: review.overall_rating,
        communication: review.communication_rating,
        maintenance: review.maintenance_rating,
        property_condition: review.property_condition_rating,
        value: review.value_rating
      },
      title: review.title,
      review_text: review.review_text,
      move_in_date: review.move_in_date,
      move_out_date: review.move_out_date,
      would_recommend: review.would_recommend,
      anonymous: review.anonymous,
      verified: review.verified,
      helpful_count: review.helpful_count,
      created_at: review.created_at,
      updated_at: review.updated_at,
      landlord_response: (include_responses && review.landlord_response) ? {
        text: review.landlord_response,
        created_at: review.response_created_at,
        landlord: {
          first_name: review.landlord_first_name,
          last_name: review.landlord_last_name
        }
      } : null
    }));

    sendSuccessResponse(res, 200, {
      reviews: formattedReviews,
      pagination: {
        total_count: totalCount,
        total_pages: totalPages,
        current_page: currentPage,
        limit: limit,
        offset: offset,
        has_next: currentPage < totalPages,
        has_previous: currentPage > 1
      },
      filters_applied: {
        property_id, landlord_id, reviewer_id,
        rating_range: min_rating || max_rating ? { min: min_rating, max: max_rating } : null,
        sort_by, include_responses
      }
    });

  } catch (error) {
    console.error('Error searching reviews:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to search reviews');
  }
});

// POST /reviews/:id/response - Landlord response to review (PROTECTED)
app.post('/reviews/:id/response', authenticateToken, requireRole(['landlord']), responseCreateLimiter, async (req, res) => {
  try {
    const reviewId = parseInt(req.params.id);
    
    if (isNaN(reviewId)) {
      return sendErrorResponse(res, 400, 'Invalid review ID', 'Review ID must be a number');
    }

    // Validate request body
    const { error, value } = landlordResponseSchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid response data',
        error.details.map(detail => detail.message));
    }

    const { response_text } = value;
    const landlord_id = req.user.id;

    // Verify review exists and get property info
    const reviewCheck = await pool.query(`
      SELECT r.id, p.landlord_id as property_landlord_id, r.title
      FROM reviews r
      JOIN properties p ON r.property_id = p.id
      WHERE r.id = $1
    `, [reviewId]);

    if (reviewCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Review not found', 'The specified review does not exist');
    }

    const review = reviewCheck.rows[0];

    // Verify landlord owns the property
    if (review.property_landlord_id !== landlord_id) {
      return sendErrorResponse(res, 403, 'Unauthorized', 'You can only respond to reviews of your own properties');
    }

    // Check if response already exists
    const existingResponse = await pool.query(
      'SELECT id FROM landlord_responses WHERE review_id = $1',
      [reviewId]
    );

    if (existingResponse.rows.length > 0) {
      return sendErrorResponse(res, 409, 'Response already exists', 'You have already responded to this review');
    }

    // Insert the response
    const insertQuery = `
      INSERT INTO landlord_responses (review_id, landlord_id, response_text)
      VALUES ($1, $2, $3)
      RETURNING *
    `;

    const result = await pool.query(insertQuery, [reviewId, landlord_id, response_text]);
    const newResponse = result.rows[0];

    console.log(`✅ Response created by landlord ${landlord_id} for review ${reviewId}`);

    sendSuccessResponse(res, 201, {
      response: {
        id: newResponse.id,
        review_id: newResponse.review_id,
        response_text: newResponse.response_text,
        created_at: newResponse.created_at
      }
    }, 'Response added successfully');

  } catch (error) {
    console.error('Error creating landlord response:', error);
    
    if (error.code === '23505') { // Unique constraint violation
      return sendErrorResponse(res, 409, 'Response already exists', 'You have already responded to this review');
    }
    
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to create response');
  }
});

// POST /reviews/:id/helpful - Mark review as helpful (PROTECTED)
app.post('/reviews/:id/helpful', authenticateToken, async (req, res) => {
  try {
    const reviewId = parseInt(req.params.id);
    
    if (isNaN(reviewId)) {
      return sendErrorResponse(res, 400, 'Invalid review ID', 'Review ID must be a number');
    }

    const { is_helpful } = req.body;
    
    if (typeof is_helpful !== 'boolean') {
      return sendErrorResponse(res, 400, 'Invalid helpfulness value', 'is_helpful must be a boolean');
    }

    const user_id = req.user.id;

    // Verify review exists
    const reviewCheck = await pool.query('SELECT id FROM reviews WHERE id = $1', [reviewId]);
    if (reviewCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Review not found', 'The specified review does not exist');
    }

    // Insert or update helpfulness rating
    const upsertQuery = `
      INSERT INTO review_helpfulness (review_id, user_id, is_helpful)
      VALUES ($1, $2, $3)
      ON CONFLICT (review_id, user_id)
      DO UPDATE SET is_helpful = EXCLUDED.is_helpful, created_at = NOW()
      RETURNING *
    `;

    await pool.query(upsertQuery, [reviewId, user_id, is_helpful]);

    // Update helpful count on review
    const updateCountQuery = `
      UPDATE reviews 
      SET helpful_count = (
        SELECT COUNT(*) 
        FROM review_helpfulness 
        WHERE review_id = $1 AND is_helpful = true
      )
      WHERE id = $1
      RETURNING helpful_count
    `;

    const countResult = await pool.query(updateCountQuery, [reviewId]);
    const newHelpfulCount = countResult.rows[0].helpful_count;

    console.log(`✅ Review ${reviewId} marked as ${is_helpful ? 'helpful' : 'not helpful'} by user ${user_id}`);

    sendSuccessResponse(res, 200, {
      helpful_count: newHelpfulCount,
      user_rating: is_helpful
    }, 'Helpfulness rating recorded successfully');

  } catch (error) {
    console.error('Error recording helpfulness:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to record helpfulness rating');
  }
});

// GET /reviews/stats - Review statistics (PUBLIC)
app.get('/reviews/stats', async (req, res) => {
  try {
    const statsQuery = `
      SELECT 
        COUNT(*) as total_reviews,
        COUNT(CASE WHEN verified = true THEN 1 END) as verified_reviews,
        AVG(overall_rating) as avg_overall_rating,
        AVG(communication_rating) as avg_communication_rating,
        AVG(maintenance_rating) as avg_maintenance_rating,
        AVG(property_condition_rating) as avg_property_condition_rating,
        AVG(value_rating) as avg_value_rating,
        COUNT(CASE WHEN would_recommend = true THEN 1 END) as would_recommend_count,
        COUNT(CASE WHEN anonymous = true THEN 1 END) as anonymous_reviews,
        COUNT(DISTINCT property_id) as properties_reviewed,
        COUNT(DISTINCT reviewer_id) as unique_reviewers
      FROM reviews
    `;

    // Additional stats for responses
    const responseStatsQuery = `
      SELECT 
        COUNT(*) as total_responses,
        COUNT(DISTINCT landlord_id) as responding_landlords
      FROM landlord_responses
    `;

    const [statsResult, responseStatsResult] = await Promise.all([
      pool.query(statsQuery),
      pool.query(responseStatsQuery)
    ]);

    const stats = statsResult.rows[0];
    const responseStats = responseStatsResult.rows[0];

    sendSuccessResponse(res, 200, {
      statistics: {
        total_reviews: parseInt(stats.total_reviews),
        verified_reviews: parseInt(stats.verified_reviews),
        verification_rate: stats.total_reviews > 0 
          ? Math.round((stats.verified_reviews / stats.total_reviews) * 100) 
          : 0,
        average_ratings: {
          overall: stats.avg_overall_rating ? Math.round(parseFloat(stats.avg_overall_rating) * 10) / 10 : null,
          communication: stats.avg_communication_rating ? Math.round(parseFloat(stats.avg_communication_rating) * 10) / 10 : null,
          maintenance: stats.avg_maintenance_rating ? Math.round(parseFloat(stats.avg_maintenance_rating) * 10) / 10 : null,
          property_condition: stats.avg_property_condition_rating ? Math.round(parseFloat(stats.avg_property_condition_rating) * 10) / 10 : null,
          value: stats.avg_value_rating ? Math.round(parseFloat(stats.avg_value_rating) * 10) / 10 : null
        },
        recommendation_rate: stats.total_reviews > 0 
          ? Math.round((stats.would_recommend_count / stats.total_reviews) * 100) 
          : 0,
        anonymous_rate: stats.total_reviews > 0 
          ? Math.round((stats.anonymous_reviews / stats.total_reviews) * 100) 
          : 0,
        coverage: {
          properties_reviewed: parseInt(stats.properties_reviewed),
          unique_reviewers: parseInt(stats.unique_reviewers)
        },
        engagement: {
          total_responses: parseInt(responseStats.total_responses),
          responding_landlords: parseInt(responseStats.responding_landlords),
          response_rate: stats.total_reviews > 0 
            ? Math.round((responseStats.total_responses / stats.total_reviews) * 100) 
            : 0
        }
      }
    });

  } catch (error) {
    console.error('Error fetching review statistics:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch review statistics');
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`⭐ Review service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  console.log(`JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Missing'}`);
  console.log(`Authentication: Enabled`);
  console.log(`Rate Limiting: Enabled`);
});