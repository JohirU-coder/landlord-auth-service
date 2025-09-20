require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3002;

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

const createPropertyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit property creation to 10 per hour
  message: {
    error: 'Too many property creations',
    message: 'Maximum 10 properties can be created per hour'
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

// Enhanced validation schema for property creation
const createPropertySchema = Joi.object({
  address: Joi.string().required().trim().min(5).max(500),
  city: Joi.string().required().trim().min(2).max(100),
  state: Joi.string().required().trim().min(2).max(50),
  zip_code: Joi.string().required().trim().pattern(/^\d{5}(-\d{4})?$/), // US zip code format
  rent_amount: Joi.number().positive().precision(2).max(50000), // Max $50k rent
  bedrooms: Joi.number().integer().min(0).max(20),
  bathrooms: Joi.number().positive().precision(1).max(20),
  square_feet: Joi.number().integer().positive().max(50000),
  description: Joi.string().trim().max(2000).allow('').default(''),
  data_source: Joi.string().valid('landlord_submitted', 'community_submitted').default('landlord_submitted'),
  source_url: Joi.string().uri().allow('').default(''),
  verification_status: Joi.string().valid('verified', 'community_submitted', 'pending_verification').default('verified')
});

// Enhanced validation schema for property updates
const updatePropertySchema = Joi.object({
  address: Joi.string().trim().min(5).max(500),
  city: Joi.string().trim().min(2).max(100),
  state: Joi.string().trim().min(2).max(50),
  zip_code: Joi.string().trim().pattern(/^\d{5}(-\d{4})?$/),
  rent_amount: Joi.number().positive().precision(2).max(50000),
  bedrooms: Joi.number().integer().min(0).max(20),
  bathrooms: Joi.number().positive().precision(1).max(20),
  square_feet: Joi.number().integer().positive().max(50000),
  description: Joi.string().trim().max(2000).allow('')
}).min(1); // At least one field must be provided

// Validation schema for property search (enhanced)
const searchPropertiesSchema = Joi.object({
  city: Joi.string().trim().min(2).max(100),
  state: Joi.string().trim().min(2).max(50),
  zip_code: Joi.string().trim().pattern(/^\d{5}(-\d{4})?$/),
  min_rent: Joi.number().positive().max(50000),
  max_rent: Joi.number().positive().max(50000),
  min_bedrooms: Joi.number().integer().min(0).max(20),
  max_bedrooms: Joi.number().integer().min(0).max(20),
  min_bathrooms: Joi.number().positive().precision(1).max(20),
  max_bathrooms: Joi.number().positive().precision(1).max(20),
  min_sqft: Joi.number().integer().positive().max(50000),
  max_sqft: Joi.number().integer().positive().max(50000),
  landlord_verified: Joi.boolean(),
  verification_status: Joi.string().valid('verified', 'community_submitted', 'pending_verification'),
  sort_by: Joi.string().valid('rent_asc', 'rent_desc', 'newest', 'oldest', 'sqft_asc', 'sqft_desc'),
  limit: Joi.number().integer().min(1).max(100).default(20),
  offset: Joi.number().integer().min(0).default(0)
}).custom((value, helpers) => {
  // Custom validation to ensure logical ranges
  if (value.min_rent && value.max_rent && value.min_rent >= value.max_rent) {
    return helpers.error('custom.rentRange');
  }
  if (value.min_bedrooms !== undefined && value.max_bedrooms !== undefined && value.min_bedrooms > value.max_bedrooms) {
    return helpers.error('custom.bedroomsRange');
  }
  if (value.min_bathrooms && value.max_bathrooms && value.min_bathrooms > value.max_bathrooms) {
    return helpers.error('custom.bathroomsRange');
  }
  if (value.min_sqft && value.max_sqft && value.min_sqft > value.max_sqft) {
    return helpers.error('custom.sqftRange');
  }
  return value;
}, 'Range validation').messages({
  'custom.rentRange': 'min_rent must be less than max_rent',
  'custom.bedroomsRange': 'min_bedrooms must be less than or equal to max_bedrooms',
  'custom.bathroomsRange': 'min_bathrooms must be less than max_bathrooms',
  'custom.sqftRange': 'min_sqft must be less than max_sqft'
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
      service: 'property-service',
      timestamp: new Date().toISOString(),
      version: '2.1.0',
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
    message: 'RentReviews Property Service API',
    status: 'running',
    version: '2.1.0',
    endpoints: {
      health: '/health (GET)',
      'setup-database': '/setup-database (GET)',
      'create-property': '/properties (POST) - Auth required',
      'update-property': '/properties/:id (PUT) - Auth required',
      'delete-property': '/properties/:id (DELETE) - Auth required',
      'get-property': '/properties/:id (GET)',
      'search-properties': '/properties (GET)',
      'my-properties': '/properties/my (GET) - Auth required',
      'property-stats': '/properties/stats (GET)',
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
    message: 'Property service test endpoint working!',
    database: process.env.DATABASE_URL ? 'Connected' : 'Not configured',
    jwt_secret: process.env.JWT_SECRET ? 'Configured' : 'Missing',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Database setup endpoint - UPDATED with new columns
app.get('/setup-database', async (req, res) => {
  try {
    // Create properties table with new tracking columns
    await pool.query(`
      CREATE TABLE IF NOT EXISTS properties (
        id SERIAL PRIMARY KEY,
        address TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(50) NOT NULL,
        zip_code VARCHAR(20) NOT NULL,
        rent_amount DECIMAL(10,2),
        bedrooms INTEGER,
        bathrooms DECIMAL(3,1),
        square_feet INTEGER,
        description TEXT,
        landlord_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        landlord_verified BOOLEAN DEFAULT FALSE,
        data_source VARCHAR(50) DEFAULT 'landlord_submitted',
        source_url TEXT DEFAULT '',
        verification_status VARCHAR(20) DEFAULT 'verified',
        last_verified_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add new columns if they don't exist (for existing databases)
    try {
      await pool.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS data_source VARCHAR(50) DEFAULT 'landlord_submitted';`);
      await pool.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS source_url TEXT DEFAULT '';`);
      await pool.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS verification_status VARCHAR(20) DEFAULT 'verified';`);
      await pool.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP;`);
    } catch (error) {
      // Columns might already exist, continue
      console.log('Some columns already exist, continuing...');
    }

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_properties_city ON properties(city);
      CREATE INDEX IF NOT EXISTS idx_properties_state ON properties(state);
      CREATE INDEX IF NOT EXISTS idx_properties_zip_code ON properties(zip_code);
      CREATE INDEX IF NOT EXISTS idx_properties_landlord_id ON properties(landlord_id);
      CREATE INDEX IF NOT EXISTS idx_properties_rent_amount ON properties(rent_amount);
      CREATE INDEX IF NOT EXISTS idx_properties_bedrooms ON properties(bedrooms);
      CREATE INDEX IF NOT EXISTS idx_properties_verification_status ON properties(verification_status);
      CREATE INDEX IF NOT EXISTS idx_properties_data_source ON properties(data_source);
    `);
    
    sendSuccessResponse(res, 200, { 
      tables: ['properties'],
      indexes: [
        'idx_properties_city', 'idx_properties_state', 'idx_properties_zip_code', 
        'idx_properties_landlord_id', 'idx_properties_rent_amount', 'idx_properties_bedrooms',
        'idx_properties_verification_status', 'idx_properties_data_source'
      ],
      new_columns: ['data_source', 'source_url', 'verification_status', 'last_verified_at']
    }, 'Properties table, indexes, and tracking columns created successfully');
    
  } catch (error) {
    console.error('Database setup error:', error);
    sendErrorResponse(res, 500, 'Database setup failed', 'Failed to create properties table', error.message);
  }
});

// POST /properties - Create a new property (PROTECTED) - ENHANCED VERIFICATION CHECK
app.post('/properties', authenticateToken, requireRole(['landlord']), createPropertyLimiter, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = createPropertySchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid property data', 
        error.details.map(detail => detail.message));
    }

    const {
      address,
      city,
      state,
      zip_code,
      rent_amount,
      bedrooms,
      bathrooms,
      square_feet,
      description,
      data_source,
      source_url,
      verification_status
    } = value;

    // Use authenticated user's ID as landlord_id
    const landlord_id = req.user.id;

    // ENHANCED VERIFICATION CHECK
    console.log(`🔍 Checking verification status for landlord ${landlord_id}...`);
    
    const userVerificationQuery = `
      SELECT landlord_verified, verification_status 
      FROM users WHERE id = $1
    `;

    const userCheck = await pool.query(userVerificationQuery, [landlord_id]);
    
    if (userCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'User not found', 'Landlord account does not exist');
    }
    
    const userData = userCheck.rows[0];
    console.log(`📋 Verification check result:`, userData);

    // Block unverified landlords from creating verified properties
    if (!userData.landlord_verified) {
      const userVerificationStatus = userData.verification_status || 'pending';
      
      let message = 'Please verify your landlord account before listing properties.';
      let details = {
        redirect_url: './verify-landlord.html',
        verification_status: userVerificationStatus,
        action_required: 'complete_verification'
      };

      // Customize message based on verification status
      switch (userVerificationStatus) {
        case 'under-review':
          message = 'Your landlord verification is under review. You can list properties once approved.';
          details.estimated_time = '1-3 business days';
          details.action_required = 'wait_for_approval';
          break;
        case 'rejected':
          message = 'Your landlord verification was rejected. Please resubmit your verification documents.';
          details.action_required = 'resubmit_verification';
          break;
        case 'pending':
        default:
          message = 'Please verify your landlord account before listing properties.';
          details.action_required = 'complete_verification';
      }

      console.log(`❌ Verification failed for landlord ${landlord_id}: ${userVerificationStatus}`);
      
      return sendErrorResponse(res, 403, 'Verification required', message, details);
    }

    console.log(`✅ Landlord ${landlord_id} is verified, proceeding with property creation...`);

    // Check for duplicate property (same address + zip for this landlord)
    const duplicateCheck = await pool.query(
      'SELECT id FROM properties WHERE LOWER(address) = LOWER($1) AND zip_code = $2 AND landlord_id = $3',
      [address, zip_code, landlord_id]
    );

    if (duplicateCheck.rows.length > 0) {
      return sendErrorResponse(res, 409, 'Property already exists', 
        'You have already listed a property with this address and zip code',
        { existing_property_id: duplicateCheck.rows[0].id });
    }

    // Set verification timestamp for verified properties
    const last_verified_at = verification_status === 'verified' ? new Date() : null;

    // Insert the new property with enhanced tracking
    const insertQuery = `
      INSERT INTO properties (
        address, city, state, zip_code, rent_amount, 
        bedrooms, bathrooms, square_feet, description, landlord_id,
        data_source, source_url, verification_status, last_verified_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING *
    `;

    const result = await pool.query(insertQuery, [
      address, city, state, zip_code, rent_amount,
      bedrooms, bathrooms, square_feet, description, landlord_id,
      data_source, source_url, verification_status, last_verified_at
    ]);

    const newProperty = result.rows[0];

    console.log(`✅ Property created by verified landlord ${landlord_id}: ${address}`);

    sendSuccessResponse(res, 201, {
      property: {
        id: newProperty.id,
        address: newProperty.address,
        city: newProperty.city,
        state: newProperty.state,
        zip_code: newProperty.zip_code,
        rent_amount: newProperty.rent_amount,
        bedrooms: newProperty.bedrooms,
        bathrooms: newProperty.bathrooms,
        square_feet: newProperty.square_feet,
        description: newProperty.description,
        landlord_id: newProperty.landlord_id,
        landlord_verified: newProperty.landlord_verified,
        data_source: newProperty.data_source,
        source_url: newProperty.source_url,
        verification_status: newProperty.verification_status,
        last_verified_at: newProperty.last_verified_at,
        created_at: newProperty.created_at
      }
    }, 'Property created successfully');

  } catch (error) {
    console.error('Error creating property:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to create property');
  }
});

// PUT /properties/:id - Update a property (PROTECTED)
app.put('/properties/:id', authenticateToken, requireRole(['landlord']), async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    if (isNaN(propertyId)) {
      return sendErrorResponse(res, 400, 'Invalid property ID', 'Property ID must be a number');
    }

    // Validate request body
    const { error, value } = updatePropertySchema.validate(req.body);
    if (error) {
      return sendErrorResponse(res, 400, 'Validation failed', 'Invalid update data',
        error.details.map(detail => detail.message));
    }

    // Check if property exists and belongs to the authenticated landlord
    const propertyCheck = await pool.query(
      'SELECT id, landlord_id FROM properties WHERE id = $1',
      [propertyId]
    );

    if (propertyCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Property not found', 'No property found with the specified ID');
    }

    const property = propertyCheck.rows[0];
    if (property.landlord_id !== req.user.id) {
      return sendErrorResponse(res, 403, 'Unauthorized', 'You can only update your own properties');
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

    if (updateFields.length === 0) {
      return sendErrorResponse(res, 400, 'No updates provided', 'At least one field must be updated');
    }

    // Add updated_at and property ID
    paramCount++;
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(new Date());
    
    paramCount++;
    updateValues.push(propertyId);

    const updateQuery = `
      UPDATE properties 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedProperty = result.rows[0];

    console.log(`✅ Property ${propertyId} updated by user ${req.user.id}`);

    sendSuccessResponse(res, 200, {
      property: {
        id: updatedProperty.id,
        address: updatedProperty.address,
        city: updatedProperty.city,
        state: updatedProperty.state,
        zip_code: updatedProperty.zip_code,
        rent_amount: updatedProperty.rent_amount,
        bedrooms: updatedProperty.bedrooms,
        bathrooms: updatedProperty.bathrooms,
        square_feet: updatedProperty.square_feet,
        description: updatedProperty.description,
        landlord_verified: updatedProperty.landlord_verified,
        data_source: updatedProperty.data_source,
        source_url: updatedProperty.source_url,
        verification_status: updatedProperty.verification_status,
        last_verified_at: updatedProperty.last_verified_at,
        created_at: updatedProperty.created_at,
        updated_at: updatedProperty.updated_at
      }
    }, 'Property updated successfully');

  } catch (error) {
    console.error('Error updating property:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to update property');
  }
});

// DELETE /properties/:id - Delete a property (PROTECTED)
app.delete('/properties/:id', authenticateToken, requireRole(['landlord']), async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    if (isNaN(propertyId)) {
      return sendErrorResponse(res, 400, 'Invalid property ID', 'Property ID must be a number');
    }

    // Check if property exists and belongs to the authenticated landlord
    const propertyCheck = await pool.query(
      'SELECT id, landlord_id, address FROM properties WHERE id = $1',
      [propertyId]
    );

    if (propertyCheck.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Property not found', 'No property found with the specified ID');
    }

    const property = propertyCheck.rows[0];
    if (property.landlord_id !== req.user.id) {
      return sendErrorResponse(res, 403, 'Unauthorized', 'You can only delete your own properties');
    }

    // Delete the property
    await pool.query('DELETE FROM properties WHERE id = $1', [propertyId]);

    console.log(`✅ Property ${propertyId} deleted by user ${req.user.id}: ${property.address}`);

    sendSuccessResponse(res, 200, {}, 'Property deleted successfully');

  } catch (error) {
    console.error('Error deleting property:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to delete property');
  }
});

// GET /properties/my - Get current user's properties (PROTECTED)
app.get('/properties/my', authenticateToken, requireRole(['landlord']), async (req, res) => {
  try {
    const query = `
      SELECT 
        p.*,
        COUNT(r.id) as review_count,
        AVG(r.overall_rating) as avg_rating
      FROM properties p
      LEFT JOIN reviews r ON p.id = r.property_id
      WHERE p.landlord_id = $1
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `;

    const result = await pool.query(query, [req.user.id]);
    const properties = result.rows;

    const formattedProperties = properties.map(property => ({
      id: property.id,
      address: property.address,
      city: property.city,
      state: property.state,
      zip_code: property.zip_code,
      rent_amount: property.rent_amount,
      bedrooms: property.bedrooms,
      bathrooms: property.bathrooms,
      square_feet: property.square_feet,
      description: property.description,
      landlord_verified: property.landlord_verified,
      data_source: property.data_source,
      source_url: property.source_url,
      verification_status: property.verification_status,
      last_verified_at: property.last_verified_at,
      created_at: property.created_at,
      updated_at: property.updated_at,
      review_count: parseInt(property.review_count) || 0,
      avg_rating: property.avg_rating ? Math.round(parseFloat(property.avg_rating) * 10) / 10 : null
    }));

    sendSuccessResponse(res, 200, {
      properties: formattedProperties,
      total_count: properties.length
    });

  } catch (error) {
    console.error('Error fetching user properties:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch your properties');
  }
});

// GET /properties/:id - Get a specific property by ID (PUBLIC)
app.get('/properties/:id', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    if (isNaN(propertyId)) {
      return sendErrorResponse(res, 400, 'Invalid property ID', 'Property ID must be a number');
    }

    // Get property with landlord information and review stats
    const query = `
      SELECT 
        p.*,
        u.first_name as landlord_first_name,
        u.last_name as landlord_last_name,
        u.email as landlord_email,
        COUNT(r.id) as review_count,
        AVG(r.overall_rating) as avg_rating
      FROM properties p
      JOIN users u ON p.landlord_id = u.id
      LEFT JOIN reviews r ON p.id = r.property_id
      WHERE p.id = $1
      GROUP BY p.id, u.id
    `;

    const result = await pool.query(query, [propertyId]);

    if (result.rows.length === 0) {
      return sendErrorResponse(res, 404, 'Property not found', 'No property found with the specified ID');
    }

    const property = result.rows[0];

    sendSuccessResponse(res, 200, {
      property: {
        id: property.id,
        address: property.address,
        city: property.city,
        state: property.state,
        zip_code: property.zip_code,
        rent_amount: property.rent_amount,
        bedrooms: property.bedrooms,
        bathrooms: property.bathrooms,
        square_feet: property.square_feet,
        description: property.description,
        landlord_verified: property.landlord_verified,
        data_source: property.data_source,
        source_url: property.source_url,
        verification_status: property.verification_status,
        last_verified_at: property.last_verified_at,
        created_at: property.created_at,
        landlord: {
          id: property.landlord_id,
          first_name: property.landlord_first_name,
          last_name: property.landlord_last_name,
          email: property.landlord_email
        },
        review_stats: {
          count: parseInt(property.review_count) || 0,
          avg_rating: property.avg_rating ? Math.round(parseFloat(property.avg_rating) * 10) / 10 : null
        }
      }
    });

  } catch (error) {
    console.error('Error fetching property:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch property');
  }
});

// GET /properties - Search properties with filtering (PUBLIC)
app.get('/properties', async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = searchPropertiesSchema.validate(req.query);
    if (error) {
      return sendErrorResponse(res, 400, 'Invalid search parameters', 'Invalid search parameters',
        error.details.map(detail => detail.message));
    }

    const {
      city, state, zip_code, min_rent, max_rent, min_bedrooms, max_bedrooms,
      min_bathrooms, max_bathrooms, min_sqft, max_sqft, landlord_verified,
      verification_status, sort_by = 'newest', limit = 20, offset = 0
    } = value;

    // Build dynamic WHERE clause
    let whereConditions = [];
    let queryParams = [];
    let paramCount = 0;

    // Add filters based on provided parameters
    if (city) {
      paramCount++;
      whereConditions.push(`LOWER(p.city) LIKE LOWER(${paramCount})`);
      queryParams.push(`%${city}%`);
    }

    if (state) {
      paramCount++;
      whereConditions.push(`LOWER(p.state) = LOWER(${paramCount})`);
      queryParams.push(state);
    }

    if (zip_code) {
      paramCount++;
      whereConditions.push(`p.zip_code = ${paramCount}`);
      queryParams.push(zip_code);
    }

    if (min_rent !== undefined) {
      paramCount++;
      whereConditions.push(`p.rent_amount >= ${paramCount}`);
      queryParams.push(min_rent);
    }

    if (max_rent !== undefined) {
      paramCount++;
      whereConditions.push(`p.rent_amount <= ${paramCount}`);
      queryParams.push(max_rent);
    }

    if (min_bedrooms !== undefined) {
      paramCount++;
      whereConditions.push(`p.bedrooms >= ${paramCount}`);
      queryParams.push(min_bedrooms);
    }

    if (max_bedrooms !== undefined) {
      paramCount++;
      whereConditions.push(`p.bedrooms <= ${paramCount}`);
      queryParams.push(max_bedrooms);
    }

    if (min_bathrooms !== undefined) {
      paramCount++;
      whereConditions.push(`p.bathrooms >= ${paramCount}`);
      queryParams.push(min_bathrooms);
    }

    if (max_bathrooms !== undefined) {
      paramCount++;
      whereConditions.push(`p.bathrooms <= ${paramCount}`);
      queryParams.push(max_bathrooms);
    }

    if (min_sqft !== undefined) {
      paramCount++;
      whereConditions.push(`p.square_feet >= ${paramCount}`);
      queryParams.push(min_sqft);
    }

    if (max_sqft !== undefined) {
      paramCount++;
      whereConditions.push(`p.square_feet <= ${paramCount}`);
      queryParams.push(max_sqft);
    }

    if (landlord_verified !== undefined) {
      paramCount++;
      whereConditions.push(`p.landlord_verified = ${paramCount}`);
      queryParams.push(landlord_verified);
    }

    if (verification_status) {
      paramCount++;
      whereConditions.push(`p.verification_status = ${paramCount}`);
      queryParams.push(verification_status);
    }

    // Build WHERE clause
    const whereClause = whereConditions.length > 0 
      ? `WHERE ${whereConditions.join(' AND ')}`
      : '';

    // Build ORDER BY clause
    let orderClause;
    switch (sort_by) {
      case 'rent_asc':
        orderClause = 'ORDER BY p.rent_amount ASC NULLS LAST';
        break;
      case 'rent_desc':
        orderClause = 'ORDER BY p.rent_amount DESC NULLS LAST';
        break;
      case 'oldest':
        orderClause = 'ORDER BY p.created_at ASC';
        break;
      case 'sqft_asc':
        orderClause = 'ORDER BY p.square_feet ASC NULLS LAST';
        break;
      case 'sqft_desc':
        orderClause = 'ORDER BY p.square_feet DESC NULLS LAST';
        break;
      case 'newest':
      default:
        orderClause = 'ORDER BY p.created_at DESC';
        break;
    }

    // Add pagination parameters
    paramCount++;
    const limitParam = `${paramCount}`;
    queryParams.push(limit);
    
    paramCount++;
    const offsetParam = `${paramCount}`;
    queryParams.push(offset);

    // Main search query with review stats and enhanced property tracking
    const searchQuery = `
      SELECT 
        p.id,
        p.address,
        p.city,
        p.state,
        p.zip_code,
        p.rent_amount,
        p.bedrooms,
        p.bathrooms,
        p.square_feet,
        p.description,
        p.landlord_verified,
        p.data_source,
        p.source_url,
        p.verification_status,
        p.last_verified_at,
        p.created_at,
        u.first_name as landlord_first_name,
        u.last_name as landlord_last_name,
        COUNT(r.id) as review_count,
        AVG(r.overall_rating) as avg_rating
      FROM properties p
      JOIN users u ON p.landlord_id = u.id
      LEFT JOIN reviews r ON p.id = r.property_id
      ${whereClause}
      GROUP BY p.id, u.id
      ${orderClause}
      LIMIT ${limitParam} OFFSET ${offsetParam}
    `;

    // Count query for pagination metadata
    const countQuery = `
      SELECT COUNT(*) as total
      FROM properties p
      JOIN users u ON p.landlord_id = u.id
      ${whereClause}
    `;

    // Execute both queries
    const [searchResult, countResult] = await Promise.all([
      pool.query(searchQuery, queryParams),
      pool.query(countQuery, queryParams.slice(0, -2)) // Remove limit and offset for count
    ]);

    const properties = searchResult.rows;
    const totalCount = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(totalCount / limit);
    const currentPage = Math.floor(offset / limit) + 1;

    // Format response with enhanced property tracking
    const formattedProperties = properties.map(property => ({
      id: property.id,
      address: property.address,
      city: property.city,
      state: property.state,
      zip_code: property.zip_code,
      rent_amount: property.rent_amount,
      bedrooms: property.bedrooms,
      bathrooms: property.bathrooms,
      square_feet: property.square_feet,
      description: property.description,
      landlord_verified: property.landlord_verified,
      data_source: property.data_source,
      source_url: property.source_url,
      verification_status: property.verification_status,
      last_verified_at: property.last_verified_at,
      created_at: property.created_at,
      landlord: {
        first_name: property.landlord_first_name,
        last_name: property.landlord_last_name
      },
      review_stats: {
        count: parseInt(property.review_count) || 0,
        avg_rating: property.avg_rating ? Math.round(parseFloat(property.avg_rating) * 10) / 10 : null
      }
    }));

    sendSuccessResponse(res, 200, {
      properties: formattedProperties,
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
        city, state, zip_code,
        rent_range: min_rent || max_rent ? { min: min_rent, max: max_rent } : null,
        bedrooms_range: min_bedrooms !== undefined || max_bedrooms !== undefined ? { min: min_bedrooms, max: max_bedrooms } : null,
        bathrooms_range: min_bathrooms || max_bathrooms ? { min: min_bathrooms, max: max_bathrooms } : null,
        sqft_range: min_sqft || max_sqft ? { min: min_sqft, max: max_sqft } : null,
        landlord_verified, verification_status, sort_by
      }
    });

  } catch (error) {
    console.error('Error searching properties:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to search properties');
  }
});

// GET /properties/stats - Get property statistics (PUBLIC)
app.get('/properties/stats', async (req, res) => {
  try {
    const statsQuery = `
      SELECT 
        COUNT(*) as total_properties,
        COUNT(CASE WHEN landlord_verified = true THEN 1 END) as verified_properties,
        COUNT(CASE WHEN verification_status = 'verified' THEN 1 END) as properties_verified,
        COUNT(CASE WHEN verification_status = 'community_submitted' THEN 1 END) as community_properties,
        COUNT(CASE WHEN verification_status = 'pending_verification' THEN 1 END) as pending_properties,
        AVG(rent_amount) as avg_rent,
        MIN(rent_amount) as min_rent,
        MAX(rent_amount) as max_rent,
        AVG(bedrooms) as avg_bedrooms,
        AVG(bathrooms) as avg_bathrooms,
        AVG(square_feet) as avg_sqft,
        COUNT(DISTINCT city) as cities_count,
        COUNT(DISTINCT state) as states_count,
        COUNT(DISTINCT landlord_id) as unique_landlords
      FROM properties
      WHERE rent_amount IS NOT NULL
    `;

    const result = await pool.query(statsQuery);
    const stats = result.rows[0];

    sendSuccessResponse(res, 200, {
      statistics: {
        total_properties: parseInt(stats.total_properties),
        verified_properties: parseInt(stats.verified_properties),
        verification_rate: stats.total_properties > 0 
          ? Math.round((stats.verified_properties / stats.total_properties) * 100) 
          : 0,
        property_verification: {
          verified: parseInt(stats.properties_verified),
          community_submitted: parseInt(stats.community_properties),
          pending_verification: parseInt(stats.pending_properties)
        },
        rent_statistics: {
          average: stats.avg_rent ? Math.round(parseFloat(stats.avg_rent)) : null,
          minimum: stats.min_rent ? parseFloat(stats.min_rent) : null,
          maximum: stats.max_rent ? parseFloat(stats.max_rent) : null
        },
        property_features: {
          avg_bedrooms: stats.avg_bedrooms ? Math.round(parseFloat(stats.avg_bedrooms) * 10) / 10 : null,
          avg_bathrooms: stats.avg_bathrooms ? Math.round(parseFloat(stats.avg_bathrooms) * 10) / 10 : null,
          avg_square_feet: stats.avg_sqft ? Math.round(parseFloat(stats.avg_sqft)) : null
        },
        geographic_coverage: {
          cities: parseInt(stats.cities_count),
          states: parseInt(stats.states_count),
          unique_landlords: parseInt(stats.unique_landlords)
        }
      }
    });

  } catch (error) {
    console.error('Error fetching property statistics:', error);
    sendErrorResponse(res, 500, 'Internal server error', 'Failed to fetch property statistics');
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
  console.log(`🏠 Property service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  console.log(`JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Missing'}`);
  console.log(`Authentication: Enabled`);
  console.log(`Rate Limiting: Enabled`);
});