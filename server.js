const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

// Validate environment variables
const requiredEnvVars = [
  'JWT_SECRET', 
  'AUTH_SERVICE_URL', 
  'TRANSACTION_SERVICE_URL', 
  'FRAUD_SERVICE_URL', 
  'NOTIFICATION_SERVICE_URL', 
  'ANALYTICS_SERVICE_URL'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

// Create Express app
const app = express();

// Apply middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  next();
});

// Define services
const services = {
  auth: {
    url: process.env.AUTH_SERVICE_URL
  },
  transactions: {
    url: process.env.TRANSACTION_SERVICE_URL
  },
  fraud: {
    url: process.env.FRAUD_SERVICE_URL
  },
  notifications: {
    url: process.env.NOTIFICATION_SERVICE_URL
  },
  analytics: {
    url: process.env.ANALYTICS_SERVICE_URL
  }
};

// ===== AUTHENTICATION MIDDLEWARE =====

// Authentication middleware
function authenticate(req, res, next) {
  console.log(`Authenticating request to: ${req.originalUrl}`);
  
  // Get token from header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication required. Please provide a valid token.'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(`User authenticated: ${decoded.email} (${decoded.role})`);
    
    // Store user info in request
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(401).json({
      status: 'error',
      message: 'Invalid or expired token'
    });
  }
}

// Admin role check middleware
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication required'
    });
  }
  
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      status: 'error',
      message: 'Admin privileges required for this operation'
    });
  }
  
  next();
}

// ===== PUBLIC ROUTES (NO AUTH NEEDED) =====

// Root endpoint
app.get('/proxy', (req, res) => {
  res.json({
    service: 'Credit Card Fraud Detection API Gateway',
    version: '1.0.0',
    endpoints: {
      public: ['/proxy', '/proxy/health', '/proxy/auth/login'],
      protected: ['/proxy/transactions/*', '/proxy/analytics/*', '/proxy/notifications/*'],
      adminOnly: ['/proxy/auth/register', '/proxy/fraud/metrics', '/proxy/fraud/model_info']
    }
  });
});

// Health check
app.get('/proxy/health', (req, res) => {
  res.json({ status: 'ok', service: 'api-gateway' });
});

// Login endpoint
app.post('/proxy/auth/login', async (req, res) => {
  try {
    console.log(`Forwarding login request to ${services.auth.url}/login`);
    const response = await axios.post(`${services.auth.url}/login`, req.body);
    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Login request failed:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(502).json({
        status: 'error',
        message: 'Authentication service unavailable'
      });
    }
  }
});

// ===== PROTECTED ROUTES (AUTH REQUIRED) =====

// Register endpoint - admin only
app.post('/proxy/auth/register', authenticate, requireAdmin, async (req, res) => {
  try {
    console.log(`Admin user ${req.user.email} registering new user`);
    console.log(`Forwarding register request to ${services.auth.url}/register`);
    
    const response = await axios.post(`${services.auth.url}/register`, req.body, {
      headers: {
        'Authorization': req.headers.authorization,
        'Content-Type': 'application/json'
      }
    });
    
    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Register request failed:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(502).json({
        status: 'error',
        message: 'Authentication service unavailable'
      });
    }
  }
});

// Generic service forward function
function forwardToService(service) {
  return async (req, res) => {
    try {
      // Extract path after service name
      const parts = req.originalUrl.split('/');
      const serviceName = parts[2];  // 'proxy/auth/...' => 'auth'
      const path = '/' + parts.slice(3).join('/');
      
      const url = `${services[service].url}${path}`;
      console.log(`Forwarding ${req.method} request to ${url}`);
      
      let response;
      const config = {
        headers: {
          'Authorization': req.headers.authorization,
          'Content-Type': 'application/json'
        }
      };
      
      if (req.method === 'GET') {
        response = await axios.get(url, config);
      } else if (req.method === 'POST') {
        response = await axios.post(url, req.body, config);
      } else if (req.method === 'PUT') {
        response = await axios.put(url, req.body, config);
      } else if (req.method === 'DELETE') {
        response = await axios.delete(url, config);
      }
      
      res.status(response.status).json(response.data);
    } catch (error) {
      console.error(`Service request failed:`, error.message);
      if (error.response) {
        res.status(error.response.status).json(error.response.data);
      } else {
        res.status(502).json({
          status: 'error',
          message: `Service unavailable: ${service}`
        });
      }
    }
  };
}

// Service routes - ALL require authentication
app.use('/proxy/auth', (req, res, next) => {
  // Skip /login and /register which are handled separately
  if ((req.path === '/login' && req.method === 'POST') || 
      (req.path === '/register' && req.method === 'POST')) {
    return next('route');
  }
  
  // All other auth routes require authentication
  authenticate(req, res, () => forwardToService('auth')(req, res));
});

app.use('/proxy/transactions', authenticate, forwardToService('transactions'));
app.use('/proxy/notifications', authenticate, forwardToService('notifications'));
app.use('/proxy/analytics', authenticate, forwardToService('analytics'));

// Fraud routes with special handling for admin-only metrics endpoint
app.use('/proxy/fraud', authenticate, (req, res, next) => {
  if (req.path === '/metrics' && req.method === 'GET') {
    // Admin-only route
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'error',
        message: 'Admin privileges required for this operation'
      });
    }
  }
  
  forwardToService('fraud')(req, res);
});

// Error handler for routes not found
app.use((req, res) => {
  console.log(`Route not found: ${req.originalUrl}`);
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});