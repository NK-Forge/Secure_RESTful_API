const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { createError } = require('../utils/errorHandler');

// Middleware to  authenticate JWT tokens
exports.protect = async (req, res, next) => {
    try {
        let token;

        // Get token from header
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        // Check if token exists
        if (!token) {
            return next(createError(401, 'Not authorized to access this route'));
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        // Add user to request
        req.user = await User.findById(decoded.id).select('-password');

        if (!req.user) {
            return next(createError(404, 'User not found'));
        }

        next();
    }   catch (error) {
        // Handle expired token
        if (error.name === 'TokenExpiredError') {
            return next(createError(401, 'Token expired'));
        }
        // Handle invalid token
        if (error.name === 'JsonWebTokenError') {
            return next(createError(401, 'Invalid token'));
        }

        return next(createError(401, 'Not authorized to access this route'));
    }
};

// Middleware for rol-based access control
exports.authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return next(createError(401, 'Not authorized to access this route'));
        }

        if (!roles.some(role => req.user.roles.includes(role))) {
            return next(createError(403, 'User role ${req.user.roles.join(','} not authorized to access this route'));
        }

        next();
    };
};