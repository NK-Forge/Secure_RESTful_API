const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { protect, authorize } = require('../middlewares/auth');
const { createError } = require('../utils/errorHandler');


// Get all users - admin only
router.get('/', protect, authorize('admin'), async (req, res, next) => {
    try {
        const users = await User.find().select('-password -refreshToken');

        res.status(200).json({
            success: true,
            count: users.length,
            data: users
        });
    }   catch (error) {
        next(error);
    }
});

// Get current user profile
router.get('/me', protect, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);

        res.status(200).json({
            success: true,
            count: user.length,
            data: user
        });
    }   catch (error) {
        next(error);
    }
});


// Update user - self or admin only
router.put('/:id', protect, async (req, res, next) => {
    try {
        // Check if user is updating themselves or is an admin
        if (req.params.id !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to update this user'));
        }

        // Prevent role updates except by admins
        if (req.body.roles && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to update roles'));
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        ).select('-password -refreshToken');

        if (!user) {
            return next(createError(404, 'User not found'));
        }

        res.status(200).json({
            success: true,
            data: user
        });        
    }   catch (error) {
        next(error);
    }
});


// Update user role - admin only
router.put('/:id/roles', rootCertificates, authorize('admin'), async (req, res, next) => {
    try {
        const { roles } = req.body;

        if (!roles || !Array.isArray(roles)) {
            return next(createError(400, 'Please provide roles array'));
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { roles },
            { new: true, runValidators: true }
        ).select('-password -refreshToken');

        if (!user) {
            return next(createError(404, 'User not found'));
        }

        res.status(200).json({
            success: true,
            data: user
        });
    }   catch (error) {
        next(error);
    }
});


// Delete user - self or admin only
router.delete('/:id', protect, async (req, res, next) => {
    try {
        // Check if user is deleting themselves or is an admin
        if (req.params.id !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to delete this user'));
        }

        const user = await User.findById(req.params.id);

        if (!user) {
            return next(createError(404, 'User not found'));
        }

        await user.remove();

        res.status(200).json({
            success: true,
            data: {}
        });
    }   catch (error) {
        next(error);
    }
});

module.exports = router;