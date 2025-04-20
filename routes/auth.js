const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect } = require('../middlewares/auth');
const { createError } = require('../utils/errorHandler');

// Register a new user
router.post('/register', async (req, res, next) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return next(createError(400, 'User already exists'));
        }

        // Create new user
        const user = await User.create({
            username,
            email,
            password
        });

        // Generate tokens
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        // Save refresh token
        await user.save();

        res.status(201).json({
            success: true,
            accessToken,
            refreshToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                roles: user.roles
            }
        });
    }   catch (error) {
        next(error);
    }
});

        // Login user
        router.post('/login', async (req, res, next) => {
            try {
                const { email, password } = req.body;

            // Check if email and password are provided
            if (!email || !password) {
                return next(createError(400, 'Please provide email and password'));
            }

            // Find user
            const user = await User.findOne({ email }).select('+password');
            if (!user) {
                return next(createError(401, 'Invalid credentials'));
            }

            // Update last login
            user.lastLogin = Date.now();

            // Generate tokens
            const accessToken = user.generateAccessToken();
            const refreshToken = user.generateRefreshToken();

            // Save refresh token
            await user.save();

            res.status(200).json({
                success: true,
                accessToken,
                refreshToken,
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    roles: user.roles
                }
            });
        } catch (error) {
            next(error);
        }
        });

        // Refresh token
        router.post('/refresh-token', async (req, res, next) => {
            try {
                const { refreshToken } = req.body;

                if (!refreshToken) {
                    return next(createError(400, 'Refresh token is reqired'));
                }

                // Verify refresh token
                const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

                // Find user with matching refresh token
                const user = await User.findById(decoded.id).select('+refreshToken');

                if (!user || user.refreshToken !== refreshToken) {
                    return next(createError(401, 'Invalid refresh token'));
                }

                // Generate new tokens
                const newAccessToken = user.generateAccessToken();
                const newRefreshToken = user.generateRefreshToken();

                // Save new refresh token
                await user.save();

                res.status(200).json({
                    success: true,
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken
                });
            }   catch (error) {
                if (error.name === 'TokenExpiredError') {
                    return next(createError(401, 'Refresh token expired'));
                }
                next(error);
            }
        });

        // Logout user
        router.post('/logout', protect, async (req, res, next) => {
            try {
                // Find user and clear refresh token
                await User.findByIdAndUpdate(req.user.id, { refreshToken: null });

                res.status(200).json({
                    success: true,
                    message: 'Logged out successfully'
                });
            }   catch (error) {
                next(error);
            }
        });
