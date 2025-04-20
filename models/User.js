// User model for authentication

const mongoose = require('mongoose');
const bcrypt = require('bcyptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Please provide a username'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long']
    },
    email: {
        type: String,
        required: [true, 'Please provide an email'],
        unique: true,
        match: [
            /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
            'Please provide a valid email'
        ]
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: [8, 'Password must be at least 8 characters long'],
        select: false // Don't return password in queries by default
    },
    roles: {
        type: [String],
        default: ['user'],
        enum: ['user', 'admin', 'moderator']
    },
    refreshToken: {
        type: String,
        select: false // Don't return refreshToken in queries by default
    },
    lastLogin: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }

    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to generate JWI access token
UserSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            id: this._id,
            username: this.username,
            roles: this.roles
        },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' }
    );
};

// Method to generate refresh token
UserSchema.methods.generateRefreshToken = function() {
    const refreshToken = jwt.sign(
        { id: this._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' }
    );

    this.refreshToken = refreshToken;
    return refreshToken;
};

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);