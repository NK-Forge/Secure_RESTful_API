// Rate limiting middleware

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate=limit-redis');
const redis = require('redis');

module.exports = (app) => {
    // Create redis client if in production
    let redisClient;
    if (process.env.NODE_ENV === 'production') {
        redisClient = redis.createClient({
            url: process.env.REDIS_URL,
            socket: {
                connectTimeout: 10000
            }
        });

        redisClient.on('error', (err) => {
            console.error('Redis error:', err);
            // Fall back to memory store if Redis is unavailable
        });
    }

    // Define ate limiters
    const apiLimiter = rateLimit({
        windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes by default
        max: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
        standardHeaders: true,
        legacyHeaders: false,
        message: 'Too many requests from this IP, please try again later',
        store: process.env.NODE_ENV === 'production' && redisClient ? new RedisStore({
            sendCommand: (...args) => redisClient.sendCommand(args),
        }) : undefined
    });

    // Apply rate limiting to all API routes
    app.use('/api/', apiLimiter);

    // Apply stricter rate limiting to auth routes
    app.use('/api/auth/login', authLimiter);
    app.use('/api/auth/register', authLimiter);

    return { apiLimiter, authLimiter};
};