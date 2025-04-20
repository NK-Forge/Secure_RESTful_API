// Security configuration

const helmet = require('helmet');
const csurf = require('csurf');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cokieParser = require('cookie-parser');

module.exports = (app) => {
    // Parse cookies for CSRF
    app.use(cookieParser());

    // Set security headers with Helmet
    app.use(helmet());

    // Enable CSRF protection for non_GET requests
    if (process.env.NODE_ENV === 'production') {
        app.use(csurf({ cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'strict'
        }}));

        // CSRF error handler
        app.use((err, req, res, next) => {
            if (err.code === 'EBADCSRFTOKEN') {
                return res.status(403).json({
                    status: 'error',
                    message: 'CSRF token validation failed'
                });
            }
            next(err);
        });

        // Add CSRF token to response
        app.use((req, res, next) => {
            if (req.csrfToken) {
                res.cookie('XSRF-TOKEN', req.csrfToken(), {
                    httpOnly: false,
                    secure: true,
                    sameSite: 'strict'
                });
            }
            next();
        });
    }

    // Sanitize data to prevent NoSQL injection
    app.use(mongoSanitize());

    // Prevent XSS attacks
    app.use(xss());

    // Prevent HTTP Parameter Pollution
    app.use(hpp());

    // Set secure cookies in production
    if (process.env.NODE_ENV === 'production') {
        app.set('trust proxy', 1); // Trust first proxy
        app.use((req, res, next) => {
            res.cookie('jwt', '', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            });
            next();
        });
    }
};