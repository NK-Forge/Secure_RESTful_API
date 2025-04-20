// Request logging middleware

const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const rfs = require('rotating-file-stream');

// Create log directory
const logDirectory = path.join(__dirname, '../logs');
fs.existsSync(logDirectory) || fs.mkdirSync(logDirectory);

// Create a rotationg write stream
const accessLogStream = rfs.createStream('access.log', {
    interval: '1d', // rotate daily
    path: logDirectory
});

module.exports = (app) => {
    //Development logging
    if (process.env.NODE_ENV === 'development') {
        app.use(morgan('dev'));
    }

    // Production logging to file
    app.use(morgan('combined', { stream: accessLogStream }));
};