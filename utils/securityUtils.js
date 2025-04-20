// Security utilities

const crypto = require('crypto');

// Generate a secure random string
exports.generateSecureToken = (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
};

// Hash sensitive data
exports.hashData = (data) => {
    return crypto.createHash('sha256').update(data).digest('hex');
};

// Encrypt data
exports.encryptData = (data, encryptionKey) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
        'aes-256-cbc',
        Buffer.from(encryptionKey, 'hex'),
        iv
    );

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return{
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
};

// Decrypt data
exports.decryptData = (encryptedData, iv, encryptionKey) => {
    const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        Buffer.from(encryptionKey, 'hex'),
        Buffer.from(iv, 'hex')
    );

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
};

// Generate CSRF token
exports.generateCSRFToken = () => {
    return crypto.randomBytes(100).toString('base64');
};