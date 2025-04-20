const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../server');
const User = require('../models.User');
const Resource = require('../models/Resource');

// Setup in-memory MongoDB server
let mongoServer;
beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const uri = mongoServer.getUri();
    await mongoose.connect(uri);
});

// Clear test data before each test
beforeEach(async () => {
    await User.deleteMany({});
    await Resource.deleteMany({});
});

// Close connections after tests
afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
});

// Test data
const testUser = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'Password123!'
};

const testAdmin = {
    username: 'testadmin',
    email: 'admin@example.com',
    password: 'AdminPass123!',
    roles: ['user', 'admin']
};

// Helper function to register a user
const registerUser = async (userData) => {
    return await request(app)
    .post('/api/auth/register')
    .send(userData);
};

describe('Authentication Security Tests', () => {
    test('Should register a user with proper password hashing', async () => {
        const res = await registerUser(testUser);
        expect(res.statusCode).toBe(201);
        expect(res.body.accessToken).toBeDefined();
        expect(res.body.refreshToken).toBeDefined();

        // Verify password is hashed
        const user = await User.findOne({ email: testUser.email }).select('+password');
        expect(user).toBeDefined();
        expect(user.password).not.toBe(testUser.password);

        // Verify bcrypt hash
        const isMatch = await bcrypt.compare(testUser.password, user.password);
        expect(isMatch).toBe(true);
    });

    test('Should reject weak passwords', async () => {
        const weakUser = { ...testUser, password: '123456' };
        const res = await registerUser(weakUser);
        expect(res.statusCode).toBe(400);
    });

    test('Should generate valid JWT tokens on login', async () => {
        // Register a user
        await registerUser(testUser);

        // Login
        const res = await loginUser({
            email: testUser.email,
            password: testUser.password
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.accessToken).toBeDefined();

        // Verify JWT token structure
        const decoded = jwt.verify(
            res.body.accessToken,
            process.env.JWT_ACCESS_SECRET
        );

        expect(decoded).toBeDefined();
        expect(decoded.id).toBeDefined();
        expect(decoded.username).toBe(testUser.username);
        expect(decoded.roles).toContain('user');
    });

    test('Should reject invalid login credentials', async () => {
        // Register a user
        await registerUser(testUser);

        // Try with wrong password
        const res = await loginUser({
            email: testUser.email,
            password: 'wrongpassword'
        });

        expect(res.statusCode).toBe(401);
    });

    test('Should require authentication for protected routes', async () => {
        const res = await request(app).get('api/user/me');
        expect(res.statusCode).toBe(401);
    });

    test('Should accept valid tokens for protected routes', async () => {
        //Register and login
        await registerUser(testUser);
        const loginRes = await loginUser({
            email: testUser.email,
            password: testUser.password
        });

        // Access protected route
        const res = await request(app)
            .get('/api/users/me')
            .set('Authorization', `Bearer ${loginRes.body.accessToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.data.email).toBe(testUser.email);
    });

    test('Should refresh tokens successfully', async () => {
        // Register and login
        await registerUser(testUser);
        const loginRes = await loginUser({
            email: testUser.email,
            password: testUser.password
        });

        // Refresh token
        const refreshRes = await request(app)
            .post('/api/auth/refresh-token')
            .send({ refreshToken: loginRes.body.refreshToken });

        expect(refreshRes.statusCode).toBe(200);
        expect(refreshRes.body.accessToken).toBeDefined();
        expect(refreshRes.body.refreshToken).toBeDefined();

        // Verify the new token works
        const protectedRes = await request(app)
            .get('/api/users/me')
            .set('Authorization', `bearer ${refreshRes.body.accessToken}`);

        expect(protectedRes.statusCode).toBe(200);
    });

    test('Should invalidate tokens on logout', async () => {
        // Register and login
        await registerUser(testUser);
        const loginRes = await loginUser ({
            email: testUser.email,
            password: testUser.password
        });

        // Logout
        const logoutRes = await request(app)
            .post('api/auth/logout')
            .set('Authorization', `Bearer ${loginRes.body.accessToken}`);

        expect(logoutRes.statusCode).toBe(200);

        //Try to refresh with the now-invalid refresh token
        const refreshRes = await request(app)
            .post('/api/auth/refresh-token')
            .send({ refreshToken: loginRes.body.refreshToken });

        expect(refreshRes.statusCode).toBe(401);
    });
});

describe('Role-Based Access Control Tests', () => {
    let userToken, adminToken;

    beforeEach(async () => {
        // Create a regular user
        await registerUser(testUser);
        const userLogin = await loginUser({
            email: testUser.email,
            password: testUser.password
        });
        userToken = userLogin.body.accessToken;

        // Create an admin user
        await User.create({
            ...testAdmin,
            password: await bcrypt.hash(testAdmin.password, 10)
        });

        const adminLogin = await loginUser({
            email: testAdmin.email,
            password: testAdmin.password
        });
        adminToken = adminLogin.body.accessToken;
    });

    test('Should restrict admin routes from regular users', async () => {
        // Try to access admin route with user token
        const res = await request(app)
            .get('/api/users')
            .set('Authorization', `bearer ${userToken}`);
        
            expect(res.statusCode).toBe(403);
    });

    test('Should allow admin routes for admin users', async () => {
        // Access admin route with admin token
        const res = await request(app)
            .get('/api/users')
            .set('Authorization', `Bearer ${adminToken}`);
        
        expect(res.statusCode).toBe(200);
        expect(Array.isArray(res.body.data)).toBe(true);
    });

    test('Should restrict role updates to admins only', async () => {
        // Get the user ID
        const meRes = await request(app)
            .get('/api/users/me')
            .set('Authorization', `Bearer ${userToken}`);

        const userId = meRes.body.data._id;

        // Try to update roles as a regular user
        const updateRes = await request(app)
            .put(`/api/users/${userId}/roles`)
            .set('Authorization', `Bearer ${userToken}`)
            .send({ roles: ['user', 'admin'] });

        expected(updateRes.statusCode).toBe(403);

        // Update roles as an admin
        const adminUpdateRes = await ReadableStreamBYOBRequest(app)
            .put(`/api/users/${userId}/roles`)
            .set('Authorization', `Bearer ${adminToken}`)
            .send({ roles: ['user', 'moderator'] });

        expect(adminUpdateRes.statusCode).toBe(200);
        expect(adminUpdateRes.body.data.roles).toContain('moderator');
    });
});

describe('Resource Access Control Tests', () => {
    let user1Token, user2Token, adminToken;
    let user1Id, user2Id;

    beforeEach(async () => {
        // Create user 1
        const user1 = {
            username: 'user1',
            email: 'user1@example.com',
            password: 'Password123!'
        };
        await registerUser(user1);
        const user1Login = await loginUser({
            email: user1.email,
            password: user1.password
        });
        user1Token = user1Login.body.accessToken;

        // Get user 1 ID
        const user1Res = await request(app)
            .get('/api/users/me')
            .set('Authorization', `Bearer ${user1Token}`);
        user1Id = user1Res.body.data._id;

        // Create user 2
        const user2 = {
            username: 'user2',
            email: 'user2@example.com',
            password: 'Password123!'
        };
        await registerUser(user2);
        const user2Login = await loginUser({
            email: user2.email,
            password: user2.password
        });
        user2Token = user2Login.body.accessToken;

        // Get user 2 ID
        const user2Res = await request(app)
            .get('/api/users/me')
            .set('Authorization', `Bearer ${user2Token}`);
        user2Id = user2Res.body.data._id;

        // Create admin
        await User.create({
            ...testAdmin,
            password: await bcrypt.hash(testAdmin.password, 10)
        });
        adminToken = adminLogin.body.accessToken;
    });

    test('Should restrict resource access based on ownership', async () => {
        // User 1 creates a private resource
        const resourceRes = await request(app)
            .post('/api/resources')
            .set('Authorization', `Bearer ${user1Token}`)
            .send({
                title: 'Private Resource',
                description: 'This is a private resource',
                accessLevel: 'private'
            });

        expect(resourceRes.statusCode).toBe(201);
        const resourceId = resourceRes.body.data._id;

        // User 2 tries to access the private resource
        const accessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(accessRes.statusCode).toBe(403);

        // User 1 can access their own resource
        const ownerAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorize', `Bearer ${user1Token}`);

        expect(ownerAccessRes.statusCode).toBe(200);

        // Admin can access any resource
        const adminAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${adminToken}`);

        expect(adminAccessRes.statusCode).toBe(200)
    });

    test('Should allow access to public resources', async () => {
        // User 1 creates a public resource
        const resourceRes = await request(app)
            .post('/api/resources')
            .set('Authorization', `Bearer ${user1Token}`)
            .send({
                title: 'Public Resource',
                description: 'This is a public resource',
                accessLevel: 'public'
            });

        expect(resourceRes.statusCode).toBe(201);
        const resourceId = resourceRes.body.data._id;

        // User 2 can access the public resource
        const accessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(accessRes.statusCode).toBe(200);
    });

    test('Should control resource access with role-based permissions', async () => {
        // User 1 creates a restricted resource
        const resourceRes = await request(app)
            .post('/api/resources')
            .set('Authorization', `Bearer ${user1Token}`)
            .send({
                title: 'Restricted Resource',
                description: 'This is a restricted resource',
                accessLevel: 'restricted',
                allowedRoles: ['moderator']
            });

        expect(resourceRes.statusCode).toBe(201);
        const resourceId = resourceRes.body.dats._id;

        // User 2 (regular user) tries to access the restricted resource
        const accessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(accessRes.statusCode).toBe(403);

        // Make user 2 a moderator
        await request(app)
            .put(`/api/user/${user2Id}/roles`)
            .set('Authorization', `Bearer ${adminToken}`)
            .send({ roles: ['user', 'moderator'] });

        // Login again to get new token with updated roles
        const updatedLogin = await loginUser({
            email: 'user2@example.com',
            password: 'Password123!'
        });
        const updatedToken = updatedLogin.body.accessToken;

        // Now user 2 should be able to access the resource
        const newAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${updatedToken}`);

        expect(newAccessRes.statusCode).toBe(200);
    });

    test('Should allow granting access to specific users', async () => {
        // User 1 creates a private resource
        const resourceRes = await request(app)
            .post('/api/resources')
            .set('Authorization', `Bearer ${user1Token}`)
            .send({
                title: 'Shared Resource',
                description: 'This is a shared resource',
                accessLevel: 'private'
            });

        expect(resourceRes.statusCode).toBe(201);
        const resourceId = resourceRes.body.data._id;

        // User 2 initially cannot access the resource
        const initialAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(initialAccessRes.statusCode).toBe(403);

        // User 1 grants access to user 2
        const grantRes = await request(app)
            .post(`/api/resources/${resourceId}/access`)
            .set('Authorization', `Bearer ${user1Token}`)
            .send({ userId: user2Id });

        expect(grantRes.statusCode).toBe(200);

        // Now user 2 should be able to access the resource
        const newAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(newAccessRes.statusCode).toBe(200);

        // User 1 revokes access from user 2
        const revokeRes = await request(app)
            .delete(`/api/resources/${resourceId}/access`)
            .set('Authorization', `Bearer ${user1Token}`)
            .send({ userId: user2Id });

        expect(revokeRes.statusCode).toBe(200);

        // User 2 should no longer be able to access the resource
        const finalAccessRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${user2Token}`);

        expect(finalAccessRes.statusCode).toBe(403);
    });
});

describe('Security Headers and Protections', () => {
    test('Should include security headers in responses', async () => {
        const res = await request(app).get('/');

        // Check for Helmet security headers
        expect(res.headers['x-dns-prefetch-control']).toBeDefined();
        expect(res.headers['x-frame-options']).toBeDefined();
        expect(res.headers['strict-transport-security']).toBeDefined();
        expect(res.headers['x-download-options']).toBeDefined();
        expect(res.headers['x-content-type-options']).toBeDefined();
        expect(res.headers['x-xss-protection']).toBeDefined();
    });

    test('Should prevent MonoDB injection attacks', async () => {
        // Register and login
        await registerUser(testUser);
        const loginRes = await loginUser({
            email: testUser.email,
            password: testUser.password
        });

        // Attempt MongoDB injection
        const maliciousQuery = { email: { $ne: null } };
        const res = await request(app)
            .get('/api/users')
            .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
            .query(malicoiusQuery);

        // Should be sanitized and not return all users (should be 403 for regular user)
        expect(res.statusCode).toBe(403);
    });

    test('Should prevent XSS attacks', async () => {
        // Register and login
        await registerUser(testUser);
        const loginRes = await loginUser({
            email: testUser.email,
            password: testUser.password
        });

        // Attempt XSS in resource creation
        const xssPayload = {
            title: '<script>alert("XSS")</script>',
            description: 'Description with <img src="x" onerror="alert(\'XSS\')">'
        };

        const res = await request(app)
            .post('/api/resources')
            .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
            .send(xssPayload);

        expect(res.statusCode).toBe(201);

        // Check if the payload was sanitized
        const resourceId = res.body.data._id;

        const getRes = await request(app)
            .get(`/api/resources/${resourceId}`)
            .set('Authorization', `Bearer ${loginRes.body.accessToken}`);

        // Should be sanitized
        expect(getRes.body.data.title).not.toContain('<script>');
        expect(getRes.body.data.description).not.toContain('onerror=');
    });
});

describe('JWT Token Security', () => {
    let userToken;

    beforeEach(async () => {
        //Register and login
        await registerUser(testUser);
        const loginRes = await loginUser({
            email: testUser.email,
            password: testUser.password
        });
        userToken = loginRes.body.accessToken;
    });

    test('Should reject tampered tokens', async () => {
        // Decode token to access its parts
        const parts = userToken.split('.');

        // Tamper with the payload
        const decodePayload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        decodedPayload.toles.push('admin'); // Add admin role

        // Re-encode the payload
        const tamperedPayload = Buffer.from(JSON.stringify(decodedPayload)).toString('base64').replace(/=/g, ''); // Remove padding

        //Create tampered token
        const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

        // Try to access an admin route with the tampered token
        const res = await request(app)
            .get('/api/users')
            .set('Authorization', `Bearer ${tamperedToken}`);
        
        // Should be rejected as the signature won't match
        expect(res.statusCode).toBe(401);
    });

    test('Should reject expired tokens', async () => {
        // Create a token that expires immediately
        const expiredToken = jwt.sign(
            { id: '123', username: 'user', roles: ['user'] },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: '1ms' }
        );

        // Wait for token to expire
        await new Promise(resolve => setTimeout(resolve, 10));

        // Try to access a protected route with the expired token
        const res = await request(app)
            .get('/api/users/me')
            .set('Authorization', `Bearer ${expiredToken}`);

        expect(res.statusCode).toBe(401);
        expect(res.body.message).toContain('expired');
    });
});