# Secure RESTful API

A comprehensive RESTful API implementation with robust security features including OAuth 2.0, JWT tokens, and role-based access control.

## Security Features

This API implementation includes:

- ## OAuth 2.0 Authentication Flow with:
    * Registration & Login
    * Access tokens (short-lived)
    * Refresh tokens (long-lived)
    * Token revocation

- ## JWT (JSON Web Tokens) for:
    * Stateless authentication
    * Payload encryption
    * Role & permission encoding

- ## Role-Based Access Control(RBAC) with:
    * Granular permission management
    * Resource ownership checks
    * Role-based API endpoints

- ## Advanced Security Measures:
    * HTTPS enforcement(in production)
    * Helmet.js security headers
    * CSRF protection
    * Rate limiting (IP-based and Redis-backed)
    * MongoDB injection protection
    * XSS protection
    * HTTP parameter pollution protection
    * Secure cookie settings
    * Request logging
    * Input validation

## Prerequisites
- Node.js(v14+)
- MongoDB(v4+)
- Redis(optional, for production rate limiting)

## Installation
### 1. Clone the repository:
```bash
git clone https://github.com/ErzaKaneki/Portfolio/tree/main/Secure_RESTful_API
cd secure_restful_api
```
### 2. Install dependencies:
```bash
npm install
```
### 3. Create a `.env` file by copying `env.example`:
```bash
cp .env.example .env
```
### 4. Update the `.env` file with your configuration:
```bash
# Generate secure random strings for JWT_ACCESS_SECRET and JWT_REFRESH_SECRET
# You can use: node -e
"console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Running the API

### Development
```bash
npm run dev
```
### Production
```bash
npm start
```

## API Endpoints

### Authentication
- ### POST/api/auth/register: <span style="font-weight:normal">Register a new user</span>
    * Request body:`{ "username": "user1", "email": "user1@example.com", "password": "password123" }`
    * Response:User object with access and refresh tokens
- ### POST/api/auth/login:<span style="font-weight:normal">Login a user</span>
    * Request body:`{ "username": "user1", "email": "user1@example.com", "password": "password123" }`
    * Response:User object with access and refresh tokens
- ### POST/api/auth/refresh-token:<span style="font-weight:normal">Get a new access token</span>
    * Request body:`{ "refreshToken": "your-refresh-token" }`
    * Response:New access and refresh tokens
- ### POST/api/auth/logout:<span style="font-weight:normal">Logout a user(invalidate refresh token)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Response:Success message

### User Management
- ### GET/api/users:<span style="font-weight:normal">Get all users(admin only)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Response:Success message
- ### GET/api/users/me:<span style="font-weight:normal">Get current user profile</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Response:User object
- ### PUT/api/users:<span style="font-weight:normal">Update a user(self or admin)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "username": "updated_username" }`
    * Response:Updated user object
- ### PUT/api/users/roles:<span style="font-weight:normal">Update user roles(admin only)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "roles": ["user", "admin"] }`
    * Response:Updated user object
- ### DELETE/api/users:<span style="font-weight:normal">Delete a user(self or admin)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Response:Empty object

### Resources
- ### POST/api/resources:<span style="font-weight:normal">Create a new resource</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "title": "Resource Title", "description": "Resource description", "accessLevel": "private" }`
    * Responce:Resource object
- ### GET/api/resources:<span style="font-weight:normal">Get all accessible resources</span>
    * Headers:`Authorization: Bearer your-access-token`
    *Response:Array of resource objects
- ### GET/api/resources:<span style="font-weight:normal">Get a single resource</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Response:Resource object
- ### PUT/api/resources:<span style="font-weight:normal">Update a resource(owner or admin)</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "title": "Updated Title" }`
    * Response:Updated resource object
- ### DELETE/api/resources:<span style="font-weight:normal">Delete a resource(owner or admin)</span>
    * Headers:`Authorization: bearer your-access-token`
    * Responce: Empty object
- ### POST/api/resources/access:<span style="font-weight:normal">Grant access to a resource</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "userId": "user_id", "role": "role_name" }`
    * Response:Updated resource object
- ### DELETE/api/resources/access:<span style="font-weight:normal">Revoke access to a resource</span>
    * Headers:`Authorization: Bearer your-access-token`
    * Request body:`{ "userId": "user_id", "role": "role_name" }`
    * Response:Updated resource object

## Security Best Practices

## API Key Management
- Never expose your JWT secrets or any API keys in client-side code
- Rotate secrets and keys regularly
- Use environment variables for all sensitive configuration

## Input Validation
- Validate all input data before processing
- Use schema validation libraries(like Joi or Yup)
- Sanitize inputs to prevent injection attacks

## Authentication
- Implemenmt least privilege principle
- Check permissions on every protected route
- Validate user roles and permissions

## Data Protection
- Encrypt sensitive data at rest
- Use HTTPS for data in transit
- Implement proper database security

## Error Handling
- Use generic error messages to clients
- Log detailed errors server-side
- Don't expose stack traces in production

## Logging and Monitoring
- Log all authentication events
- Monitor for suspicious activity
- Implement audit trails for sensitive operations

# Testing
Run tests with:
```bash
npm test
```

# License
This project is licensed under the MIT License-see the LICENSE file for details.