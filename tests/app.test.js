require('dotenv').config();

import request from 'supertest';
import { compare, hash } from 'bcrypt';
import { connectToDatabase, disconnectFromDatabase } from '../database';
import { verify, sign } from 'jsonwebtoken';
import { join } from 'path';
import { existsSync, unlinkSync } from 'fs';
import { app } from '../app';
import { User } from '../models/user';
import { authMiddleware } from '../middleware/authMiddleware';
import { registerTestUser, loginAndGetToken } from './utils';

const SECRET_KEY = process.env.SECRET_KEY;

// Connect to MongoDB before all tests (globally)
beforeAll(async () => {
    try {
        await connectToDatabase();
    } catch (error) {
        console.error(error.message);
        throw error; 
    }
});

// Close the connection to MongoDB after all tests (globally)
afterAll(async () => {
    await disconnectFromDatabase();
});

// Tests
describe('POST /api/auth/signup', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should register a new user successfully', async () => {
        const userData = {
            name: 'Test User',
            email: 'testuser@example.com',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(201);
        expect(res.body.message).toBe('User registered successfully');
        const newUser = await User.findOne({ email: userData.email });
        expect(newUser).toBeDefined();
        const passwordMatch = await compare(userData.password, newUser.password);
        expect(passwordMatch).toBe(true);
    });

    it('should not allow registration with an existing email', async () => {
        const existingUser = new User({
            name: 'Existing User',
            email: 'existinguser@example.com',
            password: await hash('password123', 10),
        });

        await existingUser.save();

        const userData = {
            name: 'New User',
            email: 'existinguser@example.com',
            password: 'newpassword'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('User already exists');
    });

    it('should return an error if the name is too short', async () => {
        const userData = {
            name: 'Jo', // Nome com menos de 3 caracteres
            email: 'jo@example.com',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Name should have at least 3 characters');
    });

    it('should return an error if the email is invalid', async () => {
        const userData = {
            name: 'John Doe',
            email: 'invalid-email',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Please provide a valid email address');
    });

    it('should return an error if the password is too short', async () => {
        const userData = {
            name: 'Jane Doe',
            email: 'janedoe@example.com',
            password: 'short'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Password must be at least 8 characters long');
    });

    it('should return an error if any required field is missing', async () => {
        const userData = {
            email: 'janedoe@example.com',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signup')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Name is required');
    });
});

describe('POST /api/auth/signin', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should check that the password is correct', async () => {
        const registeredUser = await registerTestUser();

        const userData = {
            email: 'testuser@example.com',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signin')
            .send(userData);

        // Check if the status is 200
        expect(res.statusCode).toEqual(200);

        // Check if the token is present
        expect(res.body.token).toBeDefined();

        // Check if the token is in the format of a JWT
        expect(res.body.token.split('.').length).toBe(3);

        // Decode the token and check if the content is correct
        const decodedToken = verify(res.body.token, SECRET_KEY);
        expect(decodedToken).toHaveProperty('userId');
        expect(decodedToken.userId.toString()).toBe(registeredUser._id.toString());
        expect(decodedToken.email).toBe('testuser@example.com');
    });

    it('should check that the password is incorrect', async () => {
        await registerTestUser();

        const userData = {
            email: 'testuser@example.com',
            password: 'wrongpassword'
        };

        const res = await request(app)
            .post('/api/auth/signin')
            .send(userData);

        expect(res.statusCode).toEqual(401);
        expect(res.body.message).toBe('Invalid credentials');
    });

    it('should return an error if the email is invalid', async () => {
        const userData = {
            email: 'invalid-email',
            password: 'password123'
        };

        const res = await request(app)
            .post('/api/auth/signin')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Please provide a valid email address');
    });

    it('should return an error if the password is too short', async () => {
        const userData = {
            email: 'janedoe@example.com',
            password: 'short'
        };

        const res = await request(app)
            .post('/api/auth/signin')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Password must be at least 8 characters long');
    });

    it('should return an error if any required field is missing', async () => {
        const userData = {
            email: 'janedoe@example.com'
        };

        const res = await request(app)
            .post('/api/auth/signin')
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Password is required');
    });
});

describe('GET /api/users', () => {
    beforeEach(async () => {
        await User.deleteMany({});

        const users = [
            { name: 'John Doe', email: 'john@example.com', password: 'exemple123' },
            { name: 'Jane Smith', email: 'jane@example.com', password: 'exemple123' },
            { name: 'Alice Johnson', email: 'alice@example.com', password: 'exemple123' },
        ];

        try {
            await User.insertMany(users);
        } catch (error) {
            console.error('Error adding users:', error);
        }
    });

    it('should return paginated users with limit and page', async () => {
        await registerTestUser(); // Here another user was added to the array so that it is possible to access via login

        const token = await loginAndGetToken(); // Mock function to get auth token

        const res = await request(app)
            .get('/api/user/users?page=1&limit=2')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.data).toHaveLength(2);
        expect(res.body.page).toBe(1);
        expect(res.body.limit).toBe(2);
        expect(res.body.totalUsers).toBe(4);
        expect(res.body.totalPages).toBe(2);
    });

    it('should return filtered users by name', async () => {
        await registerTestUser(); // Here another user was added to the array so that it is possible to access via login

        const token = await loginAndGetToken();

        const res = await request(app)
            .get('/api/user/users?email=john')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.data).toHaveLength(1); // Only one user matches "john"
        expect(res.body.data[0].name).toBe('John Doe');
    });

    it('should return filtered users by email', async () => {
        await registerTestUser(); // Here another user was added to the array so that it is possible to access via login

        const token = await loginAndGetToken();

        const res = await request(app)
            .get('/api/user/users?email=jane')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.data).toHaveLength(1); // Only one user matches "jane@example.com"
        expect(res.body.data[0].email).toBe('jane@example.com');
    });

    it('should return empty data if no users match the filter', async () => {
        await registerTestUser(); // Here another user was added to the array so that it is possible to access via login

        const token = await loginAndGetToken();

        const res = await request(app)
            .get('/api/user/users?name=nonexistent')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.data).toHaveLength(0); // No users should match the name "nonexistent"
        expect(res.body.totalUsers).toBe(0); // Total users should be 0
    });

    it('should return 401 if no token is provided', async () => {
        const res = await request(app)
            .get('/api/user/users?page=1&limit=2'); // No Authorization header

        expect(res.statusCode).toBe(401);
        expect(res.body.message).toBe('Unauthorized: No token provided');
    });
});

describe('PUT /api/user/name', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should check if name has been changed', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            name: 'testuser1'
        };

        const res = await request(app)
            .put('/api/user/name')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(200);
        expect(res.body.message).toBe('Name updated successfully');
        expect(res.body.userName).toBeDefined();
        expect(res.body.userName).toBe(userData.name);
    });

    it('should return an error if the name is too short', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            name: 'te'
        };

        const res = await request(app)
            .put('/api/user/name')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Name should have at least 3 characters');
    });

    it('should return an error if name is missing', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
        };

        const res = await request(app)
            .put('/api/user/name')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Name is required');
    });
});

describe('PUT /api/user/email', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should check if email has been changed', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            email: 'testuser1@example.com'
        };

        const res = await request(app)
            .put('/api/user/email')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(200);
        expect(res.body.message).toBe('Email updated successfully');
        expect(res.body.userEmail).toBeDefined();
        expect(res.body.userEmail).toBe(userData.email);
    });

    it('should return an error if the email is invalid', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            email: 'testuser1'
        };

        const res = await request(app)
            .put('/api/user/email')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Please provide a valid email address');
    });

    it('should return an error if email is missing', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
        };

        const res = await request(app)
            .put('/api/user/email')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Email is required');
    });
});

describe('PUT /api/user/password', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should check if the password does not match the current one', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            newPassword: "password123",
            currentPassword: 'password123'
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('New password cannot be the same as the current password');
    });

    it('should check if password has been changed', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            newPassword: "passwordd123",
            currentPassword: 'password123'
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(200);
        expect(res.body.message).toBe('Password updated successfully');
    });

    it('should return an error if the new password is too short', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            newPassword: "pas",
            currentPassword: 'password123'
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('New password must be at least 8 characters long');
    });

    it('should return an error if the current password is too short', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            newPassword: "passwordd123",
            currentPassword: 'pas'
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Current password must be at least 8 characters long');
    });

    it('should return an error if new passord is missing', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            currentPassword: 'password123'
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('New password is required');
    });

    it('should return an error if current passord is missing', async () => {
        await registerTestUser();

        const token = await loginAndGetToken();

        const userData = {
            newPassword: "passwordd123"
        };

        const res = await request(app)
            .put('/api/user/password')
            .set('Authorization', `Bearer ${token}`)
            .send(userData);

        expect(res.statusCode).toEqual(400);
        expect(res.body.message).toBe('Current password is required');
    });
});

describe('POST /api/user/profile-photo', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    it('should upload a profile photo successfully', async () => {
        const filePath = join(__dirname, 'test-files', 'profile-photo.jpg'); // Caminho do arquivo de teste

        if (!existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        await registerTestUser();
        const token = await loginAndGetToken();

        const res = await request(app)
            .post('/api/user/profile-photo')
            .set('Authorization', `Bearer ${token}`)
            .attach('profilePhoto', filePath);

        expect(res.statusCode).toBe(200);
        expect(res.body.message).toBe('Profile photo uploaded successfully');
        expect(res.body.filePath).toBeDefined();

        const uploadedFilePath = join(__dirname, '..', res.body.filePath);

        const fileExists = existsSync(uploadedFilePath);
        expect(fileExists).toBe(true);

        if (fileExists) {
            unlinkSync(uploadedFilePath);
        }
    });

    it('should return an error if no file is uploaded', async () => {
        await registerTestUser();
        const token = await loginAndGetToken();

        const res = await request(app)
            .post('/api/user/profile-photo')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(400);
        expect(res.body.message).toBe('No file uploaded');
    });

    it('should return an error if the file type is not allowed', async () => {
        await registerTestUser();
        const token = await loginAndGetToken();

        const filePath = join(__dirname, 'test-files', 'invalid-file.txt'); // Invalid file

        const res = await request(app)
            .post('/api/user/profile-photo')
            .set('Authorization', `Bearer ${token}`)
            .attach('profilePhoto', filePath);

        expect(res.statusCode).toBe(400);
        expect(res.body.message).toBe('Only images are allowed');
    });

    it('should return an error if the file size exceeds the limit', async () => {
        await registerTestUser();
        const token = await loginAndGetToken();

        const filePath = join(__dirname, 'test-files', 'large-photo.jpg'); // Arquivo grande de teste

        const res = await request(app)
            .post('/api/user/profile-photo')
            .set('Authorization', `Bearer ${token}`)
            .attach('profilePhoto', filePath);

        expect(res.statusCode).toBe(400);
        expect(res.body.message).toBe('File upload error: File too large');
    });
});

describe('Auth Middleware', () => {
    const token = sign({ userId: 1, email: 'testuser@example.com' }, SECRET_KEY, { expiresIn: '1h' });

    it('should return 401 if no token is provided', () => {
        const req = { get: jest.fn().mockReturnValue(null) }; // Mock de req.get()
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
        const next = jest.fn();

        authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized: No token provided' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is invalid', () => {
        const req = { get: jest.fn().mockReturnValue('Bearer invalidtoken') }; // Token inválido
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
        const next = jest.fn();

        authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Invalid token' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should call next() if token is valid', () => {
        const req = { get: jest.fn().mockReturnValue(`Bearer ${token}`) }; // Token válido
        const res = {};
        const next = jest.fn();

        authMiddleware(req, res, next);

        expect(req.user).toBeDefined();
        expect(req.user.userId).toBe(1);
        expect(req.user.email).toBe('testuser@example.com');
        expect(next).toHaveBeenCalled();
    });
});