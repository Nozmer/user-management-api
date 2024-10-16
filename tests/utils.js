// tests/utils.js
import { hash } from 'bcrypt';
import { User } from '../models/user';
import { app } from '../app';
import request from 'supertest';

// Helper to register a user
async function registerTestUser() {
    const hashedPassword = await hash('password123', 10);
    
    const newUser = new User({
        name: 'Test User',
        email: 'testuser@example.com',
        password: hashedPassword
    });

    await newUser.save();

    return newUser;
}

async function loginAndGetToken() {
    const res = await request(app)
        .post('/api/auth/signin')
        .send({
            email: 'testuser@example.com',
            password: 'password123'
        });
    
    return res.body.token; 
}

export { registerTestUser, loginAndGetToken };
