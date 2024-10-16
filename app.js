import express, { json } from 'express';
import cors from 'cors';
import { connectToDatabase } from './database.js';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import { generalLimiter, authLimiter } from './config/rateLimit.js';

const app = express();
app.use(json());

// Middleware setup based on environment
const applyMiddleware = (app) => {
    // Apply CORS settings
    const corsOptions = {
        origin: process.env.CORS_ORIGIN || 'http://127.0.0.1:34471',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    };

    app.use(cors(corsOptions));

    // Apply rate limiters and routes depending on environment
    if (process.env.NODE_ENV !== 'test') {
        app.use(generalLimiter); // General rate limiting for all routes
        app.use('/api/auth', authLimiter, authRoutes); // Auth-specific rate limiting
    } else {
        app.use('/api/auth', authRoutes); // No rate limiting in test environment
    }

    // Other routes
    app.use('/api/user', userRoutes);
};

applyMiddleware(app); // Apply the middleware configuration

// Connect to MongoDB unless in test environment
if (process.env.NODE_ENV !== 'test') {
    connectToDatabase();
}

// Export the app for testing and running
export { app };

// Start the server if not in test mode
if (process.env.NODE_ENV !== 'test') {
    const port = process.env.PORT || 3000; // Use environment variable or default to 3000
    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}