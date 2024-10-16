import dotenv from 'dotenv';
import { hash, compare } from 'bcrypt';
import { sign } from 'jsonwebtoken-esm';
import { User } from '../models/user.js';
import { userSchema } from '../utils/validationSchemas.js';
import winston from 'winston'; 

const SECRET_KEY = process.env.SECRET_KEY; 
// Load secret key from environment variable for JWT signing

dotenv.config();

const logger = winston.createLogger({
    level: 'info', 
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => {
            return `[${info.timestamp}] [${info.level}] ${info.message}, IP: ${info.ip}, UserAgent: ${info.userAgent}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/auth.log' }) 
        // Log to file
    ]
});

export async function signup(req, res) {
    const { error } = userSchema.validate(req.body);
    if (error) {
        logger.warn({
            timestamp: new Date().toISOString(),
            message: 'Signup validation error: ' + error.details[0].message,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        });
        return res.status(400).json({ message: error.details[0].message.replace(/"/g, '') });
    }

    const { name, email, password } = req.body;

    try {
        const userExists = await User.findOne({ email });
        if (userExists) {
            logger.warn({
                timestamp: new Date().toISOString(),
                message: 'User already exists: ' + email,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await hash(password, 10);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        logger.info({
            timestamp: new Date().toISOString(),
            message: 'User registered successfully: ' + email,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        logger.error({
            timestamp: new Date().toISOString(),
            message: 'Error during signup: ' + err.message,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        });
        res.status(500).json({ message: 'Internal server error' });
    }
}

export async function signin(req, res) {
    const emailPasswordSchema = userSchema
        .fork(['email', 'password'], (schema) => schema.required())
        .fork(['name'], (schema) => schema.forbidden()); 
    // Modify schema to only validate email and password for sign-in

    const { error } = emailPasswordSchema.validate(req.body);
    if (error) {
        logger.warn({
            timestamp: new Date().toISOString(),
            message: 'Signin validation error: ' + error.details[0].message,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path // Capture request path
        });
        return res.status(400).json({ message: error.details[0].message.replace(/"/g, '') });
    }

    const { email, password } = req.body;
    const userExists = await User.findOne({ email }); 
    if (!userExists || !(await compare(password, userExists.password))) {
        logger.warn({
            timestamp: new Date().toISOString(),
            message: 'Invalid credentials: ' + email, 
            ip: req.ip, 
            userAgent: req.get('User-Agent'),
            path: req.path 
        });
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = sign({ userId: userExists._id, email: userExists.email }, SECRET_KEY, { expiresIn: '1h' });
    // Generate JWT for authenticated user

    logger.info({
        timestamp: new Date().toISOString(),
        message: 'User signed in successfully: ' + email, 
        ip: req.ip, 
        userAgent: req.get('User-Agent'),
        path: req.path
    });

    res.status(200).json({ token }); 
    // Return JWT token to the client
}