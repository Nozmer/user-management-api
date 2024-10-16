import { User } from '../models/user.js';
import multer from 'multer';
import upload from '../config/uploadConfig.js';
import { join } from 'path';
import { userSchema, passwordSchema } from '../utils/validationSchemas.js';
import { compare, hash } from 'bcrypt';
import winston from 'winston';

// Configuring the logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => {
            return `[${info.timestamp}] [${info.level}] ${info.message} - UserID: ${info.userId}, IP: ${info.ip}, Path: ${info.path}, UserAgent: ${info.userAgent}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/user.log' })
    ]
});

export function updateProfilePhoto(req, res) {
    // Middleware to handle file uploads
    upload.single('profilePhoto')(req, res, async (err) => { // Use async to handle database operations
        // Log the request details including user IP
        logger.info({
            timestamp: new Date().toISOString(), // Capture timestamp
            level: 'info',
            message: 'Profile photo upload attempt',
            userId: req.user.userId,
            ip: req.ip, // Capture IP address
            userAgent: req.get('User-Agent'), // Capture User-Agent
            path: req.path // Capture the path of the request
        });

        if (err) {
            if (err instanceof multer.MulterError) {
                // Log error if it's a multer error
                logger.error({
                    timestamp: new Date().toISOString(),
                    level: 'error',
                    message: 'File upload error',
                    userId: req.user.userId,
                    ip: req.ip,
                    error: err.message
                });
                return res.status(400).json({ message: 'File upload error: ' + err.message });
            } else if (err) {
                // Log generic upload error
                logger.error({
                    timestamp: new Date().toISOString(),
                    level: 'error',
                    message: 'Upload error',
                    userId: req.user.userId,
                    ip: req.ip,
                    error: err.message
                });
                return res.status(400).json({ message: err.message });
            }
        }

        // Check if no file was uploaded
        if (!req.file) {
            logger.warn({
                timestamp: new Date().toISOString(),
                level: 'warn',
                message: 'No file uploaded',
                userId: req.user.userId,
                ip: req.ip // Capture IP address
            });
            return res.status(400).json({ message: 'No file uploaded' });
        }

        // Find the user in the database
        const user = await User.findById(req.user.userId); // Use Mongoose method to find user by ID
        if (!user) {
            logger.warn({
                timestamp: new Date().toISOString(),
                level: 'warn',
                message: 'User not found',
                userId: req.user.userId,
                ip: req.ip
            });
            return res.status(404).json({ message: 'User not found' });
        }

        // Update user's profile picture in the database
        user.profilePicture = req.file.path; // Save the file path to the user document

        // Save the updated user document
        await user.save(); // Ensure to save the user after updating

        // Log successful upload
        logger.info({
            timestamp: new Date().toISOString(),
            level: 'info',
            message: 'Profile photo uploaded successfully',
            userId: req.user.userId,
            filePath: req.file.path,
            ip: req.ip // Capture IP address
        });
        res.status(200).json({
            message: 'Profile photo uploaded successfully',
            filePath: join('uploads', req.file.filename)
        });
    });
}

export async function getUser(req, res) {
    const { name, email, page = 1, limit = 10 } = req.query;

    // Log the request details including user IP
    logger.info({
        timestamp: new Date().toISOString(), // Capture timestamp
        level: 'info',
        message: 'Get User request',
        ip: req.ip, // Capture IP address
        userAgent: req.get('User-Agent'), // Capture User-Agent
        path: req.path // Capture the path of the request
    });

    // Fetch all users from the database
    let filteredUser = await User.find(); // Use Mongoose to get all users

    // Filter User by name if provided
    if (name) {
        filteredUser = filteredUser.filter(user =>
            user.name.toLowerCase().split(' ').includes(name.toLowerCase())
        );
    }

    // Filter User by email if provided
    if (email) {
        filteredUser = filteredUser.filter(user => user.email.toLowerCase().includes(email.toLowerCase()));
    }

    // Pagination logic
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const paginatedUser = filteredUser.slice(startIndex, endIndex); // Get paginated User

    // Log information about the fetched User
    logger.info({
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'Fetched User',
        totalUser: filteredUser.length,
        page,
        limit,
        ip: req.ip // Capture IP address
    });
    res.status(200).json({
        data: paginatedUser,
        page: parseInt(page),
        limit: parseInt(limit),
        totalUsers: filteredUser.length,
        totalPages: Math.ceil(filteredUser.length / limit)
    });
}

export async function updateUserName(req, res) {
    const nameSchema = userSchema
        .fork(['name'], (schema) => schema.required()) // Validate name
        .fork(['email', 'password'], (schema) => schema.forbidden()); // Disallow email and password during name update

    const { error } = nameSchema.validate(req.body);
    if (error) {
        // Log validation error
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'Update name validation error',
            error: error.details[0].message,
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(400).json({ message: error.details[0].message.replace(/"/g, '') });
    }

    const newName = req.body.name;
    const user = await User.findById(req.user.userId); // Use Mongoose method to find user by ID
    if (!user) {
        // Log warning if user is not found
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'User not found',
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(404).json({ message: 'User not found' });
    }

    // Update user's name
    user.name = newName;

    // Save the updated user document
    await user.save(); // Ensure to save the user after updating

    // Log successful name update
    logger.info({
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'User name updated successfully',
        userId: req.user.userId,
        newName,
        ip: req.ip
    });
    res.status(200).json({
        message: 'Name updated successfully',
        userName: user.name
    });
}

export async function updateUserEmail(req, res) {
    const emailSchema = userSchema
        .fork(['email'], (schema) => schema.required()) // Validate email
        .fork(['name', 'password'], (schema) => schema.forbidden()); // Disallow name and password during email update

    const { error } = emailSchema.validate(req.body);
    if (error) {
        // Log validation error
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'Update email validation error',
            error: error.details[0].message,
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(400).json({ message: error.details[0].message.replace(/"/g, '') });
    }

    const newEmail = req.body.email;
    const user = await User.findById(req.user.userId); // Use Mongoose method to find user by ID
    if (!user) {
        // Log warning if user is not found
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'User not found',
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(404).json({ message: 'User not found' });
    }

    // Update user's email
    user.email = newEmail;

    // Save the updated user document
    await user.save(); // Ensure to save the user after updating

    // Log successful email update
    logger.info({
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'User email updated successfully',
        userId: req.user.userId,
        newEmail,
        ip: req.ip
    });
    res.status(200).json({
        message: 'Email updated successfully',
        userEmail: user.email
    });
}

export async function updateUserPassword(req, res) {
    const { error } = passwordSchema.validate(req.body);
    if (error) {
        // Log validation error
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'Update password validation error',
            error: error.details[0].message,
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(400).json({ message: error.details[0].message.replace(/"/g, '') });
    }

    const { newPassword, currentPassword } = req.body;
    const user = await User.findById(req.user.userId); // Use Mongoose method to find user by ID
    if (!user) {
        // Log warning if user is not found
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'User not found',
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(404).json({ message: 'User not found' });
    }

    // Check if current password matches
    const isMatch = await compare(currentPassword, user.password);
    if (!isMatch) {
        // Log warning for invalid current password
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'Invalid current password',
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(400).json({ message: 'Invalid current password' });
    }

    // Check if the new password is the same as the current one
    const isSamePassword = await compare(newPassword, user.password);
    if (isSamePassword) {
        // Log warning for trying to set the same password
        logger.warn({
            timestamp: new Date().toISOString(),
            level: 'warn',
            message: 'New password cannot be the same as current password',
            userId: req.user.userId,
            ip: req.ip
        });
        return res.status(400).json({ message: 'New password cannot be the same as the current password' });
    }

    // Hash the new password before saving it
    const hashedPassword = await hash(newPassword, 10);
    user.password = hashedPassword;

    // Save the updated user document
    await user.save(); // Ensure to save the user after updating

    // Log successful password update
    logger.info({
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'User password updated successfully',
        userId: req.user.userId,
        ip: req.ip
    });
    res.status(200).json({
        message: 'Password updated successfully'
    });
}