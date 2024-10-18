import mongoose from 'mongoose';
import winston from 'winston';

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/mongodb.log' })
    ],
});

export const connectToDatabase = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            serverSelectionTimeoutMS: 5000,
        });

        logger.info('MongoDB connected');
    } catch (err) {
        logger.error('Error connecting to MongoDB: ' + err.message);
        throw new Error('Error connecting to MongoDB: ' + err.message);
    }
};

export const disconnectFromDatabase = async () => {
    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
    } catch (err) {
        logger.error('Error disconnecting from MongoDB: ' + err.message);
    }
};