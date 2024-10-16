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

export const connectToDatabase = () => {
    return new Promise(async (resolve, reject) => {
        try {
            await mongoose.connect(process.env.MONGO_URI, {
                serverSelectionTimeoutMS: 2000
            });

            const connection = mongoose.connection;

            connection.once('open', () => {
                logger.info('MongoDB connected');
                resolve(true); 
            });

            connection.on('error', (err) => {
                logger.error('MongoDB connection error: ' + err.message);
                reject(new Error('MongoDB connection failed. Ensure MongoDB is running.'));  
            });

        } catch (err) {
            logger.error('Error connecting to MongoDB: ' + err.message);
            reject(new Error('Error connecting to MongoDB: ' + err.message));
        }
    });
};

export const disconnectFromDatabase = async () => {
    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
    } catch (err) {
        logger.error('Error disconnecting from MongoDB: ' + err.message);
    }
};