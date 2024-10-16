import dotenv from 'dotenv';
dotenv.config();

import { verify } from 'jsonwebtoken-esm';
const SECRET_KEY = process.env.SECRET_KEY;

function authMiddleware(req, res, next) {
    const token = req.get('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired, please log in again' });
        }
        return res.status(401).json({ message: 'Invalid token' });
    }
}

export { authMiddleware };
