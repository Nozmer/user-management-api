import express from 'express';
const router = express.Router();
import * as userController from '../controllers/userController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';

router.post('/profile-photo', authMiddleware, userController.updateProfilePhoto);
router.get('/users', authMiddleware, userController.getUser);
router.put('/name', authMiddleware, userController.updateUserName);
router.put('/email', authMiddleware, userController.updateUserEmail);
router.put('/password', authMiddleware, userController.updateUserPassword);

export default router;