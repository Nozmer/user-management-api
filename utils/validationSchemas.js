import Joi from 'joi';

const userSchema = Joi.object({
    name: Joi.string().min(3).max(30).required().label('Name').messages({
        'string.empty': 'Name is required',
        'string.min': 'Name should have at least 3 characters',
        'string.max': 'Name should have at most 30 characters'
    }),
    email: Joi.string().email().required().label('Email').messages({
        'string.email': 'Please provide a valid email address',
        'string.empty': 'Email is required'
    }),
    password: Joi.string().min(8).required().label('Password').messages({
        'string.empty': 'Password is required',
        'string.min': 'Password must be at least 8 characters long'
    })
});

const passwordSchema = Joi.object({
    currentPassword: Joi.string().min(8).required().label('Current password').messages({
        'string.empty': 'Current password is required',
        'string.min': 'Current password must be at least 8 characters long'
    }),
    newPassword: Joi.string().min(8).required().label('New password').messages({
        'string.empty': 'New password is required',
        'string.min': 'New password must be at least 8 characters long'
    })
});

export { userSchema, passwordSchema };
