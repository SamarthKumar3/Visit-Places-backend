const HttpError = require('../models/http-error');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { validationResult } = require('express-validator');

const User = require('../models/user');


const getUsers = async (req, res, next) => {
    let users;
    try {
        users = await User.find({}, '-password');
    } catch (err) {
        const error = new HttpError('Fetching users failed, please try again later.', 500);
        return next(error);
    }
    res.json({ users: users.map(user => user.toObject({ getters: true })) });

}

const signUp = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors);
        return next(new HttpError('Invalid Inputs sent, please check your data', 422));
    }

    const { name, email, password } = req.body;

    let existingUser;
    try {
        existingUser = await User.findOne({ email: email });
    } catch (err) {
        const error = new HttpError('Signing Up failed, please try again later.', 500)
        return next(error);
    }

    if (existingUser) {
        const error = new HttpError('User Exists already, please login instead.', 422)
        return next(error);
    }

    let hashedPass;
    try {
        hashedPass = await bcrypt.hash(password, 15);
    } catch (err) {
        const error = new HttpError('Could not create user, please try again', 500);
        return next(error);
    }

    const createdUser = new User({
        name,
        email,
        image: req.file.path,
        password: hashedPass,
        places: []
    });
    try {
        await createdUser.save();
    } catch (err) {
        const error = new HttpError('Signing Up failed, please try again.', 500);
        return next(error);
    }

    let token;
    try {
        token = jwt.sign({ userId: createdUser.id, email: createdUser.email }, `${process.env.JWT_KEY}`, { expiresIn: '1h' });
    } catch (err) {
        const error = new HttpError('Signing Up failed, please try again later.', 500)
        return next(error);
    }

    res.status(201).json({ userId: createdUser.id, email: createdUser.email, token });
}

const login = async (req, res, next) => {
    const { email, password } = req.body;
    let existingUser;
    try {
        existingUser = await User.findOne({ email: email });
    } catch (err) {
        const error = new HttpError('Logging in failed, please try again later.', 500)
        return next(error);
    }

    if (!existingUser) {
        const error = new HttpError('Invalid Credentials, could not log you in.', 401);
        return next(error);
    }

    let isValidPass = false;
    try {
        isValidPass = await bcrypt.compare(password, existingUser.password);
    } catch (err) {
        const error = new HttpError('Could not log you in, please check your credentials and try again', 500);
        return next(error);
    }

    if (!isValidPass) {
        const error = new HttpError('Invalid Credentials, could not log you in.', 403);
        return next(error);
    }

    let token;
    try {
        token = jwt.sign({ userId: existingUser.id, email: existingUser.email }, `${process.env.JWT_KEY}`, { expiresIn: '1h' });
    } catch (err) {
        const error = new HttpError('Logging In failed, please try again later.', 500)
        return next(error);
    }

    res.json({ userId: existingUser.id, email: existingUser.email, token: token });
}

exports.getUsers = getUsers;
exports.login = login;
exports.signUp = signUp;
