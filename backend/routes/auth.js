const express = require('express');
const router = express.Router();
const User = require('../models/user'); 
const { VerificationCode } = require('../models/user'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { generateECDHKeyPair, encryptPrivateKey } = require('../utils/cryptoUtils');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

router.get('/', async (req, res) => {
    console.log('GET /api/auth/ accessed');
    return res.status(200).json({ message: 'Hello from the server!' });
});

router.get('/check-user', async (req, res) => {
    try {
        const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
        console.log('Check-user request:', {
            cookies: req.cookies,
            authorization: req.headers.authorization,
            token: token ? token.substring(0, 20) + '...' : null
        });
        if (!token) {
            console.error('No token provided in /check-user');
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Token decoded:', { id: decoded.id, email: decoded.email, role: decoded.role });
        const user = await User.findById(decoded.id).select('email role publicKey encryptedPrivateKey fullName phoneNumber');
        if (!user) {
            console.error('User not found for ID:', decoded.id);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('User found for /check-user:', { email: user.email, role: user.role, fullName: user.fullName, phoneNumber: user.phoneNumber });
        res.json({ 
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                publicKey: user.publicKey,
                encryptedPrivateKey: user.encryptedPrivateKey,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber
            }
        });
    } catch (err) {
        console.error('Error in /check-user:', {
            message: err.message,
            stack: err.stack
        });
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

router.post('/login', async (req, res) => {
    const { email, password, role } = req.body;
    console.log('Login attempt:', {
        email,
        role,
        hasPassword: !!password,
        headers: {
            'content-type': req.headers['content-type'],
            origin: req.headers.origin
        }
    });

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.error('Invalid email:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        console.log('User found:', {
            email: user.email,
            role: user.role,
            hasPublicKey: !!user.publicKey,
            hasEncryptedPrivateKey: !!user.encryptedPrivateKey,
            fullName: user.fullName,
            phoneNumber: user.phoneNumber
        });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.error('Invalid password for email:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        console.log('Password matched for:', email);

        if (role && user.role !== role) {
            console.error(`Role mismatch: requested ${role}, user has ${user.role}`);
            return res.status(403).json({ error: `Account does not have ${role} role` });
        }
        console.log('Role verified:', role);

        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        console.log('Token generated:', { token: token.substring(0, 20) + '...' });

        res.cookie('accessToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            maxAge: 60 * 60 * 1000
        });
        console.log('Cookie set:', {
            name: 'accessToken',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            maxAge: '1h'
        });

        res.json({
            message: 'Login successful',
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                publicKey: user.publicKey,
                encryptedPrivateKey: user.encryptedPrivateKey,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber
            },
            token
        });
        console.log('Login response sent:', { 
            email, 
            role, 
            publicKey: !!user.publicKey,
            fullName: user.fullName,
            phoneNumber: user.phoneNumber
        });
    } catch (err) {
        console.error('Login error:', {
            message: err.message,
            stack: err.stack,
            email,
            role
        });
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/logout', (req, res) => {
    console.log('Logout request received');
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
    });
    console.log('Cookie cleared: accessToken');
    return res.json({ message: 'Logged out successfully' });
});

router.post('/send-verification-code', async (req, res) => {
    const { role, email, password, code } = req.body;
    console.log('Send verification code attempt:', { email, role, hasPassword: !!password, code });

    try {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/;
        if (!emailRegex.test(email)) {
            console.error('Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.error('Email already exists:', email);
            return res.status(403).json({ error: 'Email already registered, please login' });
        }

        if (!['employee', 'manager'].includes(role)) {
            console.error('Invalid role:', role);
            return res.status(400).json({ error: 'Invalid role' });
        }

        if (role === 'manager' && code !== process.env.VITE_SECRET_CODE) {
            console.error('Invalid secret code:', code);
            return res.status(400).json({ error: 'Invalid secret code for manager' });
        }

        // generate key pair ECDH
        const { publicKey, privateKey } = await generateECDHKeyPair();
        console.log('Generated key pair:', {
            publicKey: publicKey.substring(0, 20) + '...',
            privateKey: privateKey.substring(0, 20) + '...'
        });

        let encryptedPrivateKey;
        try {
            const rawEncryptedPrivateKey = await encryptPrivateKey(privateKey, password);
            encryptedPrivateKey = typeof rawEncryptedPrivateKey === 'string' ? JSON.parse(rawEncryptedPrivateKey) : rawEncryptedPrivateKey;
            console.log('Encrypted privateKey:', {
                salt: encryptedPrivateKey.salt.substring(0, 20) + '...',
                iv: encryptedPrivateKey.iv,
                ciphertext: encryptedPrivateKey.ciphertext.substring(0, 20) + '...',
                authTag: encryptedPrivateKey.authTag
            });
        } catch (err) {
            console.error('Failed to encrypt privateKey:', err.message);
            return res.status(500).json({ error: 'Failed to encrypt private key' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed for:', email);

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        await VerificationCode.findOneAndUpdate(
            { email },
            {
                email,
                code: verificationCode,
                userData: {
                    email,
                    role,
                    publicKey,
                    encryptedPrivateKey,
                    hashedPassword
                }
            },
            { upsert: true, new: true }
        );

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'SafeVault Verification Code',
            text: `Your verification code is: ${verificationCode}. It will expire in 15 minutes.`
        };

        await transporter.sendMail(mailOptions);
        console.log('Verification code sent to:', email);

        res.status(200).json({
            message: 'Verification code sent to your email',
            privateKey
        });
    } catch (err) {
        console.error('Send verification code error:', {
            message: err.message,
            stack: err.stack
        });
        res.status(500).json({ error: 'Failed to send verification code: ' + err.message });
    }
});

router.post('/verify-code', async (req, res) => {
    const { email, code, privateKey } = req.body;
    console.log('Verify code attempt:', { email, code, hasPrivateKey: !!privateKey });

    try {
        if (!email || !code || !privateKey) {
            console.error('Missing required fields:', { email, code, hasPrivateKey: !!privateKey });
            return res.status(400).json({ error: 'Email, code, and privateKey are required' });
        }

        const verification = await VerificationCode.findOne({ email, code });
        if (!verification) {
            console.error('Invalid or expired verification code:', { email, code });
            return res.status(400).json({ error: 'Invalid or expired verification code' });
        }

        const { userData } = verification;
        const newUser = new User({
            email: userData.email,
            role: userData.role,
            password: userData.hashedPassword,
            publicKey: userData.publicKey,
            encryptedPrivateKey: userData.encryptedPrivateKey,
            personalPasswordTable: [],
            sharedPasswordTable: [],
            notifications: []
        });

        await newUser.save();
        await VerificationCode.deleteOne({ email, code });
        console.log('User created:', { id: newUser._id, email: newUser.email, role: newUser.role });

        const token = jwt.sign(
            { id: newUser._id, email: newUser.email, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('accessToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            maxAge: 60 * 60 * 1000
        });

        res.json({
            message: 'Registration successful',
            user: {
                id: newUser._id,
                email: newUser.email,
                role: newUser.role,
                publicKey: newUser.publicKey,
                encryptedPrivateKey: userData.encryptedPrivateKey
            },
            privateKey
        });
    } catch (err) {
        console.error('Verify code error:', {
            message: err.message,
            stack: err.stack
        });
        res.status(500).json({ error: 'Verification failed: ' + err.message });
    }
});

router.post('/register', async (req, res) => {
    const { role, email, password, code } = req.body;
    console.log('Register attempt:', {
        email,
        role,
        hasPassword: !!password,
        code
    });

    try {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/;
        if (!emailRegex.test(email)) {
            console.error('Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.error('Email already exists:', email);
            return res.status(403).json({ error: 'Email already registered, please login' });
        }

        if (!['employee', 'manager'].includes(role)) {
            console.error('Invalid role:', role);
            return res.status(400).json({ error: 'Invalid role' });
        }

        if (role === 'manager' && code !== process.env.VITE_SECRET_CODE) {
            console.error('Invalid secret code:', code);
            return res.status(400).json({ error: 'Invalid secret code for manager' });
        }

        const { publicKey, privateKey } = await generateECDHKeyPair();
        console.log('Generated key pair:', {
            publicKey: publicKey.substring(0, 20) + '...',
            privateKey: privateKey.substring(0, 20) + '...'
        });

        let encryptedPrivateKey;
        try {
            const rawEncryptedPrivateKey = await encryptPrivateKey(privateKey, password);
            encryptedPrivateKey = typeof rawEncryptedPrivateKey === 'string' ? JSON.parse(rawEncryptedPrivateKey) : rawEncryptedPrivateKey;
            console.log('Encrypted privateKey:', {
                salt: encryptedPrivateKey.salt.substring(0, 20) + '...',
                iv: encryptedPrivateKey.iv,
                ciphertext: encryptedPrivateKey.ciphertext.substring(0, 20) + '...',
                authTag: encryptedPrivateKey.authTag
            });
        } catch (err) {
            console.error('Failed to encrypt privateKey:', err.message);
            return res.status(500).json({ error: 'Failed to encrypt private key' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed for:', email);

        const newUser = new User({
            role,
            email,
            password: hashedPassword,
            publicKey,
            encryptedPrivateKey,
            personalPasswordTable: [],
            sharedPasswordTable: []
        });

        await newUser.save();
        console.log('User created:', {
            id: newUser._id,
            email: newUser.email,
            role: newUser.role
        });

        res.status(200).json({
            message: 'Register successful',
            user: {
                id: newUser._id,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (err) {
        console.error('Registration error:', {
            message: err.message,
            stack: err.stack,
            email,
            role
        });
        res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
});

router.put('/update-user', async (req, res) => {
    const { fullName, phoneNumber } = req.body;
    console.log('Update user information attempt:', { fullName, phoneNumber });

    try {
        const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
        if (!token) {
            console.error('No token provided in /update-user');
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) {
            console.error('User not found for ID:', decoded.id);
            return res.status(404).json({ error: 'User not found' });
        }

        user.fullName = fullName || user.fullName;
        user.phoneNumber = phoneNumber || user.phoneNumber;
        await user.save();

        console.log('User information updated successfully for:', decoded.email);
        res.json({ 
            message: 'Information updated successfully',
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                publicKey: user.publicKey,
                encryptedPrivateKey: user.encryptedPrivateKey,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber
            }
        });
    } catch (err) {
        console.error('Error updating user information:', {
            message: err.message,
            stack: err.stack
        });
        res.status(500).json({ error: 'Failed to update information: ' + err.message });
    }
});

router.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    console.log('Change password attempt:', {
        hasCurrentPassword: !!currentPassword,
        hasNewPassword: !!newPassword
    });

    try {
        const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
        if (!token) {
            console.error('No token provided in /change-password');
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Token decoded:', { id: decoded.id, email: decoded.email });

        const user = await User.findById(decoded.id);
        if (!user) {
            console.error('User not found for ID:', decoded.id);
            return res.status(404).json({ error: 'User not found' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            console.error('Invalid current password for user:', user.email);
            return res.status(401).json({ error: 'Invalid current password' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        console.log('New password hashed for user:', user.email);

        user.password = hashedPassword;

        try {
            const { publicKey, privateKey } = await generateECDHKeyPair();
            const encryptedPrivateKey = await encryptPrivateKey(privateKey, newPassword);
            user.publicKey = publicKey;
            user.encryptedPrivateKey = JSON.parse(encryptedPrivateKey);
            console.log('Generated new key pair and encrypted private key for:', user.email);
        } catch (err) {
            console.error('Failed to update encrypted private key:', err.message);
            return res.status(500).json({ error: 'Failed to update encryption keys' });
        }

        await user.save();
        console.log('User password updated successfully:', user.email);

        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
        });

        res.json({ message: 'Password changed successfully. Please log in again.' });
    } catch (err) {
        console.error('Change password error:', {
            message: err.message,
            stack: err.stack
        });
        res.status(500).json({ error: 'Failed to change password: ' + err.message });
    }
});

module.exports = router;