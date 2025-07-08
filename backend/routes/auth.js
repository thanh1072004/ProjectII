const express = require('express');
const router = express.Router();
const User = require('../models/user'); // Import User làm default
const { VerificationCode } = require('../models/user'); // Import VerificationCode làm named export
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
        const user = await User.findById(decoded.id).select('email role publicKey encryptedPrivateKey');
        if (!user) {
            console.error('User not found for ID:', decoded.id);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('User found for /check-user:', { email: user.email, role: user.role });
        res.json({ user });
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
            hasEncryptedPrivateKey: !!user.encryptedPrivateKey
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
                encryptedPrivateKey: user.encryptedPrivateKey
            },
            token
        });
        console.log('Login response sent:', { email, role, publicKey: !!user.publicKey });
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
        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/;
        if (!emailRegex.test(email)) {
            console.error('Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Kiểm tra người dùng tồn tại
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.error('Email already exists:', email);
            return res.status(403).json({ error: 'Email already registered, please login' });
        }

        // Kiểm tra vai trò hợp lệ
        if (!['employee', 'manager'].includes(role)) {
            console.error('Invalid role:', role);
            return res.status(400).json({ error: 'Invalid role' });
        }

        // Kiểm tra mã bí mật cho manager
        if (role === 'manager' && code !== process.env.VITE_SECRET_CODE) {
            console.error('Invalid secret code:', code);
            return res.status(400).json({ error: 'Invalid secret code for manager' });
        }

        // Tạo cặp khóa ECDH
        const { publicKey, privateKey } = await generateECDHKeyPair();
        console.log('Generated key pair:', {
            publicKey: publicKey.substring(0, 20) + '...',
            privateKey: privateKey.substring(0, 20) + '...'
        });

        // Mã hóa privateKey
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

        // Hash mật khẩu
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed for:', email);

        // Tạo mã xác thực
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

        // Gửi email
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

        res.status(200).json({
            message: 'Registration successful',
            user: {
                id: newUser._id,
                email: newUser.email,
                role: newUser.role,
                publicKey: newUser.publicKey,
                encryptedPrivateKey: newUser.encryptedPrivateKey
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
        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/;
        if (!emailRegex.test(email)) {
            console.error('Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Kiểm tra người dùng tồn tại
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.error('Email already exists:', email);
            return res.status(403).json({ error: 'Email already registered, please login' });
        }

        // Kiểm tra vai trò hợp lệ
        if (!['employee', 'manager'].includes(role)) {
            console.error('Invalid role:', role);
            return res.status(400).json({ error: 'Invalid role' });
        }

        // Kiểm tra mã bí mật cho manager
        if (role === 'manager' && code !== process.env.VITE_SECRET_CODE) {
            console.error('Invalid secret code:', code);
            return res.status(400).json({ error: 'Invalid secret code for manager' });
        }

        // Tạo cặp khóa ECDH
        const { publicKey, privateKey } = await generateECDHKeyPair();
        console.log('Generated key pair:', {
            publicKey: publicKey.substring(0, 20) + '...',
            privateKey: privateKey.substring(0, 20) + '...'
        });

        // Mã hóa privateKey
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

        // Hash mật khẩu
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed for:', email);

        // Tạo người dùng
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

module.exports = router;