const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

router.get('/', async (req, res) => {
    return res.status(200).json({message: 'Hello from the server!'});
})


router.get('/check-user', async (req, res) => {
    try {
        // Get token from cookies
        const token = req.cookies.accessToken;
        if (!token) return res.status(401).json({ error: 'No token provided' });

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Optionally, fetch user info from DB
        const user = await User.findById(decoded.id).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Return user info
        res.json({ user });
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
})

router.post('/login', async (req, res) => {
    const {email, password} = req.body;
    try {
        const user = await User.findOne({email});
        if (!user) return res.status(400).json({error: 'Invalid email or password'});


        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({error: 'Invalid email or password'})

        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role},
            process.env.JWT_SECRET,
            {expiresIn: '1h'}
        )

        
        res.cookie('accessToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict', 
            maxAge: 60 * 60 * 1000,
        })
    
        return res.json({message: 'Login successfully', user});
    } catch (err){
        res.status(500).json({error: 'Internal server error'});
    } 
});

router.post('/logout', (req, res) => {
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    });
    return res.json({ message: 'Logged out successfully' });
});

router.post('/register', async (req, res) => {
    const { role, email, password, publicKey, encryptedPrivateKey } = req.body;
    try {
        // Check if user exists
        const user = await User.findOne({email});
        if (user) return res.status(403).json({
            error: 'Email of this account has been made, please login!'
        });
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user with public key
        const newUser = await User.create({
            role,
            email,
            password: hashedPassword,
            publicKey,
            encryptedPrivateKey,
            personalPasswordTable: [],
            sharedPasswordTable: []
        });

        return res.status(200).json({
            message: 'Register successfully',
            user: {
                id: newUser._id,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({
            error: err.message || 'Internal server error'
        });
    }
});

module.exports = router;