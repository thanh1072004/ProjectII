const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv').config();
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const authRoutes = require('./routes/auth');
const mainRoutes = require('./routes/employee');
const managerRoutes = require('./routes/manager'); // Xác nhận đường dẫn đúng

const app = express();
const uri = process.env.MONGO_URL;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware kiểm tra token
const authMiddleware = (req, res, next) => {
    const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
    console.log('authMiddleware triggered for path:', req.path, 'Token:', token ? 'present' : 'missing');
    if (!token) {
        console.error('No token provided for path:', req.path);
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        console.log('JWT verified for user:', decoded.email, 'Path:', req.path);
        next();
    } catch (err) {
        console.error('JWT verification failed:', err.message, 'Path:', req.path);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Route công khai
app.use('/api/auth', authRoutes);

// Route bảo vệ
app.use('/api/employee', authMiddleware, mainRoutes);
app.use('/api/manager', authMiddleware, managerRoutes);

// Xử lý lỗi 404
app.use((req, res) => {
    console.error('Route not found:', req.method, req.path);
    res.status(404).json({ error: 'Route not found' });
});

mongoose.connect(uri)
    .then(() => console.log('Connected to Database'))
    .catch((err) => console.error('Database connection error:', err));

app.listen(3000, () => {
    console.log('Server running on port 3000');
});