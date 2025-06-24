const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv').config();
const cookieParser = require('cookie-parser')
const cors = require('cors')

const authRoutes = require('./routes/auth');
const mainRoutes = require('./routes/employee');

const app = express();
const uri = process.env.MONGO_URL;

//middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
}))
app.use('/api/auth', authRoutes);
app.use('/api', mainRoutes);

mongoose.connect(uri)
  .then(() => console.log('Connected to Database'))
  .catch((err) => console.error('Database connection error:', err));

app.listen(3000, () => {
  console.log('Server running on port 3000');
});




