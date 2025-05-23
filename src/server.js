const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Database Initialization
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        date DATE NOT NULL,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS subscribers (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        subscribed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
    process.exit(1);
  }
}

// Public Routes (index.html)
// Book Appointment
app.post('/api/appointments', async (req, res) => {
  const { name, email, phone, date, message } = req.body;
  try {
    if (!name || !email || !phone || !date) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    const result = await pool.query(
      'INSERT INTO appointments (name, email, phone, date, message) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, date, message]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error booking appointment:', error);
    res.status(500).json({ error: 'Failed to book appointment' });
  }
});

// Contact Message
app.post('/api/messages', async (req, res) => {
  const { name, email, message } = req.body;
  try {
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'All fields must be provided' });
    }
    const result = await pool.query(
      'INSERT INTO messages (name, email, message) VALUES ($1, $2, $3) RETURNING *',
      [name, email, message]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ error: 'Failed to save message' });
  }
});

// Newsletter Subscription
app.post('/api/subscribers', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const result = await pool.query(
      'INSERT INTO subscribers (email) VALUES ($1) ON CONFLICT (email) DO NOTHING RETURNING *',
      [email]
    );
    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'Email already subscribed' });
    }
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error subscribing:', error);
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// Admin Routes (admin.html)
// Register Admin
app.post('/api/admin/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields must be provided' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (error) {
    console.error('Error registering admin:', error);
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to register admin' });
  }
});

// Login Admin
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Send OTP for Forgot Password
app.post('/api/admin/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OAK Dental Clinic - Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 5 minutes.`
    });
    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/admin/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    const result = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (result.rowCount === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Reset Password
app.post('/api/admin/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  try {
    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields must be provided' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      'UPDATE users SET password = $1 WHERE email = $2 RETURNING id',
      [hashedPassword, email]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Admin Dashboard Data (Protected Routes)
// Get Appointments
app.get('/api/admin/appointments', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM appointments ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// Get Messages
app.get('/api/admin/messages', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get Subscribers
app.get('/api/admin/subscribers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM subscribers ORDER BY subscribed_on DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching subscribers:', error);
    res.status(500).json({ error: 'Failed to fetch subscribers' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  await initializeDatabase();
  app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
}

startServer();

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});