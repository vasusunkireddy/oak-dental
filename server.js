const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://oakdental.com'], // Allow frontend origins
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// Input Validation Middleware
const validateInput = (req, res, next) => {
  const { name, email, mobile, date, title, description, price, validity, message, password } = req.body;
  if (name && (typeof name !== 'string' || name.trim().length < 2)) {
    return res.status(400).json({ error: 'Name must be a string with at least 2 characters' });
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (mobile && !/^\+?\d{10,15}$/.test(mobile)) {
    return res.status(400).json({ error: 'Invalid mobile number' });
  }
  if (date && isNaN(Date.parse(date))) {
    return res.status(400).json({ error: 'Invalid date format' });
  }
  if (title && (typeof title !== 'string' || title.trim().length < 2)) {
    return res.status(400).json({ error: 'Title must be a string with at least 2 characters' });
  }
  if (description && (typeof description !== 'string' || description.trim().length < 10)) {
    return res.status(400).json({ error: 'Description must be a string with at least 10 characters' });
  }
  if (price && (isNaN(price) || price <= 0)) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  if (validity && isNaN(Date.parse(validity))) {
    return res.status(400).json({ error: 'Invalid validity date format' });
  }
  if (message && (typeof message !== 'string' || message.trim().length < 10)) {
    return res.status(400).json({ error: 'Message must be a string with at least 10 characters' });
  }
  if (password && (typeof password !== 'string' || password.length < 8)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }
  next();
};

// Database Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// PayPal Configuration
const PAYPAL_API = process.env.NODE_ENV === 'production' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const paypalAuth = {
  auth: {
    username: process.env.PAYPAL_CLIENT_ID,
    password: process.env.PAYPAL_CLIENT_SECRET
  }
};

// Store OTPs temporarily (in-memory; use Redis in production)
const otpStore = new Map();

// Initialize Database
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        price INTEGER NOT NULL,
        image VARCHAR(255)
      );

      CREATE TABLE IF NOT EXISTS offers (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        validity DATE NOT NULL,
        image VARCHAR(255)
      );

      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        mobile VARCHAR(15) NOT NULL,
        date DATE NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id SERIAL PRIMARY KEY,
        email VARCHAR(100) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'admin'
      );
    `);

    // Seed initial data if empty
    const servicesCount = await pool.query('SELECT COUNT(*) FROM services');
    if (parseInt(servicesCount.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO services (name, description, price, image) VALUES
        ('Dental Implants', 'High-quality dental implants for a lasting smile.', 25000, 'https://via.placeholder.com/120'),
        ('Orthodontics', 'Braces and aligners for perfect teeth alignment.', 35000, 'https://via.placeholder.com/120'),
        ('Root Canal', 'Painless root canal treatments to save your teeth.', 8000, 'https://via.placeholder.com/120'),
        ('Smile Designing', 'Transform your smile with veneers and aligners.', 20000, 'https://via.placeholder.com/120');
      `);
    }

    const offersCount = await pool.query('SELECT COUNT(*) FROM offers');
    if (parseInt(offersCount.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO offers (title, description, validity, image) VALUES
        ('New Patient Discount', 'Get 20% off your first visit!', '2025-12-31', 'https://via.placeholder.com/150'),
        ('Family Package', '10% off for family treatments.', '2025-11-30', 'https://via.placeholder.com/150'),
        ('Smile Makeover Deal', 'Special offer on veneers and whitening.', '2025-10-31', 'https://via.placeholder.com/150');
      `);
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied: No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// API Endpoints

// Services
app.get('/api/v1/services', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM services ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Offers
app.get('/api/v1/offers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM offers ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching offers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Book Appointment
app.post('/api/v1/appointments/book', validateInput, async (req, res) => {
  const { name, email, mobile, date } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO appointments (name, email, mobile, date) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, email, mobile, date]
    );

    // Send confirmation email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OAK Dental Appointment Confirmation',
      html: `
        <h2>Appointment Confirmed</h2>
        <p>Dear ${name},</p>
        <p>Your appointment is scheduled for ${new Date(date).toLocaleDateString()}.</p>
        <p>Confirmation ID: ${result.rows[0].id}</p>
        <p>Thank you for choosing OAK Dental Clinic!</p>
      `
    });

    // Send SMS (optional, for Twilio or similar)
    if (process.env.SMS_API_KEY && process.env.SMS_API_URL) {
      await axios.post(process.env.SMS_API_URL, {
        to: mobile,
        message: `OAK Dental: Your appointment is confirmed for ${new Date(date).toLocaleDateString()}. ID: ${result.rows[0].id}`
      }, {
        headers: { 'Authorization': `Bearer ${process.env.SMS_API_KEY}` }
      });
    }

    res.json({ id: result.rows[0].id, message: 'Appointment booked successfully' });
  } catch (error) {
    console.error('Error booking appointment:', error);
    res.status(500).json({ error: 'Failed to book appointment' });
  }
});

// Check Appointment Status
app.post('/api/v1/appointments/status', validateInput, async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT id, date, status FROM appointments WHERE email = $1 ORDER BY created_at DESC LIMIT 1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No appointment found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error checking appointment status:', error);
    res.status(500).json({ error: 'Failed to check status' });
  }
});

// Contact Form
app.post('/api/v1/contact', validateInput, async (req, res) => {
  const { name, email, message } = req.body;
  try {
    await pool.query('INSERT INTO contacts (name, email, message) VALUES ($1, $2, $3)', [name, email, message]);

    // Send confirmation email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Thank You for Contacting OAK Dental',
      html: `
        <h2>Message Received</h2>
        <p>Dear ${name},</p>
        <p>Thank you for your message. Our team will get back to you soon.</p>
        <p>Your message: ${message}</p>
        <p>Best regards,<br>OAK Dental Clinic</p>
      `
    });

    res.json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error('Error sending contact message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Newsletter Subscription
app.post('/api/v1/newsletter/subscribe', validateInput, async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query('INSERT INTO newsletter_subscribers (email) VALUES ($1) ON CONFLICT (email) DO NOTHING', [email]);

    // Send welcome email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to OAK Dental Newsletter',
      html: `
        <h2>Welcome!</h2>
        <p>Thank you for subscribing to OAK Dental Clinic's newsletter.</p>
        <p>Stay tuned for updates, offers, and dental care tips!</p>
        <p>Best regards,<br>OAK Dental Clinic</p>
      `
    });

    res.json({ message: 'Subscribed successfully' });
  } catch (error) {
    console.error('Error subscribing to newsletter:', error);
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// PayPal Payment Creation
app.post('/api/v1/payments/create', validateInput, async (req, res) => {
  const { amount, description } = req.body;
  if (!amount || !description) {
    return res.status(400).json({ error: 'Amount and description are required' });
  }
  try {
    const response = await axios.post(`${PAYPAL_API}/v2/checkout/orders`, {
      intent: 'CAPTURE',
      purchase_units: [{
        amount: {
          currency_code: process.env.PAYPAL_CURRENCY || 'USD',
          value: amount.toString()
        },
        description
      }],
      application_context: {
        return_url: process.env.PAYPAL_RETURN_URL,
        cancel_url: process.env.PAYPAL_CANCEL_URL
      }
    }, paypalAuth);

    res.json(response.data);
  } catch (error) {
    console.error('Error creating PayPal payment:', error);
    res.status(500).json({ error: 'Failed to create payment' });
  }
});

// PayPal Payment Capture
app.post('/api/v1/payments/capture/:orderId', async (req, res) => {
  const { orderId } = req.params;
  if (!orderId) {
    return res.status(400).json({ error: 'Order ID is required' });
  }
  try {
    const response = await axios.post(`${PAYPAL_API}/v2/checkout/orders/${orderId}/capture`, {}, paypalAuth);
    res.json(response.data);
  } catch (error) {
    console.error('Error capturing PayPal payment:', error);
    res.status(500).json({ error: 'Failed to capture payment' });
  }
});

// Admin Register
app.post('/api/v1/admin/register', validateInput, async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
      [name, email, hashedPassword, 'admin']
    );
    res.json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Login
app.post('/api/v1/admin/login', validateInput, async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, name: user.name });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Request OTP for Password Reset
app.post('/api/v1/admin/request-otp', validateInput, async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 }); // 10 minutes

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OAK Dental Password Reset OTP',
      html: `
        <h2>Password Reset Request</h2>
        <p>Your OTP for password reset is: <strong>${otp}</strong></p>
        <p>This OTP is valid for 10 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
      `
    });

    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/v1/admin/verify-otp', validateInput, async (req, res) => {
  const { email, otp } = req.body;
  try {
    const stored = otpStore.get(email);
    if (!stored) {
      return res.status(400).json({ error: 'OTP not requested or expired' });
    }
    if (stored.expires < Date.now()) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'OTP expired' });
    }
    if (stored.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Reset Password
app.post('/api/v1/admin/reset-password', validateInput, async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!otpStore.has(email)) {
      return res.status(400).json({ error: 'OTP not verified' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    otpStore.delete(email);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Admin Dashboard Data (Protected)
app.get('/api/v1/admin/dashboard', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const services = await pool.query('SELECT * FROM services ORDER BY id');
    const offers = await pool.query('SELECT * FROM offers ORDER BY id');
    const appointments = await pool.query('SELECT * FROM appointments ORDER BY created_at DESC LIMIT 10');
    const contacts = await pool.query('SELECT * FROM contacts ORDER BY created_at DESC LIMIT 10');
    const subscribers = await pool.query('SELECT * FROM newsletter_subscribers ORDER BY created_at DESC LIMIT 10');
    res.json({
      services: services.rows,
      offers: offers.rows,
      appointments: appointments.rows,
      contacts: contacts.rows,
      subscribers: subscribers.rows
    });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: Manage Services (Protected)
app.post('/api/v1/services', authenticateToken, validateInput, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { name, description, price, image } = req.body;
  try {
    let imageUrl = image || 'https://via.placeholder.com/120';
    if (image && image.startsWith('data:image')) {
      const uploadResult = await cloudinary.uploader.upload(image, { folder: 'services' });
      imageUrl = uploadResult.secure_url;
    }
    const result = await pool.query(
      'INSERT INTO services (name, description, price, image) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, description, price, imageUrl]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding service:', error);
    res.status(500).json({ error: 'Failed to add service' });
  }
});

app.put('/api/v1/services/:id', authenticateToken, validateInput, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  const { name, description, price, image } = req.body;
  try {
    let imageUrl = image;
    if (image && image.startsWith('data:image')) {
      const uploadResult = await cloudinary.uploader.upload(image, { folder: 'services' });
      imageUrl = uploadResult.secure_url;
    }
    const result = await pool.query(
      'UPDATE services SET name = $1, description = $2, price = $3, image = $4 WHERE id = $5 RETURNING *',
      [name, description, price, imageUrl, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ error: 'Failed to update service' });
  }
});

app.delete('/api/v1/services/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM services WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }
    res.json({ message: 'Service deleted successfully' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ error: 'Failed to delete service' });
  }
});

// Admin: Manage Offers (Protected)
app.post('/api/v1/offers', authenticateToken, validateInput, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { title, description, validity, image } = req.body;
  try {
    let imageUrl = image || 'https://via.placeholder.com/150';
    if (image && image.startsWith('data:image')) {
      const uploadResult = await cloudinary.uploader.upload(image, { folder: 'offers' });
      imageUrl = uploadResult.secure_url;
    }
    const result = await pool.query(
      'INSERT INTO offers (title, description, validity, image) VALUES ($1, $2, $3, $4) RETURNING *',
      [title, description, validity, imageUrl]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding offer:', error);
    res.status(500).json({ error: 'Failed to add offer' });
  }
});

app.put('/api/v1/offers/:id', authenticateToken, validateInput, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  const { title, description, validity, image } = req.body;
  try {
    let imageUrl = image;
    if (image && image.startsWith('data:image')) {
      const uploadResult = await cloudinary.uploader.upload(image, { folder: 'offers' });
      imageUrl = uploadResult.secure_url;
    }
    const result = await pool.query(
      'UPDATE offers SET title = $1, description = $2, validity = $3, image = $4 WHERE id = $5 RETURNING *',
      [title, description, validity, imageUrl, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating offer:', error);
    res.status(500).json({ error: 'Failed to update offer' });
  }
});

app.delete('/api/v1/offers/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM offers WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    res.json({ message: 'Offer deleted successfully' });
  } catch (error) {
    console.error('Error deleting offer:', error);
    res.status(500).json({ error: 'Failed to delete offer' });
  }
});

// Admin: Manage Appointments (Protected)
app.put('/api/v1/appointments/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  const { status } = req.body;
  if (!['pending', 'confirmed', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const result = await pool.query(
      'UPDATE appointments SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating appointment:', error);
    res.status(500).json({ error: 'Failed to update appointment' });
  }
});

app.delete('/api/v1/appointments/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM appointments WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    res.json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ error: 'Failed to delete appointment' });
  }
});

// Serve Frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start Server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();