const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/Uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Initialize Database
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL
      );

      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        phone VARCHAR(15) NOT NULL,
        treatment VARCHAR(50) NOT NULL,
        price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
        date DATE NOT NULL,
        time TIME NOT NULL,
        status VARCHAR(20) NOT NULL,
        approved BOOLEAN DEFAULT FALSE,
        cancel_reason TEXT,
        reschedule_reason TEXT,
        admin_reason TEXT,
        payment_id VARCHAR(100)
      );

      CREATE TABLE IF NOT EXISTS treatments (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        image_url TEXT,
        video_url TEXT
      );

      CREATE TABLE IF NOT EXISTS hospital_timings (
        id SERIAL PRIMARY KEY,
        day VARCHAR(10) NOT NULL,
        open_time TIME NOT NULL,
        close_time TIME NOT NULL,
        UNIQUE(day)
      );
    `);

    // Initialize default timings
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    for (const day of days) {
      const result = await pool.query('SELECT 1 FROM hospital_timings WHERE day = $1', [day]);
      if (result.rowCount === 0) {
        await pool.query(
          'INSERT INTO hospital_timings (day, open_time, close_time) VALUES ($1, $2, $3)',
          [day, '09:00', '18:00']
        );
      }
    }
    console.log('Database initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  const adminPath = path.join(__dirname, 'public', 'admin.html');
  if (fs.existsSync(adminPath)) {
    res.sendFile(adminPath);
  } else {
    res.status(404).json({ message: 'admin.html not found' });
  }
});

// Admin Registration
app.post('/api/admin/register', async (req, res) => {
  const { username, password, email } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO admins (username, password, email) VALUES ($1, $2, $3)',
      [username, hashedPassword, email]
    );
    res.status(201).json({ message: 'Admin registered' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering admin', error });
  }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    const admin = result.rows[0];
    if (admin && await bcrypt.compare(password, admin.password)) {
      const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(400).json({ message: 'Error logging in', error });
  }
});

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.adminId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Book Appointment
app.post('/api/appointments', async (req, res) => {
  const { fullName, phone, treatment, price, date, time } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO appointments (full_name, phone, treatment, price, date, time, status, approved) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [fullName.trim(), phone, treatment, price, date, time, 'Pending', false]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error booking appointment', error });
  }
});

// Approve Appointment
app.put('/api/appointments/:id/approve', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE appointments SET status = $1, approved = $2 WHERE id = $3', ['Approved', true, id]);
    res.json({ message: 'Appointment approved' });
  } catch (error) {
    res.status(400).json({ message: 'Error approving appointment', error });
  }
});

// Get All Appointments
app.get('/api/appointments', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ message: 'Error fetching appointments', error });
  }
});

// Add Treatment
app.post('/api/treatments', authenticate, upload.fields([{ name: 'image' }, { name: 'video' }]), async (req, res) => {
  const { name, price } = req.body;
  const image = req.files.image ? `/Uploads/${req.files.image[0].filename}` : null;
  const video = req.files.video ? `/Uploads/${req.files.video[0].filename}` : null;
  try {
    const result = await pool.query(
      'INSERT INTO treatments (name, price, image_url, video_url) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, price, image, video]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error adding treatment', error });
  }
});

// Get All Treatments
app.get('/api/treatments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM treatments');
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ message: 'Error fetching treatments', error });
  }
});

// Update Hospital Timings
app.put('/api/timings/:day', authenticate, async (req, res) => {
  const { day } = req.params;
  const { open_time, close_time } = req.body;
  try {
    await pool.query(
      'UPDATE hospital_timings SET open_time = $1, close_time = $2 WHERE day = $3',
      [open_time, close_time, day]
    );
    res.json({ message: 'Timings updated' });
  } catch (error) {
    res.status(400).json({ message: 'Error updating timings', error });
  }
});

// Get Hospital Timings
app.get('/api/timings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM hospital_timings ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ message: 'Error fetching timings', error });
  }
});

// Razorpay Payment
app.post('/api/payment', async (req, res) => {
  const { amount } = req.body;
  try {
    const order = await razorpay.orders.create({
      amount: amount * 100, // Convert to paise
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
    });
    res.json(order);
  } catch (error) {
    res.status(400).json({ message: 'Error creating payment', error });
  }
});

// Start Server
async function startServer() {
  try {
    await initializeDatabase();
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`🚀 Server running on http://0.0.0.0:${port}`));
  } catch (error) {
    console.error('Error starting server:', error);
    process.exit(1);
  }
}

startServer();
