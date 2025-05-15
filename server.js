const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const paypal = require('@paypal/checkout-server-sdk');

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Log all requests for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// File Upload Setup
const uploadDir = path.join(__dirname, 'public', 'Uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// PostgreSQL Pool (Updated to use DATABASE_URL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// PayPal Setup (Sandbox environment for testing)
const environment = new paypal.core.SandboxEnvironment(
  process.env.PAYPAL_CLIENT_ID,
  process.env.PAYPAL_CLIENT_SECRET
);
const paypalClient = new paypal.core.PayPalHttpClient(environment);

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
        price DECIMAL(10,2) NOT NULL,
        date DATE NOT NULL,
        time TIME NOT NULL,
        status VARCHAR(20) NOT NULL,
        cancel_reason TEXT,
        reschedule_reason TEXT,
        admin_reason TEXT,
        approved BOOLEAN DEFAULT FALSE,
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
    // Initialize default timings if empty
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
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
}

// Middleware for Admin Authentication
const auth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Appointment Endpoints
app.post('/api/appointments', async (req, res) => {
  const { fullName, phone, treatment, price, date, time } = req.body;
  console.log('Booking request:', req.body);
  if (!fullName || !phone || !treatment || !price || !date || !time) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ message: 'Phone number must be 10 digits' });
  }
  if (fullName.trim().length < 2) {
    return res.status(400).json({ message: 'Full name must be at least 2 characters' });
  }
  if (isNaN(price) || price < 0) {
    return res.status(400).json({ message: 'Price must be a valid number' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO appointments (full_name, phone, treatment, price, date, time, status, approved) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [fullName.trim(), phone, treatment, price, date, time, 'Pending', false]
    );
    res.status(201).json({ message: 'Appointment booked successfully', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error booking appointment:', error);
    res.status(500).json({ message: 'Failed to book appointment' });
  }
});

app.put('/api/appointments/:id/payment', async (req, res) => {
  const { id } = req.params;
  const { payment_id } = req.body;
  try {
    const result = await pool.query(
      'UPDATE appointments SET payment_id = $1 WHERE id = $2 RETURNING *',
      [payment_id, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating payment:', error);
    res.status(500).json({ message: 'Failed to update payment', error: error.message });
  }
});

app.get('/api/appointments', async (req, res) => {
  const { phone } = req.query;
  if (phone) {
    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({ message: 'Phone number must be 10 digits' });
    }
    try {
      const result = await pool.query('SELECT * FROM appointments WHERE phone = $1 ORDER BY date, time', [phone]);
      res.json(result.rows);
    } catch (error) {
      console.error('Error fetching user appointments:', error);
      res.status(500).json({ message: 'Failed to fetch appointments' });
    }
  } else {
    try {
      await auth(req, res, async () => {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
      });
    } catch (error) {
      console.error('Error fetching all appointments:', error);
      res.status(500).json({ message: 'Failed to fetch appointments' });
    }
  }
});

app.post('/api/appointments/:id/cancel', async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  console.log('Cancel request:', { id, reason });
  if (!reason) return res.status(400).json({ message: 'Reason required' });

  try {
    const result = await pool.query(
      'UPDATE appointments SET status = $1, cancel_reason = $2 WHERE id = $3 RETURNING id, status',
      ['Cancelled', reason, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment cancelled successfully', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error cancelling appointment:', error);
    res.status(500).json({ message: 'Failed to cancel appointment' });
  }
});

app.post('/api/appointments/:id/reschedule', async (req, res) => {
  const { id } = req.params;
  const { date, time, reason } = req.body;
  console.log('Reschedule request:', { id, date, time, reason });
  if (!date || !time || !reason) return res.status(400).json({ message: 'Date, time, and reason required' });

  try {
    const result = await pool.query(
      'UPDATE appointments SET date = $1, time = $2, status = $3, reschedule_reason = $4 WHERE id = $5 RETURNING id, date, time, status',
      [date, time, 'Pending', reason, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment rescheduled successfully', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error rescheduling appointment:', error);
    res.status(500).json({ message: 'Failed to reschedule appointment' });
  }
});

app.post('/api/appointments/:id/approve', auth, async (req, res) => {
  const { id } = req.params;
  console.log('Approve request:', { id });
  try {
    const result = await pool.query(
      'UPDATE appointments SET status = $1, approved = $2 WHERE id = $3 RETURNING id, status, approved',
      ['Approved', true, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment approved successfully', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error approving appointment:', error);
    res.status(500).json({ message: 'Failed to approve appointment' });
  }
});

app.post('/api/appointments/:id/admin-cancel', auth, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  console.log('Admin cancel request:', { id, reason });
  if (!reason) return res.status(400).json({ message: 'Reason required' });

  try {
    const result = await pool.query(
      'UPDATE appointments SET status = $1, admin_reason = $2 WHERE id = $3 RETURNING id, status',
      ['Cancelled', reason, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment cancelled by admin successfully', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error cancelling appointment by admin:', error);
    res.status(500).json({ message: 'Failed to cancel appointment' });
  }
});

// Treatment Endpoints
app.get('/api/treatments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM treatments ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching treatments:', error);
    res.status(500).json({ message: 'Failed to fetch treatments' });
  }
});

app.post('/api/treatments', auth, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
  const { name, price } = req.body;
  console.log('Add treatment request:', { name, price, files: req.files });
  if (!name || !price) return res.status(400).json({ message: 'Name and price required' });
  if (isNaN(price) || price < 0) return res.status(400).json({ message: 'Price must be a valid number' });

  const imageUrl = req.files.image ? `/Uploads/${req.files.image[0].filename}` : null;
  const videoUrl = req.files.video ? `/Uploads/${req.files.video[0].filename}` : null;

  try {
    const result = await pool.query(
      'INSERT INTO treatments (name, price, image_url, video_url) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, price, imageUrl, videoUrl]
    );
    res.status(201).json({ message: 'Treatment added successfully', treatment: result.rows[0] });
  } catch (error) {
    console.error('Error adding treatment:', error);
    res.status(500).json({ message: 'Failed to add treatment' });
  }
});

app.put('/api/treatments/:id', auth, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  console.log('Update treatment request:', { id, name, price, files: req.files });
  if (!name || !price) return res.status(400).json({ message: 'Name and price required' });
  if (isNaN(price) || price < 0) return res.status(400).json({ message: 'Price must be a valid number' });

  try {
    const existing = await pool.query('SELECT * FROM treatments WHERE id = $1', [id]);
    if (existing.rowCount === 0) return res.status(404).json({ message: 'Treatment not found' });

    const imageUrl = req.files.image ? `/Uploads/${req.files.image[0].filename}` : existing.rows[0].image_url;
    const videoUrl = req.files.video ? `/Uploads/${req.files.video[0].filename}` : existing.rows[0].video_url;

    const result = await pool.query(
      'UPDATE treatments SET name = $1, price = $2, image_url = $3, video_url = $4 WHERE id = $5 RETURNING *',
      [name, price, imageUrl, videoUrl, id]
    );
    res.json({ message: 'Treatment updated successfully', treatment: result.rows[0] });
  } catch (error) {
    console.error('Error updating treatment:', error);
    res.status(500).json({ message: 'Failed to update treatment' });
  }
});

app.delete('/api/treatments/:id', auth, async (req, res) => {
  const { id } = req.params;
  console.log('Delete treatment request:', { id });
  try {
    const result = await pool.query('DELETE FROM treatments WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Treatment not found' });
    res.json({ message: 'Treatment deleted successfully' });
  } catch (error) {
    console.error('Error deleting treatment:', error);
    res.status(500).json({ message: 'Failed to delete treatment' });
  }
});

// Hospital Timings Endpoints
app.get('/api/timings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM hospital_timings ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching timings:', error);
    res.status(500).json({ message: 'Failed to fetch timings' });
  }
});

app.put('/api/timings/:day', auth, async (req, res) => {
  const { day } = req.params;
  const { open_time, close_time } = req.body;
  console.log('Update timing request:', { day, open_time, close_time });
  if (!open_time || !close_time) return res.status(400).json({ message: 'Open and close times required' });

  try {
    const result = await pool.query(
      'INSERT INTO hospital_timings (day, open_time, close_time) VALUES ($1, $2, $3) ON CONFLICT (day) DO UPDATE SET open_time = $2, close_time = $3 RETURNING *',
      [day, open_time, close_time]
    );
    res.json({ message: 'Timing updated successfully', timing: result.rows[0] });
  } catch (error) {
    console.error('Error updating timing:', error);
    res.status(500).json({ message: 'Failed to update timing' });
  }
});

// Admin Endpoints
app.post('/api/admin/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).json({ message: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: 'Invalid email format' });

  try {
    const existingAdmin = await pool.query('SELECT * FROM admins WHERE username = $1 OR email = $2', [username, email]);
    if (existingAdmin.rowCount > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO admins (username, password, email) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, hashedPassword, email]
    );
    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (error) {
    console.error('Error registering admin:', error);
    res.status(500).json({ message: 'Failed to register admin' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username and password required' });

  try {
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    const admin = result.rows[0];
    if (!admin) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Failed to login' });
  }
});

// Serve Frontend Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  const adminPath = path.join(__dirname, 'public', 'admin.html');
  if (fs.existsSync(adminPath)) {
    res.sendFile(adminPath);
  } else {
    res.status(404).json({ message: 'admin.html not found in public directory' });
  }
});

// Catch-all route for 404
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start server
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