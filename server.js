const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Environment Variables
const {
  DATABASE_URL,
  PORT = 3000,
  JWT_SECRET,
  NODE_ENV,
  EMAIL_USER,
  EMAIL_PASS,
  SMS_API_KEY,
  SMS_API_URL,
  CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET,
} = process.env;

// Database Connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Log Database Connection
pool.on('connect', () => {
  console.log(`Connected to database: ${DATABASE_URL}`);
});

// Initialize Database
async function initializeDatabase() {
  try {
    // Create admins table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Verify admins table schema
    const adminColumns = await pool.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'admins' AND column_name = 'name';
    `);
    if (adminColumns.rows.length === 0) {
      console.log('Adding missing name column to admins table');
      await pool.query('ALTER TABLE admins ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT \'Unknown\'');
      console.log('Successfully added name column to admins');
    }

    // Create appointments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255),
        phone VARCHAR(20),
        date VARCHAR(50),
        message TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Verify appointments table schema
    const appointmentColumns = await pool.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'appointments';
    `);
    const hasStatus = appointmentColumns.rows.some(col => col.column_name === 'status');
    const hasReason = appointmentColumns.rows.some(col => col.column_name === 'reason');
    if (!hasStatus) {
      console.log('Adding missing status column to appointments table');
      await pool.query('ALTER TABLE appointments ADD COLUMN status VARCHAR(20) DEFAULT \'pending\'');
      console.log('Successfully added status column to appointments');
    }
    if (!hasReason) {
      console.log('Adding missing reason column to appointments table');
      await pool.query('ALTER TABLE appointments ADD COLUMN reason TEXT');
      console.log('Successfully added reason column to appointments');
    }
    // Ensure existing appointments have status
    await pool.query('UPDATE appointments SET status = \'pending\' WHERE status IS NULL');

    // Create messages table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Verify messages table schema
    const messageColumns = await pool.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'messages' AND column_name = 'full_name';
    `);
    if (messageColumns.rows.length === 0) {
      console.log('Adding missing full_name column to messages table');
      await pool.query('ALTER TABLE messages ADD COLUMN full_name VARCHAR(255) NOT NULL DEFAULT \'Anonymous\'');
      console.log('Successfully added full_name column to messages');
    }

    // Create subscribers table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscribers (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        subscribed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Verify subscribers table schema
    const subscriberColumns = await pool.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'subscribers' AND column_name = 'subscribed_on';
    `);
    if (subscriberColumns.rows.length === 0) {
      console.log('Adding missing subscribed_on column to subscribers table');
      await pool.query('ALTER TABLE subscribers ADD COLUMN subscribed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
      console.log('Successfully added subscribed_on column to subscribers');
    }

    // Create otps table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      );
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// Test Email Configuration
async function testEmailConfig() {
  try {
    await transporter.verify();
    console.log('Email configuration verified successfully');
  } catch (error) {
    console.error('Email configuration error:', error);
  }
}

// Placeholder SMS Function
async function sendSMS(phone, message) {
  if (SMS_API_KEY && SMS_API_URL) {
    console.log(`SMS would be sent to ${phone}: ${message}`);
    // Implement SMS API call here (e.g., Twilio)
    return { success: true };
  } else {
    console.log(`SMS not configured. Would send to ${phone}: ${message}`);
    return { success: false, message: 'SMS service not configured' };
  }
}

// Middleware to Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Admin Register
app.post('/api/admin/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO admins (name, email, password) VALUES ($1, $2, $3)',
      [name, email, hashedPassword]
    );
    res.json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    const admin = rows[0];
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: admin.id, email: admin.email, name: admin.name }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, name: admin.name });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin Profile
app.get('/api/admin/profile', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT name FROM admins WHERE id = $1', [req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    res.json({ name: rows[0].name });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Send OTP
app.post('/api/admin/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );
    await transporter.sendMail({
      from: `"OAK Dental Clinic" <${EMAIL_USER}>`,
      to: email,
      subject: 'Your OTP for Password Reset',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0D9488;">OAK Dental Clinic</h2>
          <p>Your OTP for password reset is <strong>${otp}</strong>.</p>
          <p>This OTP is valid for 5 minutes.</p>
          <p>If you did not request this, please ignore this email.</p>
          <p style="color: #6B7280;">© 2025 OAK Dental Clinic. All rights reserved.</p>
        </div>
      `,
    });
    // Placeholder for SMS
    await sendSMS(rows[0].phone, `Your OAK Dental OTP is ${otp}. Valid for 5 minutes.`);
    res.json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/admin/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    const { rows } = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    res.json({ message: 'OTP verified' });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// Reset Password
app.post('/api/admin/reset-password', async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE admins SET password = $1 WHERE email = $2', [hashedPassword, email]);
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// Appointment Action (Accept/Cancel)
app.post('/api/admin/appointment/action', authenticateToken, async (req, res) => {
  try {
    const { id, action, reason } = req.body;
    if (!id || !action || (action === 'cancel' && !reason)) {
      return res.status(400).json({ error: 'ID, action, and reason (for cancel) are required' });
    }
    if (!['accept', 'cancel'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const { rows } = await pool.query('SELECT * FROM appointments WHERE id = $1', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    const appointment = rows[0];
    const status = action === 'accept' ? 'accepted' : 'cancelled';
    await pool.query(
      'UPDATE appointments SET status = $1, reason = $2 WHERE id = $3',
      [status, action === 'cancel' ? reason : null, id]
    );
    // Send Email
    const subject = `OAK Dental Clinic - Appointment ${status.charAt(0).toUpperCase() + status.slice(1)}`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0D9488;">OAK Dental Clinic</h2>
        <p>Dear ${appointment.name || 'Customer'},</p>
        <p>Your appointment has been <strong>${status}</strong>.</p>
        <h3>Appointment Details:</h3>
        <ul>
          <li><strong>Date:</strong> ${appointment.date}</li>
          <li><strong>Email:</strong> ${appointment.email}</li>
          <li><strong>Phone:</strong> ${appointment.phone}</li>
          <li><strong>Message:</strong> ${appointment.message || 'N/A'}</li>
          ${action === 'cancel' ? `<li><strong>Reason for Cancellation:</strong> ${reason}</li>` : ''}
        </ul>
        <p>${action === 'accept' ? 'We look forward to seeing you!' : 'Please contact us to reschedule if needed.'}</p>
        <p style="color: #6B7280;">© 2025 OAK Dental Clinic. All rights reserved.</p>
      </div>
    `;
    await transporter.sendMail({
      from: `"OAK Dental Clinic" <${EMAIL_USER}>`,
      to: appointment.email,
      subject,
      html,
    });
    // Send SMS
    const smsMessage = `OAK Dental Clinic: Your appointment on ${appointment.date} has been ${status}. ${action === 'cancel' ? `Reason: ${reason}` : 'We look forward to seeing you!'}`;
    await sendSMS(appointment.phone, smsMessage);
    res.json({ message: `Appointment ${status} successfully` });
  } catch (error) {
    console.error('Appointment action error:', error);
    res.status(500).json({ error: 'Failed to process appointment action' });
  }
});

// Message Reply
app.post('/api/admin/message/reply', authenticateToken, async (req, res) => {
  try {
    const { id, reply } = req.body;
    if (!id || !reply) {
      return res.status(400).json({ error: 'ID and reply are required' });
    }
    const { rows } = await pool.query('SELECT * FROM messages WHERE id = $1', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    const message = rows[0];
    await transporter.sendMail({
      from: `"OAK Dental Clinic" <${EMAIL_USER}>`,
      to: message.email,
      subject: 'Response from OAK Dental Clinic',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0D9488;">OAK Dental Clinic</h2>
          <p>Dear ${message.full_name || 'Customer'},</p>
          <p>Thank you for your message. Our response is below:</p>
          <blockquote style="border-left: 4px solid #0D9488; padding-left: 10px; margin: 10px 0;">
            ${reply}
          </blockquote>
          <h3>Your Original Message:</h3>
          <p>${message.message}</p>
          <p>We value your feedback and look forward to assisting you further.</p>
          <p style="color: #6B7280;">© 2025 OAK Dental Clinic. All rights reserved.</p>
        </div>
      `,
    });
    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('Message reply error:', error);
    res.status(500).json({ error: 'Failed to send reply: ' + error.message });
  }
});

// Admin Endpoints (Protected)
app.get('/api/admin/appointments', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM appointments ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

app.get('/api/admin/messages', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/admin/subscribers', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM subscribers ORDER BY subscribed_on DESC');
    res.json(rows);
  } catch (error) {
    console.error('Get subscribers error:', error);
    res.status(500).json({ error: 'Failed to fetch subscribers' });
  }
});

// Public Endpoints
app.post('/api/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, message } = req.body;
    await pool.query(
      'INSERT INTO appointments (name, email, phone, date, message, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [name, email, phone, date, message, 'pending']
    );
    res.json({ message: 'Appointment submitted successfully' });
  } catch (error) {
    console.error('Submit appointment error:', error);
    res.status(500).json({ error: 'Failed to submit appointment' });
  }
});

app.post('/api/messages', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!email || !message) {
      return res.status(400).json({ error: 'Email and message are required' });
    }
    await pool.query(
      'INSERT INTO messages (full_name, email, message) VALUES ($1, $2, $3)',
      [name || 'Anonymous', email, message]
    );
    res.json({ message: 'Message submitted successfully' });
  } catch (error) {
    console.error('Submit message error:', error);
    res.status(500).json({ error: 'Failed to submit message: ' + error.message });
  }
});

app.post('/api/subscribers', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    await pool.query('INSERT INTO subscribers (email) VALUES ($1) ON CONFLICT (email) DO NOTHING', [email]);
    res.json({ message: 'Subscription successful' });
  } catch (error) {
    console.error('Submit subscriber error:', error);
    res.status(500).json({ error: 'Failed to submit subscription' });
  }
});

// Serve Admin Dashboard
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Fallback to serve index.html for unmatched routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
async function startServer() {
  await initializeDatabase();
  await testEmailConfig();
  app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
}

startServer();