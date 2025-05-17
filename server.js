const express = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// Environment Variables
require('dotenv').config();
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const SMS_API_KEY = process.env.SMS_API_KEY;
const SMS_API_URL = process.env.SMS_API_URL;
const NODE_ENV = process.env.NODE_ENV || 'development';

// PostgreSQL Pool
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test Database Connection
async function testDbConnection() {
    try {
        await pool.query('SELECT NOW()');
        console.log('Connected to PostgreSQL database');
    } catch (error) {
        console.error('Failed to connect to PostgreSQL:', error.message);
        throw error;
    }
}

// Database Initialization
async function initDb() {
    try {
        // Note: Not dropping tables to preserve existing schema
        // If schema reset is needed, manually drop tables via psql
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                phone VARCHAR(15) NOT NULL,
                treatment VARCHAR(50) NOT NULL,
                price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
                date DATE NOT NULL,
                time TIME NOT NULL,
                status VARCHAR(20) NOT NULL,
                approved BOOLEAN DEFAULT false,
                cancel_reason TEXT,
                reschedule_reason TEXT,
                admin_reason TEXT,
                payment_id VARCHAR(100)
            );
            CREATE TABLE IF NOT EXISTS waitlist (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                phone VARCHAR(20) NOT NULL,
                preferred_date VARCHAR(10) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                rating INTEGER NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                image VARCHAR(255),
                video VARCHAR(255)
            );
            CREATE TABLE IF NOT EXISTS leave_dates (
                date VARCHAR(10) PRIMARY KEY
            );
        `);
        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error.message);
        throw error;
    }
}

(async () => {
    try {
        await testDbConnection();
        await initDb();
    } catch (error) {
        console.error('Failed to initialize application:', error.message);
        process.exit(1);
    }
})();

// Nodemailer Transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
});

// Middleware to Verify JWT
const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        console.error('Token verification error:', error.message);
        res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

// Serve Static Files
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html at /
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve admin.html at /admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Email and SMS Notification Functions
async function sendEmail(to, subject, html) {
    try {
        await transporter.sendMail({
            from: `"Oak Dental Clinic" <${EMAIL_USER}>`,
            to,
            subject,
            html
        });
        console.log(`Email sent to ${to}`);
    } catch (error) {
        console.error('Error sending email:', error.message);
    }
}

async function sendSMS(to, body) {
    try {
        await axios.post(SMS_API_URL, {
            api_key: SMS_API_KEY,
            to,
            message: body
        });
        console.log(`SMS sent to ${to}`);
    } catch (error) {
        console.error('Error sending SMS:', error.message);
    }
}

async function getNextAvailableDate(currentDate) {
    const date = new Date(currentDate);
    let nextDate;
    do {
        date.setDate(date.getDate() + 1);
        nextDate = date.toISOString().split('T')[0];
        const result = await pool.query('SELECT 1 FROM leave_dates WHERE date = $1', [nextDate]);
        if (result.rows.length === 0) return nextDate;
    } while (true);
}

// Admin Authentication Endpoints
app.post('/api/admin/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        console.log('Register request:', { name, email, password: '[REDACTED]' });
        if (!name || !email || !password) {
            console.log('Registration failed: Missing fields');
            return res.status(400).json({ error: 'All fields (name, email, password) are required' });
        }

        const existingAdmin = await pool.query('SELECT 1 FROM admins WHERE email = $1', [email]);
        if (existingAdmin.rows.length > 0) {
            console.log(`Registration failed: Email already exists - ${email}`);
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO admins (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
            [name, email, hashedPassword]
        );
        const admin = result.rows[0];

        const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`Admin registered: ${email}`);
        res.status(201).json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        console.error('Error registering admin:', error.message, error.stack);
        if (error.code === '23505') {
            res.status(400).json({ error: 'Email or username already registered' });
        } else {
            res.status(500).json({ error: 'Internal server error during registration' });
        }
    }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login request:', { email, password: '[REDACTED]' });
        if (!email || !password) {
            console.log('Login failed: Missing fields');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        const admin = result.rows[0];

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            console.log(`Login failed: Invalid credentials for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`Admin logged in: ${email}`);
        res.json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        console.error('Error logging in:', error.message, error.stack);
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

// Public Endpoints
app.get('/api/services', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM services');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching services:', error.message);
        res.status(500).json({ error: 'Error fetching services' });
    }
});

app.get('/api/time-slots', (req, res) => {
    const timeSlots = ['10:00 AM', '11:00 AM', '2:00 PM', '3:00 PM'];
    res.json(timeSlots);
});

app.get('/api/leave-dates', async (req, res) => {
    try {
        const result = await pool.query('SELECT date FROM leave_dates');
        res.json(result.rows.map(row => row.date));
    } catch (error) {
        console.error('Error fetching leave dates:', error.message);
        res.status(500).json({ error: 'Error fetching leave dates' });
    }
});

app.get('/api/feedback', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching feedback:', error.message);
        res.status(500).json({ error: 'Error fetching feedback' });
    }
});

app.post('/api/feedback', async (req, res) => {
    try {
        const { name, email, rating, description } = req.body;
        if (!name || !email || !rating || !description) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        await pool.query(
            'INSERT INTO feedback (full_name, email, rating, description) VALUES ($1, $2, $3, $4)',
            [name, email, rating, description]
        );
        res.status(200).json({ message: 'Feedback submitted' });
    } catch (error) {
        console.error('Error submitting feedback:', error.message);
        res.status(500).json({ error: 'Error submitting feedback' });
    }
});

app.post('/api/appointments', async (req, res) => {
    try {
        const appointmentData = { ...req.body, id: Math.floor(Math.random() * 1000000) }; // Use random ID for integer
        console.log('Booking appointment:', appointmentData);
        if (!appointmentData.name || !appointmentData.phone || !appointmentData.treatment || !appointmentData.date || !appointmentData.time) {
            console.log('Appointment failed: Missing fields');
            return res.status(400).json({ error: 'All required fields (name, phone, treatment, date, time) must be provided' });
        }
        await pool.query(
            'INSERT INTO appointments (id, full_name, phone, treatment, date, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [
                appointmentData.id,
                appointmentData.name,
                appointmentData.phone,
                appointmentData.treatment || 'General Checkup',
                appointmentData.date,
                appointmentData.time,
                'CONFIRMED'
            ]
        );

        const baseUrl = NODE_ENV === 'production' ? 'https://oak-dental.onrender.com' : 'http://localhost:3000';
        const confirmationMessage = `
            <h2>Appointment Confirmed</h2>
            <p>Dear ${appointmentData.name},</p>
            <p>Your appointment is confirmed for ${appointmentData.date} at ${appointmentData.time}.</p>
            <p><a href="${baseUrl}/reschedule/${appointmentData.id}">Reschedule</a> | <a href="${baseUrl}/cancel/${appointmentData.id}">Cancel</a></p>
        `;
        await sendEmail(appointmentData.email || 'svasudevareddy18604@gmail.com', 'Appointment Confirmation - Oak Dental Clinic', confirmationMessage);
        // Comment out SMS due to missing API key
        // await sendSMS(appointmentData.phone, `Appointment confirmed for ${appointmentData.date} at ${appointmentData.time}. Reply RESCHEDULE or CANCEL to modify.`);

        const waitlistResult = await pool.query('SELECT * FROM waitlist WHERE preferred_date = $1', [appointmentData.date]);
        if (waitlistResult.rows.length > 0) {
            const nextAvailableDate = await getNextAvailableDate(appointmentData.date);
            for (const entry of waitlistResult.rows) {
                await sendEmail(entry.email, 'Slot Available - Oak Dental Clinic', `
                    <h2>Slot Available</h2>
                    <p>Dear ${entry.full_name},</p>
                    <p>A slot is available on ${nextAvailableDate}. Book now: <a href="${baseUrl}/#appointment">Book</a></p>
                `);
                // await sendSMS(entry.phone, `A slot is available on ${nextAvailableDate}. Book now at oakdental.com.`);
                await pool.query('DELETE FROM waitlist WHERE id = $1', [entry.id]);
            }
        }

        console.log(`Appointment booked: ${appointmentData.id}`);
        res.status(200).json({ message: 'Appointment booked' });
    } catch (error) {
        console.error('Error booking appointment:', error.message, error.stack);
        res.status(500).json({ error: 'Error booking appointment' });
    }
});

app.post('/api/waitlist', async (req, res) => {
    try {
        const { name, email, phone, preferredDate } = req.body;
        if (!name || !email || !phone || !preferredDate) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        await pool.query(
            'INSERT INTO waitlist (full_name, email, phone, preferred_date) VALUES ($1, $2, $3, $4)',
            [name, email, phone, preferredDate]
        );

        const baseUrl = NODE_ENV === 'production' ? 'https://oak-dental.onrender.com' : 'http://localhost:3000';
        await sendEmail(email, 'Waitlist Confirmation - Oak Dental Clinic', `
            <h2>Waitlist Confirmation</h2>
            <p>Dear ${name},</p>
            <p>You have been added to the waitlist for ${preferredDate}. We will notify you when a slot becomes available.</p>
        `);
        // await sendSMS(phone, `Added to waitlist for ${preferredDate}. We'll notify you when a slot is available.`);

        res.status(200).json({ message: 'Added to waitlist' });
    } catch (error) {
        console.error('Error joining waitlist:', error.message);
        res.status(500).json({ error: 'Error joining waitlist' });
    }
});

app.get('/api/appointments/status', async (req, res) => {
    try {
        const { identifier } = req.query;
        if (!identifier) {
            return res.status(400).json({ error: 'Identifier is required' });
        }
        const result = await pool.query(
            'SELECT * FROM appointments WHERE phone = $1 AND status IN ($2, $3)',
            [identifier, 'CONFIRMED', 'CANCELLED']
        );
        res.json({ appointment: result.rows[0] || null });
    } catch (error) {
        console.error('Error checking appointment status:', error.message);
        res.status(500).json({ error: 'Error checking appointment status' });
    }
});

app.post('/api/appointments/:id/cancel', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE appointments SET status = $1, cancel_reason = $2 WHERE id = $3 AND status = $4 RETURNING *',
            ['CANCELLED', 'Cancelled by user', id, 'CONFIRMED']
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found or already cancelled' });
        }

        const appointment = result.rows[0];
        const baseUrl = NODE_ENV === 'production' ? 'https://oak-dental.onrender.com' : 'http://localhost:3000';
        await sendEmail('svasudevareddy18604@gmail.com', 'Appointment Cancelled - Oak Dental Clinic', `
            <h2>Appointment Cancelled</h2>
            <p>Dear ${appointment.full_name},</p>
            <p>Your appointment on ${appointment.date} at ${appointment.time} has been cancelled.</p>
            <p>Book a new appointment: <a href="${baseUrl}/#appointment">Book</a></p>
        `);
        // await sendSMS(appointment.phone, `Your appointment on ${appointment.date} at ${appointment.time} has been cancelled. Book a new slot at oakdental.com.`);

        res.status(200).json({ message: 'Appointment cancelled' });
    } catch (error) {
        console.error('Error cancelling appointment:', error.message);
        res.status(500).json({ error: 'Error cancelling appointment' });
    }
});

// Admin Endpoints (Protected)
app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching appointments:', error.message);
        res.status(500).json({ error: 'Error fetching appointments' });
    }
});

app.post('/api/admin/appointments/:id/confirm', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE appointments SET status = $1, approved = $2 WHERE id = $3 RETURNING *',
            ['CONFIRMED', true, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const appointment = result.rows[0];
        await sendEmail('svasudevareddy18604@gmail.com', 'Appointment Confirmed - Oak Dental Clinic', `
            <h2>Appointment Confirmed</h2>
            <p>Dear ${appointment.full_name},</p>
            <p>Your appointment on ${appointment.date} at ${appointment.time} has been confirmed.</p>
        `);
        // await sendSMS(appointment.phone, `Your appointment on ${appointment.date} at ${appointment.time} is confirmed.`);

        res.json({ message: 'Appointment confirmed' });
    } catch (error) {
        console.error('Error confirming appointment:', error.message);
        res.status(500).json({ error: 'Error confirming appointment' });
    }
});

app.get('/api/admin/waitlist', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waitlist ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching waitlist:', error.message);
        res.status(500).json({ error: 'Error fetching waitlist' });
    }
});

app.delete('/api/admin/waitlist/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM waitlist WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Waitlist entry not found' });
        }
        res.json({ message: 'Waitlist entry deleted' });
    } catch (error) {
        console.error('Error deleting waitlist entry:', error.message);
        res.status(500).json({ error: 'Error deleting waitlist entry' });
    }
});

app.get('/api/admin/feedback', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching feedback:', error.message);
        res.status(500).json({ error: 'Error fetching feedback' });
    }
});

app.delete('/api/admin/feedback/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM feedback WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Feedback not found' });
        }
        res.json({ message: 'Feedback deleted' });
    } catch (error) {
        console.error('Error deleting feedback:', error.message);
        res.status(500).json({ error: 'Error deleting feedback' });
    }
});

app.post('/api/admin/services', authenticateAdmin, async (req, res) => {
    try {
        const { title, description, price, image, video } = req.body;
        if (!title || !description || !price) {
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }
        await pool.query(
            'INSERT INTO services (title, description, price, image, video) VALUES ($1, $2, $3, $4, $5)',
            [title, description, price, image || null, video || null]
        );
        res.status(201).json({ message: 'Service added' });
    } catch (error) {
        console.error('Error adding service:', error.message);
        res.status(500).json({ error: 'Error adding service' });
    }
});

app.put('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, price, image, video } = req.body;
        if (!title || !description || !price) {
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }
        const result = await pool.query(
            'UPDATE services SET title = $1, description = $2, price = $3, image = $4, video = $5 WHERE id = $6',
            [title, description, price, image || null, video || null, id]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Service not found' });
        }
        res.json({ message: 'Service updated' });
    } catch (error) {
        console.error('Error updating service:', error.message);
        res.status(500).json({ error: 'Error updating service' });
    }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM services WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Service not found' });
        }
        res.json({ message: 'Service deleted' });
    } catch (error) {
        console.error('Error deleting service:', error.message);
        res.status(500).json({ error: 'Error deleting service' });
    }
});

app.post('/api/admin/leave-dates', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.body;
        if (!date) {
            return res.status(400).json({ error: 'Date is required' });
        }
        await pool.query('INSERT INTO leave_dates (date) VALUES ($1) ON CONFLICT DO NOTHING', [date]);
        res.status(201).json({ message: 'Leave date added' });
    } catch (error) {
        console.error('Error adding leave date:', error.message);
        res.status(500).json({ error: 'Error adding leave date' });
    }
});

app.delete('/api/admin/leave-dates/:date', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.params;
        const result = await pool.query('DELETE FROM leave_dates WHERE date = $1', [date]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Leave date not found' });
        }
        res.json({ message: 'Leave date removed' });
    } catch (error) {
        console.error('Error removing leave date:', error.message);
        res.status(500).json({ error: 'Error removing leave date' });
    }
});

// Placeholder for Reschedule
app.get('/reschedule/:id', (req, res) => {
    const baseUrl = NODE_ENV === 'production' ? 'https://oak-dental.onrender.com' : 'http://localhost:3000';
    res.redirect(`${baseUrl}/#appointment`);
});

app.get('/cancel/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE appointments SET status = $1, cancel_reason = $2 WHERE id = $3 AND status = $4 RETURNING *',
            ['CANCELLED', 'Cancelled via link', id, 'CONFIRMED']
        );

        if (result.rows.length === 0) {
            return res.status(404).send('Appointment not found or already cancelled');
        }

        const appointment = result.rows[0];
        const baseUrl = NODE_ENV === 'production' ? 'https://oak-dental.onrender.com' : 'http://localhost:3000';
        await sendEmail('svasudevareddy18604@gmail.com', 'Appointment Cancelled - Oak Dental Clinic', `
            <h2>Appointment Cancelled</h2>
            <p>Dear ${appointment.full_name},</p>
            <p>Your appointment on ${appointment.date} at ${appointment.time} has been cancelled.</p>
            <p>Book a new appointment: <a href="${baseUrl}/#appointment">Book</a></p>
        `);
        // await sendSMS(appointment.phone, `Your appointment on ${appointment.date} at ${appointment.time} has been cancelled. Book a new slot at oakdental.com.`);

        res.redirect(`${baseUrl}/#appointment`);
    } catch (error) {
        console.error('Error cancelling appointment:', error.message);
        res.status(500).send('Error cancelling appointment');
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});