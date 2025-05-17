const express = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs').promises;

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
        // Create tables
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

        // Check if full_name column exists in feedback table
        const fullNameCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'full_name'
        `);

        if (fullNameCheck.rows.length === 0) {
            console.log('Adding full_name column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN full_name VARCHAR(255);
                
                -- Set default for existing rows
                UPDATE feedback
                SET full_name = 'Unknown'
                WHERE full_name IS NULL;
                
                ALTER TABLE feedback
                ALTER COLUMN full_name SET NOT NULL;
            `);
        }

        // Check if email column exists in feedback table
        const emailCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'email'
        `);

        if (emailCheck.rows.length === 0) {
            console.log('Adding email column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN email VARCHAR(255);
                
                -- Set default for existing rows
                UPDATE feedback
                SET email = 'unknown@example.com'
                WHERE email IS NULL;
                
                ALTER TABLE feedback
                ALTER COLUMN email SET NOT NULL;
            `);
        }

        // Check if description column exists in feedback table
        const descriptionCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'description'
        `);

        if (descriptionCheck.rows.length === 0) {
            console.log('Adding description column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN description TEXT;
                
                -- Set default for existing rows
                UPDATE feedback
                SET description = ''
                WHERE description IS NULL;
                
                ALTER TABLE feedback
                ALTER COLUMN description SET NOT NULL;
            `);
        }

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

// Multer Configuration for File Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'Uploads/');
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${uuidv4()}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif'];
        const allowedVideoTypes = ['video/mp4', 'video/mpeg'];
        if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
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
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

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
        console.error('Error logging in admin:', error.message);
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

// Appointment Endpoints
app.get('/api/time-slots', async (req, res) => {
    try {
        const timeSlots = [
            '10:00 AM', '10:30 AM', '11:00 AM', '11:30 AM',
            '12:00 PM', '12:30 PM', '01:00 PM', '01:30 PM',
            '02:00 PM', '02:30 PM', '03:00 PM', '03:30 PM',
            '04:00 PM', '04:30 PM', '05:00 PM', '05:30 PM',
            '06:00 PM', '06:30 PM', '07:00 PM', '07:30 PM'
        ];
        res.json(timeSlots);
    } catch (error) {
        console.error('Error fetching time slots:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/leave-dates', async (req, res) => {
    try {
        const result = await pool.query('SELECT date FROM leave_dates');
        const leaveDates = result.rows.map(row => row.date);
        res.json(leaveDates);
    } catch (error) {
        console.error('Error fetching leave dates:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/appointments', async (req, res) => {
    try {
        const { id, full_name, email, phone, date, time, message } = req.body;
        if (!id || !full_name || !email || !phone || !date || !time || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const treatment = message.substring(0, 50);
        const status = 'PENDING';

        await pool.query(
            'INSERT INTO appointments (id, full_name, phone, treatment, price, date, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [id, full_name, phone, treatment, 0.00, date, time, status]
        );

        await sendEmail(
            email,
            'Appointment Confirmation - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment has been booked for ${date} at ${time}.</p>
             <p>Treatment: ${treatment}</p>
             <p>We will send a confirmation once approved. For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment at Oak Dental Clinic is booked for ${date} at ${time}. Awaiting approval. Contact: +91756936767`
        );

        res.status(201).json({ message: 'Appointment booked successfully' });
    } catch (error) {
        console.error('Error booking appointment:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/appointments/status', async (req, res) => {
    try {
        const { identifier } = req.query.identifier;
        if (!identifier) {
            return res.status(400).json({ error: 'Identifier is required' });
        }

        const result = await pool.query(
            'SELECT id, full_name, date, time, status FROM appointments WHERE phone = $1 OR email = $1',
            [identifier]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'No appointment found' });
        }

        res.json({ appointment: result.rows[0] });
    } catch (error) {
        console.error('Error checking appointment status:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/appointments/:id/cancel', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE appointments SET status = $1, cancel_reason = $2 WHERE id = $3 RETURNING full_name, email, phone, date, time',
            ['CANCELLED', 'Cancelled by patient', id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const { full_name, email, phone, date, time } = result.rows[0];

        await sendEmail(
            email,
            'Appointment Cancelled - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment on ${date} at ${time} has been cancelled.</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment on ${date} at ${time} at Oak Dental Clinic has been cancelled. Contact: +91756936767`
        );

        res.json({ message: 'Appointment cancelled successfully' });
    } catch (error) {
        console.error('Error cancelling appointment:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Waitlist Endpoints
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

        await sendEmail(
            email,
            'Waitlist Confirmation - Oak Dental Clinic',
            `<p>Dear ${name},</p>
             <p>You have been added to the waitlist for ${preferredDate}.</p>
             <p>We will notify you when a slot becomes available. For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${name}, you are on the waitlist for ${preferredDate} at Oak Dental Clinic. We will notify you when a slot is available. Contact: +91756936767`
        );

        res.status(201).json({ message: 'Added to waitlist successfully' });
    } catch (error) {
        console.error('Error joining waitlist:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Feedback Endpoints
app.post('/api/feedback', async (req, res) => {
    try {
        const { full_name, email, rating, description } = req.body;
        if (!full_name || !email || !rating || !description) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        await pool.query(
            'INSERT INTO feedback (full_name, email, rating, description) VALUES ($1, $2, $3, $4)',
            [full_name, email, rating, description]
        );

        await sendEmail(
            email,
            'Thank You for Your Feedback - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Thank you for your feedback. We value your input and will use it to improve our services.</p>
             <p>Rating: ${rating}/5</p>
             <p>Feedback: ${description}</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        res.status(201).json({ message: 'Feedback submitted successfully' });
    } catch (error) {
        console.error('Error submitting feedback:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/feedback', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, full_name, email, rating, description, created_at FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching feedback:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Service Endpoints
app.get('/api/services', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, price, image, video FROM services');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching services:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/services', authenticateAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    try {
        const { title, description, price } = req.body;
        if (!title || !description || !price) {
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        const imageFile = req.files.image ? req.files.image[0].filename : null;
        const videoFile = req.files.video ? req.files.video[0].filename : null;

        const result = await pool.query(
            'INSERT INTO services (title, description, price, image, video) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [title, description, parseFloat(price), imageFile, videoFile]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error adding service:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/services/:id', authenticateAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, price } = req.body;
        if (!title || !description || !price) {
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        const existingService = await pool.query('SELECT image, video FROM services WHERE id = $1', [id]);
        if (existingService.rows.length === 0) {
            return res.status(404).json({ error: 'Service not found' });
        }

        const imageFile = req.files.image ? req.files.image[0].filename : existingService.rows[0].image;
        const videoFile = req.files.video ? req.files.video[0].filename : existingService.rows[0].video;

        const result = await pool.query(
            'UPDATE services SET title = $1, description = $2, price = $3, image = $4, video = $5 WHERE id = $6 RETURNING *',
            [title, description, parseFloat(price), imageFile, videoFile, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Service not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating service:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const service = await pool.query('SELECT image, video FROM services WHERE id = $1', [id]);
        if (service.rows.length === 0) {
            return res.status(404).json({ error: 'Service not found' });
        }

        const { image, video } = service.rows[0];
        if (image) {
            await fs.unlink(path.join(__dirname, 'Uploads', image)).catch(err => console.error('Error deleting image:', err.message));
        }
        if (video) {
            await fs.unlink(path.join(__dirname, 'Uploads', video)).catch(err => console.error('Error deleting video:', err.message));
        }

        await pool.query('DELETE FROM services WHERE id = $1', [id]);
        res.json({ message: 'Service deleted successfully' });
    } catch (error) {
        console.error('Error deleting service:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Management Endpoints
app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching appointments:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/waitlist', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waitlist ORDER BY created_at');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching waitlist:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/feedback', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching feedback:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/:id/approve', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE appointments SET status = $1, approved = $2 WHERE id = $3 RETURNING full_name, email, phone, date, time',
            ['APPROVED', true, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const { full_name, email, phone, date, time } = result.rows[0];

        await sendEmail(
            email,
            'Appointment Approved - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment on ${date} at ${time} has been approved.</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment on ${date} at ${time} at Oak Dental Clinic has been approved. Contact: +91756936767`
        );

        res.json({ message: 'Appointment approved successfully' });
    } catch (error) {
        console.error('Error approving appointment:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/:id/reschedule', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { newDate, newTime, reason } = req.body;
        if (!newDate || !newTime || !reason) {
            return res.status(400).json({ error: 'New date, time, and reason are required' });
        }

        const result = await pool.query(
            'UPDATE appointments SET date = $1, time = $2, status = $3, reschedule_reason = $4 WHERE id = $5 RETURNING full_name, email, phone',
            [newDate, newTime, 'RESCHEDULED', reason, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const { full_name, email, phone } = result.rows[0];

        await sendEmail(
            email,
            'Appointment Rescheduled - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment has been rescheduled to ${newDate} at ${newTime}.</p>
             <p>Reason: ${reason}</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment at Oak Dental Clinic has been rescheduled to ${newDate} at ${newTime}. Reason: ${reason}. Contact: +91756936767`
        );

        res.json({ message: 'Appointment rescheduled successfully' });
    } catch (error) {
        console.error('Error rescheduling appointment:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/:id/cancel', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        if (!reason) {
            return res.status(400).json({ error: 'Cancellation reason is required' });
        }

        const result = await pool.query(
            'UPDATE appointments SET status = $1, admin_reason = $2 WHERE id = $3 RETURNING full_name, email, phone, date, time',
            ['CANCELLED', reason, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const { full_name, email, phone, date, time } = result.rows[0];

        await sendEmail(
            email,
            'Appointment Cancelled - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment on ${date} at ${time} has been cancelled.</p>
             <p>Reason: ${reason}</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment on ${date} at ${time} at Oak Dental Clinic has been cancelled. Reason: ${reason}. Contact: +91756936767`
        );

        res.json({ message: 'Appointment cancelled successfully' });
    } catch (error) {
        console.error('Error cancelling appointment:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/leave-dates', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.body;
        if (!date) {
            return res.status(400).json({ error: 'Date is required' });
        }

        await pool.query('INSERT INTO leave_dates (date) VALUES ($1) ON CONFLICT (date) DO NOTHING', [date]);
        res.status(201).json({ message: 'Leave date added successfully' });
    } catch (error) {
        console.error('Error adding leave date:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/leave-dates/:date', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.params;
        const result = await pool.query('DELETE FROM leave_dates WHERE date = $1', [date]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Leave date not found' });
        }

        res.json({ message: 'Leave date removed successfully' });
    } catch (error) {
        console.error('Error removing leave date:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});