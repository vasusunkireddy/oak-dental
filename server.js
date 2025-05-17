const express = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const multer = require('multer');
const winston = require('winston');
const cloudinary = require('cloudinary').v2;

const app = express();
app.use(cors());

// Initialize Winston Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// Log request bodies for debugging
app.use(express.json(), (req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT') {
        logger.info(`Request to ${req.method} ${req.url} with body:`, { body: req.body });
    }
    next();
});

// Check for empty JSON body
app.use((req, res, next) => {
    if (req.method === 'POST' && req.headers['content-type'] === 'application/json' && !req.headers['content-length']) {
        logger.warn('Request body is missing');
        return res.status(400).json({ error: 'Request body is missing' });
    }
    next();
});

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
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// Validate Environment Variables
const requiredEnvVars = [
    'DATABASE_URL', 'EMAIL_USER', 'EMAIL_PASS', 'SMS_API_KEY', 'SMS_API_URL',
    'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'
];
requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
        logger.error(`Missing environment variable: ${varName}`);
        process.exit(1);
    }
});

// Configure Cloudinary
cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET
});

// PostgreSQL Pool
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test Database Connection
async function testDbConnection() {
    try {
        await pool.query('SELECT NOW()');
        logger.info('Connected to PostgreSQL database');
    } catch (error) {
        logger.error('Failed to connect to PostgreSQL:', { message: error.message });
        throw error;
    }
}

// Database Initialization
async function initDb() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS appointments (
                id BIGINT PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL,
                phone VARCHAR(15) NOT NULL,
                treatment VARCHAR(50),
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'PENDING'
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
                image TEXT,
                video TEXT
            );
            CREATE TABLE IF NOT EXISTS offers (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                image TEXT,
                video TEXT,
                media_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS leave_dates (
                date VARCHAR(10) PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS newsletter_subscribers (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Ensure full_name column exists in feedback table
        const fullNameCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'full_name'
        `);
        if (fullNameCheck.rows.length === 0) {
            logger.info('Adding full_name column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN full_name VARCHAR(255);
                UPDATE feedback
                SET full_name = 'Unknown'
                WHERE full_name IS NULL;
                ALTER TABLE feedback
                ALTER COLUMN full_name SET NOT NULL;
            `);
        }

        // Ensure email column exists in feedback table
        const emailCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'email'
        `);
        if (emailCheck.rows.length === 0) {
            logger.info('Adding email column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN email VARCHAR(255);
                UPDATE feedback
                SET email = 'unknown@example.com'
                WHERE email IS NULL;
                ALTER TABLE feedback
                ALTER COLUMN email SET NOT NULL;
            `);
        }

        // Ensure description column exists in feedback table
        const descriptionCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feedback' AND column_name = 'description'
        `);
        if (descriptionCheck.rows.length === 0) {
            logger.info('Adding description column to feedback table');
            await pool.query(`
                ALTER TABLE feedback
                ADD COLUMN description TEXT;
                UPDATE feedback
                SET description = ''
                WHERE description IS NULL;
                ALTER TABLE feedback
                ALTER COLUMN description SET NOT NULL;
            `);
        }

        // Ensure email column exists in appointments table
        const emailColumnCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'appointments' AND column_name = 'email'
        `);
        if (emailColumnCheck.rows.length === 0) {
            logger.info('Adding email column to appointments table');
            await pool.query(`
                ALTER TABLE appointments
                ADD COLUMN email VARCHAR(100);
                UPDATE appointments
                SET email = 'unknown@example.com'
                WHERE email IS NULL;
                ALTER TABLE appointments
                ALTER COLUMN email SET NOT NULL;
            `);
        }

        // Ensure id in appointments table is BIGINT
        const idTypeCheck = await pool.query(`
            SELECT data_type 
            FROM information_schema.columns 
            WHERE table_name = 'appointments' AND column_name = 'id'
        `);
        if (idTypeCheck.rows.length > 0 && idTypeCheck.rows[0].data_type === 'integer') {
            logger.info('Converting appointments.id from INTEGER to BIGINT');
            await pool.query(`
                ALTER TABLE appointments
                ALTER COLUMN id TYPE BIGINT;
            `);
        }

        // Ensure price column exists in offers table
        const priceCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'offers' AND column_name = 'price'
        `);
        if (priceCheck.rows.length === 0) {
            logger.info('Adding price column to offers table');
            await pool.query(`
                ALTER TABLE offers
                ADD COLUMN price DECIMAL(10,2) NOT NULL DEFAULT 0.00;
            `);
        }

        // Ensure media_url column exists in offers table
        const mediaUrlCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'offers' AND column_name = 'media_url'
        `);
        if (mediaUrlCheck.rows.length === 0) {
            logger.info('Adding media_url column to offers table');
            await pool.query(`
                ALTER TABLE offers
                ADD COLUMN media_url TEXT;
            `);
        }

        // Ensure video column exists in offers table
        const videoCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'offers' AND column_name = 'video'
        `);
        if (videoCheck.rows.length === 0) {
            logger.info('Adding video column to offers table');
            await pool.query(`
                ALTER TABLE offers
                ADD COLUMN video TEXT;
            `);
        }

        // Ensure created_at column exists in offers table
        const createdAtCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'offers' AND column_name = 'created_at'
        `);
        if (createdAtCheck.rows.length === 0) {
            logger.info('Adding created_at column to offers table');
            await pool.query(`
                ALTER TABLE offers
                ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            `);
        }

        // Ensure status column exists in waitlist table
        const statusCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'waitlist' AND column_name = 'status'
        `);
        if (statusCheck.rows.length === 0) {
            logger.info('Adding status column to waitlist table');
            await pool.query(`
                ALTER TABLE waitlist
                ADD COLUMN status VARCHAR(20) DEFAULT 'PENDING';
            `);
        }

        logger.info('Database tables initialized successfully');
    } catch (error) {
        logger.error('Error initializing database:', { message: error.message });
        throw error;
    }
}

(async () => {
    try {
        await testDbConnection();
        await initDb();
    } catch (error) {
        logger.error('Failed to initialize application:', { message: error.message });
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

// Multer Configuration for File Uploads (In-Memory Storage)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif'];
        const allowedVideoTypes = ['video/mp4', 'video/mpeg'];
        if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, GIF, MP4, and MPEG files are allowed.'));
        }
    }
});

// Middleware to Verify JWT
const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        logger.warn('Authentication failed: No token provided');
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        logger.error('Token verification error:', { message: error.message });
        res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

// Serve Static Files (Only for frontend build, if applicable)
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
        logger.info(`Email sent to ${to}`);
    } catch (error) {
        logger.error('Error sending email:', { message: error.message });
    }
}

async function sendSMS(to, body) {
    try {
        if (!SMS_API_URL) {
            throw new Error('SMS_API_URL is not defined in environment variables');
        }
        const urlPattern = /^https?:\/\/[^\s/$.?#].[^\s]*$/;
        if (!urlPattern.test(SMS_API_URL)) {
            logger.warn(`Skipping SMS due to invalid SMS_API_URL: ${SMS_API_URL}`);
            return;
        }

        const response = await axios.post(SMS_API_URL, {
            api_key: SMS_API_KEY,
            to,
            message: body
        });
        logger.info(`SMS sent to ${to}: ${response.status}`);
    } catch (error) {
        logger.error('Error sending SMS:', { message: error.message });
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

// Image/Video Upload Endpoint
app.post('/api/upload/media', authenticateAdmin, upload.single('media'), async (req, res) => {
    logger.info('Upload media request received', { file: req.file, body: req.body });
    try {
        if (!req.file) {
            logger.warn('No media file provided');
            return res.status(400).json({ error: 'No media file provided' });
        }

        const isVideo = req.file.mimetype.startsWith('video');
        const uploadResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { resource_type: isVideo ? 'video' : 'image', public_id: `oak_dental_${uuidv4()}` },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.file.buffer);
        });

        res.status(200).json({ url: uploadResult.secure_url, mimetype: req.file.mimetype });
    } catch (error) {
        logger.error('Error uploading media to Cloudinary:', { message: error.message });
        res.status(500).json({ error: 'Failed to upload media' });
    }
});

// Admin Authentication Endpoints
app.post('/api/admin/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        logger.info('Register request:', { name, email, password: '[REDACTED]' });
        if (!name || !email || !password) {
            logger.warn('Registration failed: Missing fields');
            return res.status(400).json({ error: 'All fields (name, email, password) are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Registration failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingAdmin = await pool.query('SELECT 1 FROM admins WHERE email = $1', [email]);
        if (existingAdmin.rows.length > 0) {
            logger.warn(`Registration failed: Email already exists - ${email}`);
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO admins (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
            [name, email, hashedPassword]
        );
        const admin = result.rows[0];

        const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '1h' });
        logger.info(`Admin registered: ${email}`);
        res.status(201).json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        logger.error('Error registering admin:', { message: error.message, stack: error.stack });
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
        logger.info('Login request:', { email, password: '[REDACTED]' });
        if (!email || !password) {
            logger.warn('Login failed: Missing fields');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Login failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        const admin = result.rows[0];

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            logger.warn(`Login failed: Invalid credentials for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '1h' });
        logger.info(`Admin logged in: ${email}`);
        res.json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        logger.error('Error logging in admin:', { message: error.message });
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

// Newsletter Subscription Endpoint
app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            logger.warn('Newsletter subscription failed: Email is required');
            return res.status(400).json({ error: 'Email is required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Newsletter subscription failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingSubscriber = await pool.query('SELECT 1 FROM newsletter_subscribers WHERE email = $1', [email]);
        if (existingSubscriber.rows.length > 0) {
            logger.warn(`Newsletter subscription failed: Email already subscribed - ${email}`);
            return res.status(400).json({ error: 'Email already subscribed' });
        }

        await pool.query('INSERT INTO newsletter_subscribers (email) VALUES ($1)', [email]);

        await sendEmail(
            email,
            'Welcome to Oak Dental Clinic Newsletter',
            `<p>Dear Subscriber,</p>
             <p>Thank you for subscribing to the Oak Dental Clinic newsletter!</p>
             <p>You will receive the latest dental tips, clinic updates, and special offers directly to your inbox.</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Best regards,<br>Oak Dental Clinic</p>`
        );

        res.status(201).json({ message: 'Subscribed successfully' });
    } catch (error) {
        logger.error('Error subscribing to newsletter:', { message: error.message });
        if (error.code === '23505') {
            res.status(400).json({ error: 'Email already subscribed' });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
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
        logger.error('Error fetching time slots:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/leave-dates', async (req, res) => {
    try {
        const result = await pool.query('SELECT date FROM leave_dates');
        const leaveDates = result.rows.map(row => row.date);
        res.json(leaveDates);
    } catch (error) {
        logger.error('Error fetching leave dates:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/appointments', async (req, res) => {
    try {
        const { id, full_name, email, phone, date, time } = req.body;
        if (!id || !full_name || !email || !phone || !date || !time) {
            logger.warn('Appointment booking failed: Missing required fields');
            return res.status(400).json({ error: 'All required fields (id, full_name, email, phone, date, time) must be provided' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Appointment booking failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            logger.warn('Appointment booking failed: Invalid phone number');
            return res.status(400).json({ error: 'Phone number must be 10 digits' });
        }

        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
            logger.warn('Appointment booking failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        const timeRegex = /^(1[0-2]|0?[1-9]):([0-5][0-9]) (AM|PM)$/;
        if (!timeRegex.test(time)) {
            logger.warn('Appointment booking failed: Invalid time format');
            return res.status(400).json({ error: 'Invalid time format. Use HH:MM AM/PM' });
        }

        const status = 'PENDING';
        const treatment = 'General Checkup';

        await pool.query(
            'INSERT INTO appointments (id, full_name, email, phone, treatment, price, date, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [id, full_name, email, phone, treatment, 0.00, date, time, status]
        );

        await sendEmail(
            email,
            'Appointment Confirmation - Oak Dental Clinic',
            `<p>Dear ${full_name},</p>
             <p>Your appointment has been booked for ${date} at ${time}.</p>
             <p>We will send a confirmation once approved. For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            phone,
            `Dear ${full_name}, your appointment at Oak Dental Clinic is booked for ${date} at ${time}. Awaiting approval. Contact: +91756936767`
        );

        res.status(201).json({ message: 'Appointment booked successfully' });
    } catch (error) {
        logger.error('Error booking appointment:', { message: error.message });
        if (error.code === '23505') {
            res.status(400).json({ error: 'Appointment ID already exists' });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

app.get('/api/appointments/status', async (req, res) => {
    try {
        const { identifier } = req.query;
        if (!identifier) {
            logger.warn('Appointment status check failed: Identifier required');
            return res.status(400).json({ error: 'Identifier (phone or email) is required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const phoneRegex = /^\d{10}$/;
        if (!emailRegex.test(identifier) && !phoneRegex.test(identifier)) {
            logger.warn('Appointment status check failed: Invalid identifier');
            return res.status(400).json({ error: 'Identifier must be a valid email or 10-digit phone number' });
        }

        const result = await pool.query(
            'SELECT id, full_name, email, date, time, status FROM appointments WHERE phone = $1 OR email = $1',
            [identifier]
        );

        if (result.rows.length === 0) {
            logger.info(`No appointment found for identifier: ${identifier}`);
            return res.status(404).json({ message: 'No appointment found' });
        }

        res.json({ appointment: result.rows[0] });
    } catch (error) {
        logger.error('Error checking appointment status:', { message: error.message });
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
            logger.warn(`Appointment cancellation failed: Appointment not found - ${id}`);
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
        logger.error('Error cancelling appointment:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/clear-selected', authenticateAdmin, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            logger.warn('Clear selected appointments failed: No IDs provided');
            return res.status(400).json({ error: 'No appointment IDs provided' });
        }
        await pool.query('DELETE FROM appointments WHERE id = ANY($1)', [ids]);
        logger.info(`Cleared ${ids.length} appointments`);
        res.json({ message: 'Selected appointments cleared' });
    } catch (error) {
        logger.error('Error clearing selected appointments:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/appointments/clear-old', authenticateAdmin, async (req, res) => {
    try {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        await pool.query('DELETE FROM appointments WHERE date < $1', [thirtyDaysAgo]);
        logger.info('Cleared old appointments');
        res.json({ message: 'Old appointments cleared' });
    } catch (error) {
        logger.error('Error clearing old appointments:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Waitlist Endpoints
app.post('/api/waitlist', async (req, res) => {
    try {
        const { name, email, phone, preferredDate } = req.body;
        if (!name || !email || !phone || !preferredDate) {
            logger.warn('Waitlist join failed: Missing required fields');
            return res.status(400).json({ error: 'All fields (name, email, phone, preferredDate) are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Waitlist join failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            logger.warn('Waitlist join failed: Invalid phone number');
            return res.status(400).json({ error: 'Phone number must be 10 digits' });
        }

        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(preferredDate)) {
            logger.warn('Waitlist join failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
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
        logger.error('Error joining waitlist:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/waitlist/:id/accept', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { date, time } = req.body;
        logger.info(`Waitlist accept request for ID ${id}`, { date, time, body: req.body });
        if (!date || !time) {
            logger.warn('Waitlist accept failed: Date and time required', { id, body: req.body });
            return res.status(400).json({ error: 'Date and time are required' });
        }

        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
            logger.warn('Waitlist accept failed: Invalid date format', { id, date });
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        const timeRegex = /^(1[0-2]|0?[1-9]):([0-5][0-9]) (AM|PM)$/;
        if (!timeRegex.test(time)) {
            logger.warn('Waitlist accept failed: Invalid time format', { id, time });
            return res.status(400).json({ error: 'Invalid time format. Use HH:MM AM/PM' });
        }

        const waitlistResult = await pool.query('SELECT * FROM waitlist WHERE id = $1', [id]);
        if (waitlistResult.rows.length === 0) {
            logger.warn('Waitlist accept failed: Entry not found', { id });
            return res.status(404).json({ error: 'Waitlist entry not found' });
        }

        const entry = waitlistResult.rows[0];
        if (entry.status === 'ACCEPTED') {
            logger.warn('Waitlist accept failed: Already accepted', { id });
            return res.status(400).json({ error: 'Waitlist entry already accepted' });
        }

        const appointmentId = Date.now(); // Generate unique ID
        await pool.query(
            'INSERT INTO appointments (id, full_name, email, phone, treatment, price, date, time, status, approved) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
            [appointmentId, entry.full_name, entry.email, entry.phone, 'From Waitlist', 0.00, date, time, 'APPROVED', true]
        );

        await pool.query('UPDATE waitlist SET status = $1 WHERE id = $2', ['ACCEPTED', id]);

        await sendEmail(
            entry.email,
            'Appointment Confirmed - Oak Dental Clinic',
            `<p>Dear ${entry.full_name},</p>
             <p>Your waitlist request has been approved. Your appointment is scheduled for ${date} at ${time}.</p>
             <p>For any queries, contact us at +91756936767.</p>
             <p>Thank you,<br>Oak Dental Clinic</p>`
        );

        await sendSMS(
            entry.phone,
            `Dear ${entry.full_name}, your waitlist request for Oak Dental Clinic has been approved. Appointment scheduled for ${date} at ${time}. Contact: +91756936767`
        );

        logger.info('Waitlist entry accepted', { waitlistId: id, appointmentId });
        res.json({ message: 'Waitlist entry accepted', appointmentId });
    } catch (error) {
        logger.error('Error accepting waitlist entry:', { message: error.message, id });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/waitlist/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM waitlist WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            logger.warn('Delete waitlist failed: Not found', { id });
            return res.status(404).json({ error: 'Waitlist entry not found' });
        }
        logger.info('Waitlist entry deleted', { id });
        res.json({ message: 'Waitlist entry deleted' });
    } catch (error) {
        logger.error('Error deleting waitlist entry:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Feedback Endpoints
app.post('/api/feedback', async (req, res) => {
    try {
        const { full_name, email, rating, description } = req.body;
        if (!full_name || !email || !rating || !description) {
            logger.warn('Feedback submission failed: Missing required fields');
            return res.status(400).json({ error: 'All fields (full_name, email, rating, description) are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Feedback submission failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
            logger.warn('Feedback submission failed: Invalid rating');
            return res.status(400).json({ error: 'Rating must be an integer between 1 and 5' });
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
        logger.error('Error submitting feedback:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/feedback', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, full_name, email, rating, description, created_at FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching feedback:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/feedback/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM feedback WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            logger.warn('Delete feedback failed: Not found', { id });
            return res.status(404).json({ error: 'Feedback not found' });
        }
        logger.info('Feedback deleted', { id });
        res.json({ message: 'Feedback deleted' });
    } catch (error) {
        logger.error('Error deleting feedback:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Service Endpoints
app.get('/api/services', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, price, image, video FROM services');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching services:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/services/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT id, title, description, price, image, video FROM services WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            logger.warn('Fetch service failed: Not found', { id });
            return res.status(404).json({ error: 'Service not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error fetching service:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/services', authenticateAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    try {
        const { title, description, price } = req.body;
        if (!title || !description || !price) {
            logger.warn('Service creation failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        const priceValue = parseFloat(price);
        if (isNaN(priceValue) || priceValue < 0) {
            logger.warn('Service creation failed: Invalid price');
            return res.status(400).json({ error: 'Price must be a non-negative number' });
        }

        let imageUrl = null;
        let videoUrl = null;

        if (req.files && req.files.image) {
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: 'image', public_id: `oak_dental_service_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.files.image[0].buffer);
            });
            imageUrl = uploadResult.secure_url;
        }

        if (req.files && req.files.video) {
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: 'video', public_id: `oak_dental_service_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.files.video[0].buffer);
            });
            videoUrl = uploadResult.secure_url;
        }

        const result = await pool.query(
            'INSERT INTO services (title, description, price, image, video) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [title, description, priceValue, imageUrl, videoUrl]
        );

        logger.info('Service added', { id: result.rows[0].id });
        res.status(201).json(result.rows[0]);
    } catch (error) {
        logger.error('Error adding service:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/admin/services/:id', authenticateAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, price } = req.body;
        if (!title || !description || !price) {
            logger.warn('Service update failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        const priceValue = parseFloat(price);
        if (isNaN(priceValue) || priceValue < 0) {
            logger.warn('Service update failed: Invalid price');
            return res.status(400).json({ error: 'Price must be a non-negative number' });
        }

        const existingService = await pool.query('SELECT image, video FROM services WHERE id = $1', [id]);
        if (existingService.rows.length === 0) {
            logger.warn(`Service update failed: Service not found - ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }

        let imageUrl = existingService.rows[0].image;
        let videoUrl = existingService.rows[0].video;

        if (req.files && req.files.image) {
            if (imageUrl) {
                const publicId = imageUrl.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`oak_dental_service_${publicId}`);
            }
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: 'image', public_id: `oak_dental_service_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.files.image[0].buffer);
            });
            imageUrl = uploadResult.secure_url;
        }

        if (req.files && req.files.video) {
            if (videoUrl) {
                const publicId = videoUrl.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`oak_dental_service_${publicId}`, { resource_type: 'video' });
            }
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: 'video', public_id: `oak_dental_service_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.files.video[0].buffer);
            });
            videoUrl = uploadResult.secure_url;
        }

        const result = await pool.query(
            'UPDATE services SET title = $1, description = $2, price = $3, image = $4, video = $5 WHERE id = $6 RETURNING *',
            [title, description, priceValue, imageUrl, videoUrl, id]
        );

        if (result.rows.length === 0) {
            logger.warn(`Service update failed: Service not found - ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }

        logger.info('Service updated', { id });
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error updating service:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const service = await pool.query('SELECT image, video FROM services WHERE id = $1', [id]);
        if (service.rows.length === 0) {
            logger.warn(`Service deletion failed: Service not found - ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }

        const { image, video } = service.rows[0];
        if (image) {
            const publicId = image.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`oak_dental_service_${publicId}`).catch(err => logger.error('Error deleting Cloudinary image:', { message: err.message }));
        }
        if (video) {
            const publicId = video.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`oak_dental_service_${publicId}`, { resource_type: 'video' }).catch(err => logger.error('Error deleting Cloudinary video:', { message: err.message }));
        }

        await pool.query('DELETE FROM services WHERE id = $1', [id]);
        logger.info('Service deleted', { id });
        res.json({ message: 'Service deleted successfully' });
    } catch (error) {
        logger.error('Error deleting service:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Offer Endpoints
app.get('/api/offers', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, price, image, video, media_url FROM offers ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching offers:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/offers/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!id || isNaN(parseInt(id))) {
            logger.warn('Fetch offer failed: Invalid ID', { id });
            return res.status(400).json({ error: 'Valid offer ID is required' });
        }
        const result = await pool.query('SELECT id, title, description, price, image, video, media_url FROM offers WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            logger.warn('Fetch offer failed: Not found', { id });
            return res.status(404).json({ error: 'Offer not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error fetching offer:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/offers', authenticateAdmin, upload.single('media'), async (req, res) => {
    try {
        const { title, description, price, mediaUrl } = req.body;
        if (!title || !description || description === 'undefined' || !price) {
            logger.warn('Offer creation failed: Missing or invalid required fields');
            return res.status(400).json({ error: 'Title, description, and price are required, and description cannot be "undefined"' });
        }

        const priceValue = parseFloat(price);
        if (isNaN(priceValue) || priceValue < 0) {
            logger.warn('Offer creation failed: Invalid price');
            return res.status(400).json({ error: 'Price must be a non-negative number' });
        }

        let imageUrl = null;
        let videoUrl = null;

        if (req.file) {
            const isVideo = req.file.mimetype.startsWith('video');
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: isVideo ? 'video' : 'image', public_id: `oak_dental_offer_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.file.buffer);
            });
            if (isVideo) {
                videoUrl = uploadResult.secure_url;
            } else {
                imageUrl = uploadResult.secure_url;
            }
        }

        if (mediaUrl) {
            const urlRegex = /^(https?:\/\/[^\s/$.?#].[^\s]*)$/;
            if (!urlRegex.test(mediaUrl)) {
                logger.warn('Offer creation failed: Invalid media URL');
                return res.status(400).json({ error: 'Invalid media URL format' });
            }
        }

        const result = await pool.query(
            'INSERT INTO offers (title, description, price, image, video, media_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [title, description, priceValue, imageUrl, videoUrl, mediaUrl || null]
        );

        logger.info('Offer added', { id: result.rows[0].id });
        res.status(201).json(result.rows[0]);
    } catch (error) {
        logger.error('Error adding offer:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/admin/offers/:id', authenticateAdmin, upload.single('media'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!id || isNaN(parseInt(id))) {
            logger.warn('Offer update failed: Invalid ID', { id });
            return res.status(400).json({ error: 'Valid offer ID is required' });
        }

        const { title, description, price, mediaUrl } = req.body;
        if (!title || !description || description === 'undefined' || !price) {
            logger.warn('Offer update failed: Missing or invalid required fields');
            return res.status(400).json({ error: 'Title, description, and price are required, and description cannot be "undefined"' });
        }

        const priceValue = parseFloat(price);
        if (isNaN(priceValue) || priceValue < 0) {
            logger.warn('Offer update failed: Invalid price');
            return res.status(400).json({ error: 'Price must be a non-negative number' });
        }

        const existingOffer = await pool.query('SELECT image, video FROM offers WHERE id = $1', [id]);
        if (existingOffer.rows.length === 0) {
            logger.warn(`Offer update failed: Offer not found - ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }

        let imageUrl = existingOffer.rows[0].image;
        let videoUrl = existingOffer.rows[0].video;

        if (req.file) {
            const isVideo = req.file.mimetype.startsWith('video');
            if (isVideo) {
                if (videoUrl) {
                    const publicId = videoUrl.split('/').pop().split('.')[0];
                    await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`, { resource_type: 'video' }).catch(err => logger.error('Error deleting old video:', { message: err.message }));
                }
                if (imageUrl) {
                    const publicId = imageUrl.split('/').pop().split('.')[0];
                    await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`).catch(err => logger.error('Error deleting old image:', { message: err.message }));
                    imageUrl = null;
                }
            } else {
                if (imageUrl) {
                    const publicId = imageUrl.split('/').pop().split('.')[0];
                    await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`).catch(err => logger.error('Error deleting old image:', { message: err.message }));
                }
                if (videoUrl) {
                    const publicId = videoUrl.split('/').pop().split('.')[0];
                    await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`, { resource_type: 'video' }).catch(err => logger.error('Error deleting old video:', { message: err.message }));
                    videoUrl = null;
                }
            }
            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { resource_type: isVideo ? 'video' : 'image', public_id: `oak_dental_offer_${uuidv4()}` },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.file.buffer);
            });
            if (isVideo) {
                videoUrl = uploadResult.secure_url;
            } else {
                imageUrl = uploadResult.secure_url;
            }
        }

        if (mediaUrl) {
            const urlRegex = /^(https?:\/\/[^\s/$.?#].[^\s]*)$/;
            if (!urlRegex.test(mediaUrl)) {
                logger.warn('Offer update failed: Invalid media URL');
                return res.status(400).json({ error: 'Invalid media URL format' });
            }
        }

        const result = await pool.query(
            'UPDATE offers SET title = $1, description = $2, price = $3, image = $4, video = $5, media_url = $6 WHERE id = $7 RETURNING *',
            [title, description, priceValue, imageUrl, videoUrl, mediaUrl || null, id]
        );

        if (result.rows.length === 0) {
            logger.warn(`Offer update failed: Offer not found - ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }

        logger.info('Offer updated', { id });
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error updating offer:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/offers/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!id || isNaN(parseInt(id))) {
            logger.warn('Offer deletion failed: Invalid ID', { id });
            return res.status(400).json({ error: 'Valid offer ID is required' });
        }

        const offer = await pool.query('SELECT image, video FROM offers WHERE id = $1', [id]);
        if (offer.rows.length === 0) {
            logger.warn(`Offer deletion failed: Offer not found - ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }

        const { image, video } = offer.rows[0];
        if (image) {
            const publicId = image.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`).catch(err => logger.error('Error deleting offer image:', { message: err.message }));
        }
        if (video) {
            const publicId = video.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`oak_dental_offer_${publicId}`, { resource_type: 'video' }).catch(err => logger.error('Error deleting offer video:', { message: err.message }));
        }

        await pool.query('DELETE FROM offers WHERE id = $1', [id]);
        logger.info('Offer deleted', { id });
        res.json({ message: 'Offer deleted successfully' });
    } catch (error) {
        logger.error('Error deleting offer:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Management Endpoints
app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching appointments:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/waitlist', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waitlist ORDER BY created_at');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching waitlist:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/feedback', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching feedback:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/leave-dates', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT date FROM leave_dates ORDER BY date');
        const leaveDates = result.rows.map(row => row.date);
        res.json(leaveDates);
    } catch (error) {
        logger.error('Error fetching leave dates for admin:', { message: error.message });
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
            logger.warn(`Appointment approval failed: Appointment not found - ${id}`);
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

        logger.info('Appointment approved', { id });
        res.json({ message: 'Appointment approved successfully' });
    } catch (error) {
        logger.error('Error approving appointment:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/:id/reschedule', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { newDate, newTime, reason } = req.body;
        if (!newDate || !newTime || !reason) {
            logger.warn('Appointment reschedule failed: Missing required fields');
            return res.status(400).json({ error: 'New date, time, and reason are required' });
        }

        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(newDate)) {
            logger.warn('Appointment reschedule failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        const timeRegex = /^(1[0-2]|0?[1-9]):([0-5][0-9]) (AM|PM)$/;
        if (!timeRegex.test(newTime)) {
            logger.warn('Appointment reschedule failed: Invalid time format');
            return res.status(400).json({ error: 'Invalid time format. Use HH:MM AM/PM' });
        }

        const result = await pool.query(
            'UPDATE appointments SET date = $1, time = $2, status = $3, reschedule_reason = $4 WHERE id = $5 RETURNING full_name, email, phone',
            [newDate, newTime, 'RESCHEDULED', reason, id]
        );

        if (result.rows.length === 0) {
            logger.warn(`Appointment reschedule failed: Appointment not found - ${id}`);
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

        logger.info('Appointment rescheduled', { id });
        res.json({ message: 'Appointment rescheduled successfully' });
    } catch (error) {
        logger.error('Error rescheduling appointment:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/appointments/:id/cancel', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        if (!reason) {
            logger.warn('Appointment cancellation failed: Reason required');
            return res.status(400).json({ error: 'Cancellation reason is required' });
        }

        const result = await pool.query(
            'UPDATE appointments SET status = $1, admin_reason = $2 WHERE id = $3 RETURNING full_name, email, phone, date, time',
            ['CANCELLED', reason, id]
        );

        if (result.rows.length === 0) {
            logger.warn(`Appointment cancellation failed: Appointment not found - ${id}`);
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

        logger.info('Appointment cancelled', { id });
        res.json({ message: 'Appointment cancelled successfully' });
    } catch (error) {
        logger.error('Error cancelling appointment:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/leave-dates', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.body;
        if (!date) {
            logger.warn('Leave date addition failed: Date required');
            return res.status(400).json({ error: 'Date is required' });
        }

        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
            logger.warn('Leave date addition failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        await pool.query('INSERT INTO leave_dates (date) VALUES ($1) ON CONFLICT (date) DO NOTHING', [date]);
        logger.info('Leave date added', { date });
        res.status(201).json({ message: 'Leave date added successfully' });
    } catch (error) {
        logger.error('Error adding leave date:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/leave-dates/:date', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.params;
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
            logger.warn('Leave date deletion failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        const result = await pool.query('DELETE FROM leave_dates WHERE date = $1', [date]);

        if (result.rowCount === 0) {
            logger.warn(`Leave date deletion failed: Date not found - ${date}`);
            return res.status(404).json({ error: 'Leave date not found' });
        }

        logger.info('Leave date deleted', { date });
        res.json({ message: 'Leave date removed successfully' });
    } catch (error) {
        logger.error('Error removing leave date:', { message: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Catch-All Route for Undefined Endpoints
app.use((req, res) => {
    logger.warn(`Unhandled request: ${req.method} ${req.url}`);
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        logger.error('Invalid JSON payload:', { body: req.body });
        return res.status(400).json({ error: 'Invalid JSON payload' });
    }
    if (err instanceof multer.MulterError) {
        logger.error('Multer error:', { message: err.message });
        return res.status(400).json({ error: 'File upload error: ' + err.message });
    }
    if (err.message.includes('Invalid file type')) {
        logger.error('Invalid file type:', { message: err.message });
        return res.status(400).json({ error: err.message });
    }
    logger.error('Server error:', { message: err.message });
    res.status(500).json({ error: 'Internal server error' });
});

// Start Server
app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
});