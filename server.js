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
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');

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

// Multer Configuration for Cloudinary
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const isVideo = file.mimetype.startsWith('video');
        return {
            folder: 'oak_dental',
            public_id: `oak_dental_${isVideo ? 'video' : 'image'}_${uuidv4()}`,
            resource_type: isVideo ? 'video' : 'image',
            allowed_formats: ['jpg', 'png', 'jpeg', 'gif', 'webp', 'mp4', 'mpeg', 'mov']
        };
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        const allowedVideoTypes = ['video/mp4', 'video/mpeg', 'video/quicktime'];
        if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            logger.warn('File upload rejected due to invalid type', {
                filename: file.originalname,
                mimetype: file.mimetype
            });
            cb(new Error('Unsupported file type. Only JPEG, PNG, GIF, WebP images, and MP4, MPEG, MOV videos are allowed.'));
        }
    }
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

// Initialize Database
async function initializeDatabase() {
    try {
        await testDbConnection();
        await initDb();
    } catch (error) {
        logger.error('Failed to initialize application:', { message: error.message });
        process.exit(1);
    }
}

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

// Generate Available Time Slots
function generateTimeSlots() {
    const slots = [];
    const startHour = 9; // 9:00 AM
    const endHour = 17; // 5:00 PM
    for (let hour = startHour; hour < endHour; hour++) {
        slots.push(`${hour.toString().padStart(2, '0')}:00:00`);
        slots.push(`${hour.toString().padStart(2, '0')}:30:00`);
    }
    return slots;
}

// Image/Video Upload Endpoint
app.post('/api/upload/media', authenticateAdmin, upload.single('media'), async (req, res) => {
    logger.info('Upload media request received', { file: req.file });
    try {
        if (!req.file) {
            logger.warn('No media file provided');
            return res.status(400).json({ error: 'No media file provided' });
        }

        res.status(200).json({ url: req.file.path, mimetype: req.file.mimetype });
    } catch (error) {
        logger.error('Error uploading media to Cloudinary:', { message: error.message });
        res.status(500).json({ error: 'Failed to upload media to Cloudinary' });
    }
});

// Time Slots Endpoint
app.get('/api/time-slots', async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) {
            logger.warn('Time slots request failed: Date parameter missing');
            return res.status(400).json({ error: 'Date parameter is required' });
        }

        // Validate date format (YYYY-MM-DD)
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) {
            logger.warn('Time slots request failed: Invalid date format');
            return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
        }

        // Check if the date is a leave date
        const leaveDateResult = await pool.query('SELECT 1 FROM leave_dates WHERE date = $1', [date]);
        if (leaveDateResult.rows.length > 0) {
            logger.info(`No time slots available: ${date} is a leave date`);
            return res.json([]);
        }

        // Check existing appointments for the date
        const appointmentsResult = await pool.query(
            'SELECT time FROM appointments WHERE date = $1 AND status != $2',
            [date, 'CANCELLED']
        );
        const bookedSlots = appointmentsResult.rows.map(row => row.time);

        // Generate available time slots
        const allSlots = generateTimeSlots();
        const availableSlots = allSlots.filter(slot => !bookedSlots.includes(slot));

        logger.info(`Fetched available time slots for ${date}`, { availableSlots });
        res.json(availableSlots);
    } catch (error) {
        logger.error('Error fetching time slots:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching time slots' });
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

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO admins (username, email, password) VALUES ($1, $2, $3) RETURNING *',
            [name, email, hashedPassword]
        );
        const admin = result.rows[0];
        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '1h' });
        logger.info(`Admin registered: ${admin.username}`);
        res.status(201).json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        logger.error('Error registering admin:', { message: error.message });
        if (error.code === '23505') { // Unique violation (duplicate email or username)
            return res.status(400).json({ error: 'Email or username already exists' });
        }
        res.status(500).json({ error: 'Server error during registration' });
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

        const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        const admin = result.rows[0];
        if (!admin) {
            logger.warn('Login failed: Admin not found');
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            logger.warn('Login failed: Invalid password');
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '1h' });
        logger.info(`Admin logged in: ${admin.username}`);
        res.json({ token, admin: { username: admin.username, email: admin.email } });
    } catch (error) {
        logger.error('Error logging in admin:', { message: error.message });
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Appointment Endpoints
app.post('/api/appointments', async (req, res) => {
    try {
        const { full_name, email, phone, treatment, price, date, time } = req.body;
        logger.info('Appointment creation request:', { full_name, email, phone, treatment, price, date, time });
        if (!full_name || !email || !phone || !date || !time) {
            logger.warn('Appointment creation failed: Missing required fields');
            return res.status(400).json({ error: 'All fields (full_name, email, phone, date, time) are required' });
        }

        const id = Date.now();
        await pool.query(
            'INSERT INTO appointments (id, full_name, email, phone, treatment, price, date, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [id, full_name, email, phone, treatment || null, price || 0, date, time, 'PENDING']
        );

        const formattedDate = new Date(date).toLocaleDateString('en-US', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
        const emailBody = `
            <h2>Appointment Confirmation</h2>
            <p>Dear ${full_name},</p>
            <p>Your appointment has been scheduled:</p>
            <ul>
                <li><strong>Date:</strong> ${formattedDate}</li>
                <li><strong>Time:</strong> ${time}</li>
                <li><strong>Treatment:</strong> ${treatment || 'Not specified'}</li>
            </ul>
            <p>We look forward to seeing you!</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(email, 'Appointment Confirmation - Oak Dental Clinic', emailBody);

        const smsBody = `Dear ${full_name}, your appointment is scheduled on ${formattedDate} at ${time}. Treatment: ${treatment || 'Not specified'}. - Oak Dental Clinic`;
        await sendSMS(phone, smsBody);

        logger.info(`Appointment created: ID ${id}`);
        res.status(201).json({ message: 'Appointment created', id });
    } catch (error) {
        logger.error('Error creating appointment:', { message: error.message });
        res.status(500).json({ error: 'Server error while creating appointment' });
    }
});

app.get('/api/appointments', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching appointments:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching appointments' });
    }
});

app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching admin appointments:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching appointments' });
    }
});

app.post('/api/admin/appointments/:id/approve', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Approving appointment: ID ${id}`);
        const appointmentResult = await pool.query(
            'UPDATE appointments SET status = $1, approved = $2 WHERE id = $3 RETURNING *',
            ['APPROVED', true, id]
        );
        if (appointmentResult.rows.length === 0) {
            logger.warn(`Appointment not found: ID ${id}`);
            return res.status(404).json({ error: 'Appointment not found' });
        }
        const appointment = appointmentResult.rows[0];

        const formattedDate = new Date(appointment.date).toLocaleDateString('en-US', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
        const emailBody = `
            <h2>Appointment Approved</h2>
            <p>Dear ${appointment.full_name},</p>
            <p>Your appointment has been approved:</p>
            <ul>
                <li><strong>Date:</strong> ${formattedDate}</li>
                <li><strong>Time:</strong> ${appointment.time}</li>
                <li><strong>Treatment:</strong> ${appointment.treatment || 'Not specified'}</li>
            </ul>
            <p>We look forward to seeing you!</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(appointment.email, 'Appointment Approved - Oak Dental Clinic', emailBody);

        const smsBody = `Dear ${appointment.full_name}, your appointment on ${formattedDate} at ${appointment.time} has been approved. - Oak Dental Clinic`;
        await sendSMS(appointment.phone, smsBody);

        logger.info(`Appointment approved: ID ${id}`);
        res.json({ message: 'Appointment approved' });
    } catch (error) {
        logger.error('Error approving appointment:', { message: error.message });
        res.status(500).json({ error: 'Server error while approving appointment' });
    }
});

app.post('/api/admin/appointments/:id/cancel', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        logger.info(`Cancelling appointment: ID ${id}`);
        if (!reason) {
            logger.warn('Cancellation failed: Reason required');
            return res.status(400).json({ error: 'Cancellation reason is required' });
        }

        const appointmentResult = await pool.query(
            'UPDATE appointments SET status = $1, cancel_reason = $2 WHERE id = $3 RETURNING *',
            ['CANCELLED', reason, id]
        );
        if (appointmentResult.rows.length === 0) {
            logger.warn(`Appointment not found: ID ${id}`);
            return res.status(404).json({ error: 'Appointment not found' });
        }
        const appointment = appointmentResult.rows[0];

        const formattedDate = new Date(appointment.date).toLocaleDateString('en-US', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
        const emailBody = `
            <h2>Appointment Cancelled</h2>
            <p>Dear ${appointment.full_name},</p>
            <p>Your appointment has been cancelled:</p>
            <ul>
                <li><strong>Date:</strong> ${formattedDate}</li>
                <li><strong>Time:</strong> ${appointment.time}</li>
                <li><strong>Reason:</strong> ${reason}</li>
            </ul>
            <p>We apologize for the inconvenience.</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(appointment.email, 'Appointment Cancelled - Oak Dental Clinic', emailBody);

        const smsBody = `Dear ${appointment.full_name}, your appointment on ${formattedDate} at ${appointment.time} has been cancelled. Reason: ${reason}. - Oak Dental Clinic`;
        await sendSMS(appointment.phone, smsBody);

        logger.info(`Appointment cancelled: ID ${id}`);
        res.json({ message: 'Appointment cancelled' });
    } catch (error) {
        logger.error('Error cancelling appointment:', { message: error.message });
        res.status(500).json({ error: 'Server error while cancelling appointment' });
    }
});

app.post('/api/admin/appointments/clear-selected', authenticateAdmin, async (req, res) => {
    try {
        const { ids } = req.body;
        logger.info('Clearing selected appointments:', { ids });
        if (!Array.isArray(ids) || ids.length === 0) {
            logger.warn('Clear selected failed: No IDs provided');
            return res.status(400).json({ error: 'No appointment IDs provided' });
        }

        await pool.query('DELETE FROM appointments WHERE id = ANY($1::bigint[])', [ids]);
        logger.info(`Cleared ${ids.length} appointments`);
        res.json({ message: 'Selected appointments cleared' });
    } catch (error) {
        logger.error('Error clearing selected appointments:', { message: error.message });
        res.status(500).json({ error: 'Server error while clearing appointments' });
    }
});

app.delete('/api/admin/appointments/clear-old', authenticateAdmin, async (req, res) => {
    try {
        logger.info('Clearing old appointments');
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const result = await pool.query('DELETE FROM appointments WHERE date < $1', [thirtyDaysAgo.toISOString().split('T')[0]]);
        logger.info(`Cleared ${result.rowCount} old appointments`);
        res.json({ message: 'Old appointments cleared' });
    } catch (error) {
        logger.error('Error clearing old appointments:', { message: error.message });
        res.status(500).json({ error: 'Server error while clearing old appointments' });
    }
});

// Waitlist Endpoints
app.post('/api/waitlist', async (req, res) => {
    try {
        const { full_name, email, phone, preferred_date } = req.body;
        logger.info('Waitlist creation request:', { full_name, email, phone, preferred_date });
        if (!full_name || !email || !phone || !preferred_date) {
            logger.warn('Waitlist creation failed: Missing required fields');
            return res.status(400).json({ error: 'All fields (full_name, email, phone, preferred_date) are required' });
        }

        const result = await pool.query(
            'INSERT INTO waitlist (full_name, email, phone, preferred_date) VALUES ($1, $2, $3, $4) RETURNING *',
            [full_name, email, phone, preferred_date]
        );
        const waitlistEntry = result.rows[0];

        const emailBody = `
            <h2>Waitlist Confirmation</h2>
            <p>Dear ${full_name},</p>
            <p>You have been added to the waitlist for:</p>
            <ul>
                <li><strong>Preferred Date:</strong> ${preferred_date}</li>
            </ul>
            <p>We will notify you when a slot becomes available.</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(email, 'Waitlist Confirmation - Oak Dental Clinic', emailBody);

        const smsBody = `Dear ${full_name}, you have been added to the waitlist for ${preferred_date}. We will notify you when a slot is available. - Oak Dental Clinic`;
        await sendSMS(phone, smsBody);

        logger.info(`Waitlist entry created: ID ${waitlistEntry.id}`);
        res.status(201).json({ message: 'Added to waitlist', id: waitlistEntry.id });
    } catch (error) {
        logger.error('Error creating waitlist entry:', { message: error.message });
        res.status(500).json({ error: 'Server error while creating waitlist entry' });
    }
});

app.get('/api/admin/waitlist', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waitlist ORDER BY created_at');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching waitlist:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching waitlist' });
    }
});

app.post('/api/admin/waitlist/:id/accept', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Accepting waitlist entry: ID ${id}`);
        const waitlistResult = await pool.query(
            'UPDATE waitlist SET status = $1 WHERE id = $2 RETURNING *',
            ['ACCEPTED', id]
        );
        if (waitlistResult.rows.length === 0) {
            logger.warn(`Waitlist entry not found: ID ${id}`);
            return res.status(404).json({ error: 'Waitlist entry not found' });
        }
        const waitlistEntry = waitlistResult.rows[0];

        const nextAvailableDate = await getNextAvailableDate(new Date());
        const time = '10:00:00'; // Default time
        const appointmentId = Date.now();
        await pool.query(
            'INSERT INTO appointments (id, full_name, email, phone, date, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [appointmentId, waitlistEntry.full_name, waitlistEntry.email, waitlistEntry.phone, nextAvailableDate, time, 'APPROVED']
        );

        const formattedDate = new Date(nextAvailableDate).toLocaleDateString('en-US', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
        const emailBody = `
            <h2>Appointment Scheduled</h2>
            <p>Dear ${waitlistEntry.full_name},</p>
            <p>A slot has become available, and we have scheduled your appointment:</p>
            <ul>
                <li><strong>Date:</strong> ${formattedDate}</li>
                <li><strong>Time:</strong> ${time}</li>
            </ul>
            <p>We look forward to seeing you!</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(waitlistEntry.email, 'Appointment Scheduled - Oak Dental Clinic', emailBody);

        const smsBody = `Dear ${waitlistEntry.full_name}, a slot is available! Your appointment is scheduled on ${formattedDate} at ${time}. - Oak Dental Clinic`;
        await sendSMS(waitlistEntry.phone, smsBody);

        logger.info(`Waitlist entry accepted: ID ${id}, Appointment ID ${appointmentId}`);
        res.json({ message: 'Waitlist entry accepted and appointment scheduled' });
    } catch (error) {
        logger.error('Error accepting waitlist entry:', { message: error.message });
        res.status(500).json({ error: 'Server error while accepting waitlist entry' });
    }
});

app.delete('/api/admin/waitlist/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Deleting waitlist entry: ID ${id}`);
        const result = await pool.query('DELETE FROM waitlist WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            logger.warn(`Waitlist entry not found: ID ${id}`);
            return res.status(404).json({ error: 'Waitlist entry not found' });
        }
        logger.info(`Waitlist entry deleted: ID ${id}`);
        res.json({ message: 'Waitlist entry deleted' });
    } catch (error) {
        logger.error('Error deleting waitlist entry:', { message: error.message });
        res.status(500).json({ error: 'Server error while deleting waitlist entry' });
    }
});

// Feedback Endpoints
app.post('/api/feedback', async (req, res) => {
    try {
        const { full_name, email, rating, description } = req.body;
        logger.info('Feedback submission:', { full_name, email, rating, description });
        if (!full_name || !email || !rating || !description) {
            logger.warn('Feedback submission failed: Missing required fields');
            return res.status(400).json({ error: 'All fields (full_name, email, rating, description) are required' });
        }
        if (rating < 1 || rating > 5) {
            logger.warn('Feedback submission failed: Invalid rating');
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        await pool.query(
            'INSERT INTO feedback (full_name, email, rating, description) VALUES ($1, $2, $3, $4)',
            [full_name, email, rating, description]
        );
        logger.info('Feedback submitted');
        res.status(201).json({ message: 'Feedback submitted' });
    } catch (error) {
        logger.error('Error submitting feedback:', { message: error.message });
        res.status(500).json({ error: 'Server error while submitting feedback' });
    }
});

app.get('/api/feedback', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching feedback:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching feedback' });
    }
});

app.get('/api/admin/feedback', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching admin feedback:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching feedback' });
    }
});

app.delete('/api/admin/feedback/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Deleting feedback: ID ${id}`);
        const result = await pool.query('DELETE FROM feedback WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            logger.warn(`Feedback not found: ID ${id}`);
            return res.status(404).json({ error: 'Feedback not found' });
        }
        logger.info(`Feedback deleted: ID ${id}`);
        res.json({ message: 'Feedback deleted' });
    } catch (error) {
        logger.error('Error deleting feedback:', { message: error.message });
        res.status(500).json({ error: 'Server error while deleting feedback' });
    }
});

// Services Endpoints
app.get('/api/services', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM services ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching services:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching services' });
    }
});

app.get('/api/services/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM services WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            logger.warn(`Service not found: ID ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error fetching service:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching service' });
    }
});

app.post('/api/admin/services', authenticateAdmin, upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]), async (req, res) => {
    try {
        const { title, description, price, image: imageUrl, video: videoUrl } = req.body;
        logger.info('Service creation request:', { title, description, price, imageUrl, videoUrl });
        if (!title || !description || !price) {
            logger.warn('Service creation failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        let finalImageUrl = imageUrl || null;
        let finalVideoUrl = videoUrl || null;

        // If an image file is uploaded, override the image URL
        if (req.files && req.files.image) {
            finalImageUrl = req.files.image[0].path;
        }
        // If a video file is uploaded, override the video URL
        if (req.files && req.files.video) {
            finalVideoUrl = req.files.video[0].path;
        }

        const result = await pool.query(
            'INSERT INTO services (title, description, price, image, video) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [title, description, parseFloat(price), finalImageUrl, finalVideoUrl]
        );
        logger.info(`Service created: ID ${result.rows[0].id}`);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        logger.error('Error creating service:', { message: error.message });
        res.status(500).json({ error: 'Server error while creating service' });
    }
});

app.put('/api/admin/services/:id', authenticateAdmin, upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, price, image: imageUrl, video: videoUrl } = req.body;
        logger.info(`Service update request: ID ${id}`, { title, description, price, imageUrl, videoUrl });
        if (!title || !description || !price) {
            logger.warn('Service update failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        // Fetch the existing service to get the current image and video URLs
        const existingServiceResult = await pool.query('SELECT image, video FROM services WHERE id = $1', [id]);
        if (existingServiceResult.rows.length === 0) {
            logger.warn(`Service not found: ID ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }
        const existingService = existingServiceResult.rows[0];

        let finalImageUrl = imageUrl !== undefined ? imageUrl : existingService.image;
        let finalVideoUrl = videoUrl !== undefined ? videoUrl : existingService.video;

        // If an image file is uploaded, override the image URL
        if (req.files && req.files.image) {
            finalImageUrl = req.files.image[0].path;
        }
        // If a video file is uploaded, override the video URL
        if (req.files && req.files.video) {
            finalVideoUrl = req.files.video[0].path;
        }

        const result = await pool.query(
            'UPDATE services SET title = $1, description = $2, price = $3, image = $4, video = $5 WHERE id = $6 RETURNING *',
            [title, description, parseFloat(price), finalImageUrl, finalVideoUrl, id]
        );
        if (result.rows.length === 0) {
            logger.warn(`Service not found: ID ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }
        logger.info(`Service updated: ID ${id}`);
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error updating service:', { message: error.message });
        res.status(500).json({ error: 'Server error while updating service' });
    }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Deleting service: ID ${id}`);
        const result = await pool.query('DELETE FROM services WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            logger.warn(`Service not found: ID ${id}`);
            return res.status(404).json({ error: 'Service not found' });
        }
        logger.info(`Service deleted: ID ${id}`);
        res.json({ message: 'Service deleted' });
    } catch (error) {
        logger.error('Error deleting service:', { message: error.message });
        res.status(500).json({ error: 'Server error while deleting service' });
    }
});

// Offers Endpoints
app.get('/api/offers', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM offers ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error fetching offers:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching offers' });
    }
});

app.get('/api/offers/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM offers WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            logger.warn(`Offer not found: ID ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error fetching offer:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching offer' });
    }
});

app.post('/api/admin/offers', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, description, price } = req.body;
        logger.info('Offer creation request:', { title, description, price });
        if (!title || !description || !price) {
            logger.warn('Offer creation failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }
        if (!req.file) {
            logger.warn('Offer creation failed: Image required');
            return res.status(400).json({ error: 'Offer image is required' });
        }

        const imageUrl = req.file.path;
        const result = await pool.query(
            'INSERT INTO offers (title, description, price, image) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, description, parseFloat(price), imageUrl]
        );
        logger.info(`Offer created: ID ${result.rows[0].id}`);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        logger.error('Error creating offer:', { message: error.message });
        res.status(500).json({ error: 'Server error while creating offer' });
    }
});

app.put('/api/admin/offers/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, price, image: imageUrl } = req.body;
        logger.info(`Offer update request: ID ${id}`, { title, description, price, imageUrl });
        if (!title || !description || !price) {
            logger.warn('Offer update failed: Missing required fields');
            return res.status(400).json({ error: 'Title, description, and price are required' });
        }

        const existingOfferResult = await pool.query('SELECT image FROM offers WHERE id = $1', [id]);
        if (existingOfferResult.rows.length === 0) {
            logger.warn(`Offer not found: ID ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }
        const existingOffer = existingOfferResult.rows[0];

        let finalImageUrl = imageUrl !== undefined ? imageUrl : existingOffer.image;
        if (req.file) {
            finalImageUrl = req.file.path;
        }

        const result = await pool.query(
            'UPDATE offers SET title = $1, description = $2, price = $3, image = $4 WHERE id = $5 RETURNING *',
            [title, description, parseFloat(price), finalImageUrl, id]
        );
        logger.info(`Offer updated: ID ${id}`);
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error updating offer:', { message: error.message });
        res.status(500).json({ error: 'Server error while updating offer' });
    }
});

app.delete('/api/admin/offers/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        logger.info(`Deleting offer: ID ${id}`);
        const result = await pool.query('DELETE FROM offers WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            logger.warn(`Offer not found: ID ${id}`);
            return res.status(404).json({ error: 'Offer not found' });
        }
        logger.info(`Offer deleted: ID ${id}`);
        res.json({ message: 'Offer deleted' });
    } catch (error) {
        logger.error('Error deleting offer:', { message: error.message });
        res.status(500).json({ error: 'Server error while deleting offer' });
    }
});

// Leave Dates Endpoints
app.get('/api/leave-dates', async (req, res) => {
    try {
        const result = await pool.query('SELECT date FROM leave_dates ORDER BY date');
        res.json(result.rows.map(row => row.date));
    } catch (error) {
        logger.error('Error fetching leave dates:', { message: error.message });
        res.status(500).json({ error: 'Server error while fetching leave dates' });
    }
});

app.post('/api/admin/leave-dates', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.body;
        logger.info('Adding leave date:', { date });
        if (!date) {
            logger.warn('Add leave date failed: Date required');
            return res.status(400).json({ error: 'Date is required' });
        }

        const result = await pool.query('INSERT INTO leave_dates (date) VALUES ($1) ON CONFLICT DO NOTHING RETURNING *', [date]);
        if (result.rows.length === 0) {
            logger.warn(`Leave date already exists: ${date}`);
            return res.status(400).json({ error: 'Leave date already exists' });
        }
        logger.info(`Leave date added: ${date}`);
        res.status(201).json({ message: 'Leave date added' });
    } catch (error) {
        logger.error('Error adding leave date:', { message: error.message });
        res.status(500).json({ error: 'Server error while adding leave date' });
    }
});

app.delete('/api/admin/leave-dates/:date', authenticateAdmin, async (req, res) => {
    try {
        const { date } = req.params;
        logger.info(`Deleting leave date: ${date}`);
        const result = await pool.query('DELETE FROM leave_dates WHERE date = $1', [date]);
        if (result.rowCount === 0) {
            logger.warn(`Leave date not found: ${date}`);
            return res.status(404).json({ error: 'Leave date not found' });
        }
        logger.info(`Leave date deleted: ${date}`);
        res.json({ message: 'Leave date deleted' });
    } catch (error) {
        logger.error('Error deleting leave date:', { message: error.message });
        res.status(500).json({ error: 'Server error while deleting leave date' });
    }
});

// Newsletter Subscription Endpoint
app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = req.body;
        logger.info('Newsletter subscription request:', { email });
        if (!email) {
            logger.warn('Newsletter subscription failed: Email required');
            return res.status(400).json({ error: 'Email is required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn('Newsletter subscription failed: Invalid email format');
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const result = await pool.query(
            'INSERT INTO newsletter_subscribers (email) VALUES ($1) ON CONFLICT (email) DO NOTHING RETURNING *',
            [email]
        );
        if (result.rows.length === 0) {
            logger.warn(`Newsletter subscription failed: Email already subscribed: ${email}`);
            return res.status(400).json({ error: 'Email already subscribed' });
        }

        const emailBody = `
            <h2>Welcome to Oak Dental Clinic Newsletter!</h2>
            <p>Dear Subscriber,</p>
            <p>Thank you for subscribing to our newsletter. You'll receive updates on our latest offers, dental tips, and more!</p>
            <p>Best regards,<br>Oak Dental Clinic</p>
        `;
        await sendEmail(email, 'Newsletter Subscription - Oak Dental Clinic', emailBody);

        logger.info(`Newsletter subscription successful: ${email}`);
        res.status(201).json({ message: 'Subscribed to newsletter successfully' });
    } catch (error) {
        logger.error('Error subscribing to newsletter:', { message: error.message });
        res.status(500).json({ error: 'Server error while subscribing to newsletter' });
    }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', { message: err.message, stack: err.stack });
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: 'File upload error: ' + err.message });
    }
    res.status(500).json({ error: 'Something went wrong on the server' });
});

// Handle Unhandled Routes
app.use((req, res) => {
    logger.warn(`Route not found: ${req.method} ${req.url}`);
    res.status(404).json({ error: 'Route not found' });
});

// Start Server
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
}

<<<<<<< HEAD
startServer();
=======
startServer();
>>>>>>> 404ae4b94bd6621365047aa3485dc6ebb1ac20b4
