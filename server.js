const express = require('express');
const fs = require('fs');
const path = require('path');
const Sequelize = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const axios = require('axios');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const winston = require('winston');

// Load environment variables
dotenv.config();

// Validate critical environment variables
const requiredEnvVars = [
    'DATABASE_URL',
    'JWT_SECRET',
    'PAYPAL_CLIENT_ID',
    'PAYPAL_CLIENT_SECRET',
    'EMAIL_USER',
    'EMAIL_PASS'
];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Error: Missing required environment variable ${envVar}`);
        process.exit(1);
    }
}

const app = express();

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ]
});

// CORS Configuration
const allowedOrigins = [
    'https://oak-dental.onrender.com',
    'http://localhost:3000',
    'http://localhost:5000' // For local testing
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Serve static files from public folder
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests from this IP, please try again after 15 minutes.'
});
app.use(limiter);

// Multer setup for image and video uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_').toLowerCase();
        cb(null, `${uniqueSuffix}-${sanitizedName}`);
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|mp4/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only PNG, JPEG, and MP4 files are allowed'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 2 // Max 2 files (image + video)
    }
}).fields([
    { name: 'image', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]);

// Database Connection
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false
        }
    },
    logging: (msg) => logger.debug(msg)
});

// Models
const Admin = sequelize.define('Admin', {
    username: { type: Sequelize.STRING, allowNull: false, unique: true },
    email: { type: Sequelize.STRING, allowNull: false, unique: true },
    password: { type: Sequelize.STRING, allowNull: false }
}, { timestamps: true });

const Time = sequelize.define('Time', {
    time: { type: Sequelize.STRING, allowNull: false }
}, { timestamps: true });

const Treatment = sequelize.define('Treatment', {
    name: { type: Sequelize.STRING, allowNull: false },
    description: { type: Sequelize.TEXT, allowNull: false },
    cost: { type: Sequelize.FLOAT, allowNull: false },
    offer: { type: Sequelize.STRING },
    image: { type: Sequelize.STRING },
    video: { type: Sequelize.STRING }
}, { timestamps: true });

const Appointment = sequelize.define('Appointment', {
    name: { type: Sequelize.STRING, allowNull: false },
    email: { type: Sequelize.STRING, allowNull: false },
    phone: { type: Sequelize.STRING, allowNull: false },
    date: { type: Sequelize.STRING, allowNull: false },
    time: { type: Sequelize.STRING, allowNull: false },
    status: { type: Sequelize.STRING, defaultValue: 'Pending' },
    transactionId: { type: Sequelize.STRING },
    serviceId: { type: Sequelize.INTEGER, allowNull: true }
}, { timestamps: true });

const Contact = sequelize.define('Contact', {
    name: { type: Sequelize.STRING, allowNull: false },
    email: { type: Sequelize.STRING, allowNull: false },
    message: { type: Sequelize.TEXT, allowNull: false }
}, { timestamps: true });

const Newsletter = sequelize.define('Newsletter', {
    email: { type: Sequelize.STRING, allowNull: false, unique: true }
}, { timestamps: true });

// Define Relationships
Treatment.hasMany(Appointment, { foreignKey: 'serviceId', as: 'Appointments' });
Appointment.belongsTo(Treatment, { foreignKey: 'serviceId', as: 'Treatment' });

// Sync Database
sequelize.sync({ alter: true })
    .then(() => logger.info('Database synced successfully'))
    .catch(err => logger.error('Database sync failed:', { message: err.message, stack: err.stack }));

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware to verify JWT
const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) {
        logger.warn('No token provided in Authorization header', { ip: req.ip });
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        logger.error('Authentication error:', { message: error.message, stack: error.stack, ip: req.ip });
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Sanitize input
const sanitizeInput = (data) => {
    if (typeof data === 'string') {
        return sanitizeHtml(data, { allowedTags: [], allowedAttributes: {} });
    }
    if (typeof data === 'object' && data !== null) {
        const sanitized = {};
        for (const key in data) {
            sanitized[key] = sanitizeInput(data[key]);
        }
        return sanitized;
    }
    return data;
};

// Health Check Endpoint
app.get('/api/health', async (req, res) => {
    try {
        await sequelize.authenticate();
        res.status(200).json({ message: 'Database connection successful', timestamp: new Date().toISOString() });
    } catch (error) {
        logger.error('Health check failed:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Database connection failed' });
    }
});

// Admin Registration
app.post('/api/admin/register', async (req, res) => {
    try {
        const { username, email, password } = sanitizeInput(req.body);
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }
        const existingAdmin = await Admin.findOne({ where: { [Sequelize.Op.or]: [{ username }, { email }] } });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        await Admin.create({ username, email, password: hashedPassword });
        logger.info('Admin registered successfully', { username, email });
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (error) {
        logger.error('Registration error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = sanitizeInput(req.body);
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        const admin = await Admin.findOne({ where: { username } });
        if (!admin) {
            logger.warn('Login attempt with invalid username', { username });
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            logger.warn('Login attempt with incorrect password', { username });
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info('Admin logged in successfully', { username });
        res.json({ token });
    } catch (error) {
        logger.error('Login error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// File Upload Endpoint
app.post('/api/admin/upload', authenticateAdmin, upload, async (req, res) => {
    try {
        const files = req.files;
        if (!files || (!files.image && !files.video)) {
            return res.status(400).json({ message: 'At least one file (image or video) must be uploaded' });
        }
        const response = {
            imageUrl: files.image ? `/uploads/${files.image[0].filename}` : null,
            videoUrl: files.video ? `/uploads/${files.video[0].filename}` : null
        };
        logger.info('Files uploaded successfully', { image: response.imageUrl, video: response.videoUrl });
        res.status(200).json(response);
    } catch (error) {
        logger.error('Upload error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: `Failed to upload files: ${error.message}` });
    }
});

// Contact Reply Endpoint
app.post('/api/admin/contact/reply', authenticateAdmin, async (req, res) => {
    try {
        const { contactId, email, message } = sanitizeInput(req.body);
        if (!contactId || !email || !message) {
            return res.status(400).json({ message: 'Contact ID, email, and message are required' });
        }
        const contact = await Contact.findByPk(contactId);
        if (!contact) {
            return res.status(404).json({ message: 'Contact message not found' });
        }
        await transporter.sendMail({
            from: `"OAK Dental Hospital" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Response to Your Inquiry',
            text: message,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                    <h2 style="color: #0f2a44;">OAK Dental Hospital</h2>
                    <p style="color: #1e293b;">Dear ${contact.name},</p>
                    <p style="color: #1e293b;">Thank you for reaching out to us. Below is our response to your inquiry:</p>
                    <p style="color: #1e293b; background-color: #ffffff; padding: 15px; border-radius: 8px;">${message}</p>
                    <p style="color: #1e293b;">If you have further questions, feel free to contact us.</p>
                    <p style="color: #1e293b;">Best regards,<br>OAK Dental Hospital Team</p>
                    <hr style="border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #6b7280; font-size: 12px;">This is an automated email, please do not reply directly.</p>
                </div>
            `
        });
        logger.info('Reply sent successfully', { contactId, email });
        res.status(200).json({ message: 'Reply sent successfully' });
    } catch (error) {
        logger.error('Error sending reply:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Failed to send reply: ' + error.message });
    }
});

// Public Routes for index.html
app.get('/api/treatments', async (req, res) => {
    try {
        const treatments = await Treatment.findAll({
            attributes: ['id', 'name', 'description', 'cost', 'offer', 'image', 'video']
        });
        res.json(treatments);
    } catch (error) {
        logger.error('Error fetching treatments (public):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/times', async (req, res) => {
    try {
        const times = await Time.findAll({
            attributes: ['id', 'time']
        });
        res.json(times);
    } catch (error) {
        logger.error('Error fetching times (public):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = sanitizeInput(req.body);
        if (!name || !email || !message) {
            return res.status(400).json({ message: 'Name, email, and message are required' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }
        await Contact.create({ name, email, message });
        logger.info('Contact message saved', { name, email });
        res.status(201).json({ message: 'Message sent successfully' });
    } catch (error) {
        logger.error('Error saving contact:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = sanitizeInput(req.body);
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }
        const existingSubscriber = await Newsletter.findOne({ where: { email } });
        if (existingSubscriber) {
            return res.status(400).json({ message: 'Email already subscribed' });
        }
        await Newsletter.create({ email });
        logger.info('Newsletter subscription added', { email });
        res.status(201).json({ message: 'Subscribed successfully' });
    } catch (error) {
        logger.error('Error subscribing:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/appointments/status', async (req, res) => {
    try {
        const { email } = sanitizeInput(req.query);
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        const appointment = await Appointment.findOne({
            where: { email },
            include: [{ model: Treatment, as: 'Treatment', attributes: ['name'] }],
            attributes: ['id', 'name', 'email', 'date', 'time', 'status', 'createdAt']
        });
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found' });
        }
        res.json(appointment);
    } catch (error) {
        logger.error('Error checking appointment status:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// PayPal Routes
app.post('/api/paypal/create-order', async (req, res) => {
    try {
        const { amount, description } = sanitizeInput(req.body);
        if (!amount || !description) {
            return res.status(400).json({ message: 'Amount and description are required' });
        }
        const currencyCode = process.env.PAYPAL_CURRENCY || 'USD';
        const returnUrl = process.env.PAYPAL_RETURN_URL || 'https://oak-dental.onrender.com/success';
        const cancelUrl = process.env.PAYPAL_CANCEL_URL || 'https://oak-dental.onrender.com/cancel';

        const response = await axios.post('https://api-m.sandbox.paypal.com/v2/checkout/orders', {
            intent: 'CAPTURE',
            purchase_units: [{
                amount: {
                    currency_code: currencyCode,
                    value: parseFloat(amount).toFixed(2)
                },
                description
            }],
            application_context: {
                return_url: returnUrl,
                cancel_url: cancelUrl
            }
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64')}`
            },
            timeout: 10000
        });
        logger.info('PayPal order created', { orderId: response.data.id });
        res.json({ id: response.data.id });
    } catch (error) {
        logger.error('Error creating PayPal order:', {
            message: error.message,
            response: error.response ? {
                status: error.response.status,
                statusText: error.response.statusText,
                data: error.response.data
            } : 'No response data',
            stack: error.stack
        });
        if (error.response && error.response.status === 422) {
            const details = error.response.data.details || [];
            return res.status(422).json({
                message: 'PayPal order creation failed due to validation errors',
                details: details.map(detail => detail.description || detail.issue).join('; ')
            });
        }
        res.status(500).json({ message: 'Failed to create PayPal order' });
    }
});

app.post('/api/paypal/capture-order', async (req, res) => {
    try {
        const { orderId, appointment } = sanitizeInput(req.body);
        if (!orderId || !appointment) {
            return res.status(400).json({ message: 'Order ID and appointment data are required' });
        }
        if (!appointment.name || !appointment.email || !appointment.phone || !appointment.date || !appointment.time || !appointment.serviceId) {
            return res.status(400).json({ message: 'Incomplete appointment data' });
        }
        const response = await axios.post(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderId}/capture`, {}, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64')}`
            },
            timeout: 10000
        });

        const transaction = response.data.purchase_units[0].payments.captures[0];
        const appointmentData = {
            name: appointment.name,
            email: appointment.email,
            phone: appointment.phone,
            date: appointment.date,
            time: appointment.time,
            serviceId: appointment.serviceId,
            transactionId: transaction.id,
            status: 'Confirmed'
        };
        const createdAppointment = await Appointment.create(appointmentData);
        logger.info('PayPal order captured and appointment created', { orderId, appointmentId: createdAppointment.id });
        res.json({
            transactionId: transaction.id,
            appointmentId: createdAppointment.id
        });
    } catch (error) {
        logger.error('Error capturing PayPal order:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Failed to capture order' });
    }
});

// Admin Routes for admin.html
app.get('/api/admin/times', authenticateAdmin, async (req, res) => {
    try {
        const times = await Time.findAll({
            attributes: ['id', 'time', 'createdAt'],
            order: [['time', 'ASC']]
        });
        res.json(times);
    } catch (error) {
        logger.error('Error fetching times (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/times', authenticateAdmin, async (req, res) => {
    try {
        const { time } = sanitizeInput(req.body);
        if (!time) {
            return res.status(400).json({ message: 'Time is required' });
        }
        if (!/^(0?[1-9]|1[0-2]):[0-5][0-9] (AM|PM)$/.test(time)) {
            return res.status(400).json({ message: 'Invalid time format (e.g., 09:00 AM)' });
        }
        await Time.create({ time });
        logger.info('Time slot added', { time });
        res.status(201).json({ message: 'Time slot added' });
    } catch (error) {
        logger.error('Error adding time:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/times/:id', authenticateAdmin, async (req, res) => {
    try {
        const time = await Time.findByPk(req.params.id);
        if (!time) {
            return res.status(404).json({ message: 'Time slot not found' });
        }
        await Time.destroy({ where: { id: req.params.id } });
        logger.info('Time slot deleted', { id: req.params.id });
        res.json({ message: 'Time slot deleted' });
    } catch (error) {
        logger.error('Error deleting time:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/treatments', authenticateAdmin, async (req, res) => {
    try {
        const treatments = await Treatment.findAll({
            attributes: ['id', 'name', 'description', 'cost', 'offer', 'image', 'video', 'createdAt'],
            order: [['createdAt', 'DESC']]
        });
        res.json(treatments);
    } catch (error) {
        logger.error('Error fetching treatments (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/treatments', authenticateAdmin, async (req, res) => {
    try {
        const { name, description, cost, offer, image, video } = sanitizeInput(req.body);
        if (!name || !description || cost === undefined) {
            return res.status(400).json({ message: 'Name, description, and cost are required' });
        }
        if (isNaN(cost) || cost < 0) {
            return res.status(400).json({ message: 'Cost must be a valid positive number' });
        }
        const treatmentData = {
            name,
            description,
            cost: parseFloat(cost),
            offer: offer || null,
            image: image || null,
            video: video || null
        };
        await Treatment.create(treatmentData);
        logger.info('Treatment added', { name, cost });
        res.status(201).json({ message: 'Treatment added' });
    } catch (error) {
        logger.error('Error adding treatment:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/treatments/:id', authenticateAdmin, async (req, res) => {
    try {
        const { name, description, cost, offer, image, video } = sanitizeInput(req.body);
        if (!name || !description || cost === undefined) {
            return res.status(400).json({ message: 'Name, description, and cost are required' });
        }
        if (isNaN(cost) || cost < 0) {
            return res.status(400).json({ message: 'Cost must be a valid positive number' });
        }
        const treatment = await Treatment.findByPk(req.params.id);
        if (!treatment) {
            return res.status(404).json({ message: 'Treatment not found' });
        }
        const updateData = {
            name,
            description,
            cost: parseFloat(cost),
            offer: offer || null,
            image: image || treatment.image,
            video: video || treatment.video
        };
        await Treatment.update(updateData, { where: { id: req.params.id } });
        logger.info('Treatment updated', { id: req.params.id, name });
        res.json({ message: 'Treatment updated' });
    } catch (error) {
        logger.error('Error updating treatment:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/treatments/:id', authenticateAdmin, async (req, res) => {
    try {
        const treatment = await Treatment.findByPk(req.params.id);
        if (!treatment) {
            return res.status(404).json({ message: 'Treatment not found' });
        }
        if (treatment.image) {
            const imagePath = path.join(__dirname, 'public', treatment.image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
                logger.info('Deleted treatment image', { path: imagePath });
            }
        }
        if (treatment.video) {
            const videoPath = path.join(__dirname, 'public', treatment.video);
            if (fs.existsSync(videoPath)) {
                fs.unlinkSync(videoPath);
                logger.info('Deleted treatment video', { path: videoPath });
            }
        }
        await Treatment.destroy({ where: { id: req.params.id } });
        logger.info('Treatment deleted', { id: req.params.id });
        res.json({ message: 'Treatment deleted' });
    } catch (error) {
        logger.error('Error deleting treatment:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.findAll({
            include: [{
                model: Treatment,
                as: 'Treatment',
                attributes: ['id', 'name'],
                required: false
            }],
            attributes: ['id', 'name', 'email', 'phone', 'date', 'time', 'status', 'transactionId', 'serviceId', 'createdAt'],
            order: [['createdAt', 'DESC']]
        });
        res.json(appointments);
    } catch (error) {
        logger.error('Error fetching appointments (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/appointments/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = sanitizeInput(req.body);
        if (!status || !['Pending', 'Confirmed', 'Cancelled'].includes(status)) {
            return res.status(400).json({ message: 'Valid status is required (Pending, Confirmed, Cancelled)' });
        }
        const appointment = await Appointment.findByPk(req.params.id);
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found' });
        }
        await Appointment.update({ status }, { where: { id: req.params.id } });
        logger.info('Appointment status updated', { id: req.params.id, status });
        res.json({ message: 'Appointment updated' });
    } catch (error) {
        logger.error('Error updating appointment:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/payments', authenticateAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.findAll({
            where: { transactionId: { [Sequelize.Op.ne]: null } },
            include: [{
                model: Treatment,
                as: 'Treatment',
                attributes: ['id', 'name', 'cost'],
                required: false
            }],
            attributes: ['id', 'name', 'email', 'transactionId', 'createdAt']
        });

        const payments = appointments.map(appointment => ({
            transactionId: appointment.transactionId,
            amount: appointment.Treatment ? appointment.Treatment.cost : 0,
            payer: {
                name: appointment.name,
                email: appointment.email
            },
            appointmentId: appointment.id,
            date: appointment.createdAt
        }));
        res.json(payments);
    } catch (error) {
        logger.error('Error fetching payments (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/contacts', authenticateAdmin, async (req, res) => {
    try {
        const contacts = await Contact.findAll({
            attributes: ['id', 'name', 'email', 'message', 'createdAt'],
            order: [['createdAt', 'DESC']]
        });
        res.json(contacts);
    } catch (error) {
        logger.error('Error fetching contacts (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/newsletter', authenticateAdmin, async (req, res) => {
    try {
        const subscribers = await Newsletter.findAll({
            attributes: ['id', 'email', 'createdAt'],
            order: [['createdAt', 'DESC']]
        });
        res.json(subscribers);
    } catch (error) {
        logger.error('Error fetching subscribers (admin):', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Serve Frontend Pages
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && req.path !== '/admin') {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.status(404).json({ message: 'Resource not found' });
    }
});

// Error Handling for Multer
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        logger.error('Multer error:', { message: err.message, stack: err.stack });
        return res.status(400).json({ message: `File upload error: ${err.message}` });
    } else if (err) {
        logger.error('File upload error:', { message: err.message, stack: err.stack });
        return res.status(400).json({ message: err.message });
    }
    next();
});

// Global Error Handling
app.use((err, req, res, next) => {
    logger.error('Global error:', { message: err.message, stack: err.stack, path: req.path, method: req.method });
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
});