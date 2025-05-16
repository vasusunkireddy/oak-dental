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

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from public folder (includes index.html, admin.html, and uploads)
app.use(express.static(path.join(__dirname, 'public')));

// Multer setup for image uploads
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
        const filetypes = /jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only PNG and JPEG images are allowed'));
    },
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Database Connection
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false
        }
    }
});

// Models
const Admin = sequelize.define('Admin', {
    username: { type: Sequelize.STRING, allowNull: false, unique: true },
    email: { type: Sequelize.STRING, allowNull: false, unique: true },
    password: { type: Sequelize.STRING, allowNull: false }
});

const Time = sequelize.define('Time', {
    time: { type: Sequelize.STRING, allowNull: false }
});

const Treatment = sequelize.define('Treatment', {
    name: { type: Sequelize.STRING, allowNull: false },
    description: { type: Sequelize.TEXT, allowNull: false },
    cost: { type: Sequelize.FLOAT, allowNull: false },
    imageUrl: { type: Sequelize.STRING }
});

const Appointment = sequelize.define('Appointment', {
    name: { type: Sequelize.STRING, allowNull: false },
    email: { type: Sequelize.STRING, allowNull: false },
    phone: { type: Sequelize.STRING, allowNull: false },
    date: { type: Sequelize.STRING, allowNull: false },
    time: { type: Sequelize.STRING, allowNull: false },
    status: { type: Sequelize.STRING, defaultValue: 'Pending' },
    transactionId: { type: Sequelize.STRING }
});

const Contact = sequelize.define('Contact', {
    name: { type: Sequelize.STRING, allowNull: false },
    email: { type: Sequelize.STRING, allowNull: false },
    message: { type: Sequelize.TEXT, allowNull: false },
    createdAt: { type: Sequelize.DATE, defaultValue: Sequelize.NOW }
});

const Newsletter = sequelize.define('Newsletter', {
    email: { type: Sequelize.STRING, allowNull: false, unique: true },
    createdAt: { type: Sequelize.DATE, defaultValue: Sequelize.NOW }
});

Appointment.belongsTo(Treatment, { foreignKey: 'serviceId' });

// Sync Database
sequelize.sync({ alter: true })
    .then(() => console.log('Database synced'))
    .catch(err => console.error('Database sync error:', err));

// Middleware to verify JWT
const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
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
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = sanitizeInput(req.body);
        const admin = await Admin.findOne({ where: { username } });
        if (!admin) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Public Routes
app.get('/api/treatments', async (req, res) => {
    try {
        const treatments = await Treatment.findAll();
        res.json(treatments);
    } catch (error) {
        console.error('Error fetching treatments:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/times', async (req, res) => {
    try {
        const times = await Time.findAll();
        res.json(times);
    } catch (error) {
        console.error('Error fetching times:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = sanitizeInput(req.body);
        await Contact.create({ name, email, message });
        res.status(201).json({ message: 'Message sent' });
    } catch (error) {
        console.error('Error saving contact:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = sanitizeInput(req.body);
        const existingSubscriber = await Newsletter.findOne({ where: { email } });
        if (existingSubscriber) {
            return res.status(400).json({ message: 'Email already subscribed' });
        }
        await Newsletter.create({ email });
        res.status(201).json({ message: 'Subscribed successfully' });
    } catch (error) {
        console.error('Error subscribing:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/appointments/status', async (req, res) => {
    try {
        const { email } = sanitizeInput(req.query);
        const appointment = await Appointment.findOne({ where: { email }, include: [Treatment] });
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found' });
        }
        res.json(appointment);
    } catch (error) {
        console.error('Error checking status:', error);
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
        const returnUrl = process.env.PAYPAL_RETURN_URL || 'http://localhost:3000/success';
        const cancelUrl = process.env.PAYPAL_CANCEL_URL || 'http://localhost:3000/cancel';

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
            }
        });
        res.json({ id: response.data.id });
    } catch (error) {
        console.error('Error creating PayPal order:', {
            message: error.message,
            response: error.response ? {
                status: error.response.status,
                statusText: error.response.statusText,
                data: error.response.data
            } : 'No response data'
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
        const response = await axios.post(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderId}/capture`, {}, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64')}`
            }
        });
        const appointmentData = {
            ...appointment,
            transactionId: response.data.purchase_units[0].payments.captures[0].id
        };
        await Appointment.create(appointmentData);
        res.json({ transactionId: response.data.purchase_units[0].payments.captures[0].id });
    } catch (error) {
        console.error('Error capturing PayPal order:', error);
        res.status(500).json({ message: 'Failed to capture order' });
    }
});

// Admin Routes
app.get('/api/admin/times', authenticateAdmin, async (req, res) => {
    try {
        const times = await Time.findAll();
        res.json(times);
    } catch (error) {
        console.error('Error fetching times:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/times', authenticateAdmin, async (req, res) => {
    try {
        const { time } = sanitizeInput(req.body);
        await Time.create({ time });
        res.status(201).json({ message: 'Time slot added' });
    } catch (error) {
        console.error('Error adding time:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/times/:id', authenticateAdmin, async (req, res) => {
    try {
        await Time.destroy({ where: { id: req.params.id } });
        res.json({ message: 'Time slot deleted' });
    } catch (error) {
        console.error('Error deleting time:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/treatments', authenticateAdmin, async (req, res) => {
    try {
        const treatments = await Treatment.findAll();
        res.json(treatments);
    } catch (error) {
        console.error('Error fetching treatments:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/treatments', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description, cost } = sanitizeInput(req.body);
        if (!name || !description || !cost) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
        await Treatment.create({ name, description, cost: parseFloat(cost), imageUrl });
        res.status(201).json({ message: 'Treatment added' });
    } catch (error) {
        console.error('Error adding treatment:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/treatments/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description, cost } = sanitizeInput(req.body);
        if (!name || !description || !cost) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const updateData = { name, description, cost: parseFloat(cost) };
        if (req.file) {
            updateData.imageUrl = `/uploads/${req.file.filename}`;
        }
        await Treatment.update(updateData, { where: { id: req.params.id } });
        res.json({ message: 'Treatment updated' });
    } catch (error) {
        console.error('Error updating treatment:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/treatments/:id', authenticateAdmin, async (req, res) => {
    try {
        const treatment = await Treatment.findByPk(req.params.id);
        if (treatment && treatment.imageUrl) {
            const imagePath = path.join(__dirname, 'public', treatment.imageUrl);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        await Treatment.destroy({ where: { id: req.params.id } });
        res.json({ message: 'Treatment deleted' });
    } catch (error) {
        console.error('Error deleting treatment:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/appointments', authenticateAdmin, async (req, res) => {
    try {
        const appointments = await Appointment.findAll({ include: [Treatment] });
        res.json(appointments);
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/appointments/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = sanitizeInput(req.body);
        await Appointment.update({ status }, { where: { id: req.params.id } });
        res.json({ message: 'Appointment updated' });
    } catch (error) {
        console.error('Error updating appointment:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/contacts', authenticateAdmin, async (req, res) => {
    try {
        const contacts = await Contact.findAll();
        res.json(contacts);
    } catch (error) {
        console.error('Error fetching contacts:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/newsletter', authenticateAdmin, async (req, res) => {
    try {
        const subscribers = await Newsletter.findAll();
        res.json(subscribers);
    } catch (error) {
        console.error('Error fetching subscribers:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Serve admin page at /admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error Handling for Multer
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ message: 'File upload error: ' + err.message });
    } else if (err) {
        return res.status(400).json({ message: err.message });
    }
    next();
});

// Global Error Handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// SPA fallback for user frontend (excluding /admin and /api)
app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && req.path !== '/admin') {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.status(404).json({ message: 'Resource not found' });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});