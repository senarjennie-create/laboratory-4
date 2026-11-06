require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const redis = require('redis');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- 1. DATABASE CONNECTION ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});

// --- 2. REDIS PUB/SUB ---
const redisPublisher = redis.createClient({ 
    url: process.env.REDIS_URL,
    RESP: 2 
});
const redisSubscriber = redis.createClient({ 
    url: process.env.REDIS_URL,
    RESP: 2 
});

(async () => {
    try {
        await redisPublisher.connect();
        await redisSubscriber.connect();
        console.log('Connected to Redis Message Broker');
        
        await redisSubscriber.subscribe('admin_broadcast', (message) => {
            io.emit('new_announcement', JSON.parse(message));
        });
    } catch (err) {
        console.log('Redis error:', err);
    }
})();

// --- 3. MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access Denied: No Token Provided' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid Token' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
    next();
};

// --- 4. AUTHENTICATION ROUTES ---
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, 'user']
        );
        res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        await pool.execute('INSERT INTO login_logs (user_id) VALUES (?)', [user.id]);
        await redisPublisher.publish('user_login_events', JSON.stringify({
            name: user.name,
            role: user.role,
            time: new Date().toLocaleTimeString()
        }));
        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role },
            redirectTo: `/${user.role}.html`
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// --- 5. ADMIN ROUTES ---
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const [rows] = await pool.execute('SELECT id, name, email, role FROM users');
    res.json(rows);
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    if (parseInt(req.params.id) === req.user.id) {
        return res.status(403).json({ error: 'You cannot delete your own admin account' });
    }
    await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.status(204).send();
});

// --- 5. ADMIN BROADCAST ---
app.post('/api/broadcast', authenticateToken, isAdmin, async (req, res) => {
    const { message } = req.body;
    try {
        const [result] = await pool.execute('INSERT INTO announcements (message) VALUES (?)', [message]);
        const [rows] = await pool.execute('SELECT * FROM announcements WHERE id = ?', [result.insertId]);
        await redisPublisher.publish('admin_broadcast', JSON.stringify(rows[0]));
        res.status(201).json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Broadcast failed' });
    }
});

// --- 6. SELF-SERVICE PROFILE ---
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { name, email, currentPassword, newPassword } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [req.user.id]);
        const user = rows[0];
        let updateQuery = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
        let params = [name, email, req.user.id];
        
        if (newPassword) {
            if (!currentPassword) return res.status(400).json({ error: 'Current password required' });
            const match = await bcrypt.compare(currentPassword, user.password);
            if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
            const hashedNew = await bcrypt.hash(newPassword, 10);
            updateQuery = 'UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?';
            params = [name, email, hashedNew, req.user.id];
        }
        await pool.execute(updateQuery, params);
        res.json({ message: 'Profile updated', name, email });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already in use' });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- 7. UPDATE USER (ADMIN) ---
app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const { name, email, role } = req.body;
    try {
        await pool.execute('UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?', [name, email, role, req.params.id]);
        res.json({ message: 'User updated' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email might already exist' });
        res.status(500).json({ error: 'Update failed' });
    }
});

// --- 6. SOCKET.IO & SERVER START ---
io.on('connection', async (socket) => {
    await redisSubscriber.subscribe('user_login_events', (message) => {
        socket.emit('user_logged_in', JSON.parse(message));
    });
});

server.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT || 3000}`);
});