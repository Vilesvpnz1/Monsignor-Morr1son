// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000; // Flexible port for Render
const SECRET_KEY = process.env.SECRET_KEY || 'a3f8d9e72c1b06f5e4d9876543210abcdef0123456789fedcba9876543210';
const ADMIN_KEY = process.env.ADMIN_KEY || 'Panelkey1';

// Enhanced CORS configuration
app.use(cors({
  origin: [
    'https://monsignor-morr1son.onrender.com', // Your Render frontend URL
    'http://localhost:3000' // For local development
  ],
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware setup
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ======================
// UTILITY FUNCTIONS
// ======================
const saveImage = (base64Data, userId) => {
  const matches = base64Data.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) return null;

  const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
  const filename = `user-${userId}-${Date.now()}.${ext}`;
  const filepath = path.join(__dirname, 'public/uploads', filename);

  fs.writeFileSync(filepath, matches[2], 'base64');
  return `/uploads/${filename}`;
};

// ======================
// MIDDLEWARE
// ======================
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ======================
// ROUTES
// ======================

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check endpoint
app.get('/api/status', (req, res) => {
  res.json({ 
    status: 'Monsignor Morrison Backend is running! 🚀',
    environment: process.env.NODE_ENV || 'development'
  });
});

// User registration
app.post('/api/signup', async (req, res) => {
  const { username, password, avatar } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Check if username exists
    const userExists = await new Promise((resolve) => {
      db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        resolve(!!row);
      });
    });

    if (userExists) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Process avatar
    let avatarPath = null;
    if (avatar && avatar.startsWith('data:image')) {
      avatarPath = saveImage(avatar, username);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userId = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)',
        [username, hashedPassword, avatarPath],
        function(err) {
          if (err) return reject(err);
          resolve(this.lastID);
        }
      );
    });

    // Generate JWT token
    const token = jwt.sign(
      { id: userId, username: username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    // Return user data
    const user = await new Promise((resolve) => {
      db.get(
        'SELECT id, username, avatar FROM users WHERE id = ?',
        [userId],
        (err, row) => resolve(row)
      );
    });

    res.json({ success: true, user, token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Find active user
    const user = await new Promise((resolve) => {
      db.get(
        'SELECT * FROM users WHERE username = ? AND banned = 0 AND disabled = 0',
        [username],
        (err, row) => resolve(row)
      );
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    // Sanitize user data
    const userData = {
      id: user.id,
      username: user.username,
      avatar: user.avatar || 'https://i.imgur.com/6VBx3io.png'
    };

    res.json({ token, user: userData });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Token verification endpoint
app.get('/api/verify-token', authenticate, (req, res) => {
  res.json({ valid: true });
});

// ======================
// ADMIN ENDPOINTS
// ======================

// Admin verification endpoint
app.post('/api/admin/verify', (req, res) => {
  const { key } = req.body;
  
  if (key === ADMIN_KEY) {
    res.json({ verified: true });
  } else {
    res.status(401).json({ verified: false, error: 'Invalid admin key' });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticate, (req, res) => {
  db.all('SELECT id, username, avatar, banned, disabled FROM users', [], (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users });
  });
});

// Ban a user
app.post('/api/admin/ban', authenticate, (req, res) => {
  const { username } = req.body;
  db.run(
    'UPDATE users SET banned = 1 WHERE username = ?',
    [username],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Unban a user
app.post('/api/admin/unban', authenticate, (req, res) => {
  const { username } = req.body;
  db.run(
    'UPDATE users SET banned = 0 WHERE username = ?',
    [username],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// ======================
// NEWS ENDPOINTS
// ======================
app.get('/api/news', (req, res) => {
  db.all('SELECT * FROM news ORDER BY date DESC', [], (err, news) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ news });
  });
});

app.post('/api/news', authenticate, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  db.run(
    'INSERT INTO news (title, content) VALUES (?, ?)',
    [title, content],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// ======================
// CHAT ENDPOINTS
// ======================
app.get('/api/chat', (req, res) => {
  db.all('SELECT * FROM chat_messages ORDER BY timestamp DESC LIMIT 50', [], (err, messages) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ messages });
  });
});

app.post('/api/chat', authenticate, (req, res) => {
  const { username, message } = req.body;
  db.run(
    'INSERT INTO chat_messages (username, message) VALUES (?, ?)',
    [username, message],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// ======================
// CATCH-ALL ROUTE (for frontend routing)
// ======================
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  // Create uploads directory if needed
  const uploadDir = path.join(__dirname, 'public/uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  console.log(`Server running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log('- POST /api/signup');
  console.log('- POST /api/login');
  console.log('- GET  /api/news');
  console.log('- POST /api/news (protected)');
  console.log('- GET  /api/admin/users (protected)');
  console.log('- POST /api/admin/verify (admin key check)');
  console.log('- GET  /api/chat');
  console.log('- POST /api/chat (protected)');
});