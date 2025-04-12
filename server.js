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
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'a3f8d9e72c1b06f5e4d9876543210abcdef0123456789fedcba9876543210';
const ADMIN_KEY = process.env.ADMIN_KEY || 'Panelkey1';

// Enhanced CORS configuration
app.use(cors({
  origin: [
    'https://monsignor-morr1son.onrender.com',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware setup
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Utility function to save images
const saveImage = (base64Data, userId) => {
  const matches = base64Data.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) return null;

  const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
  const filename = `user-${userId}-${Date.now()}.${ext}`;
  const filepath = path.join(__dirname, 'public/uploads', filename);

  fs.writeFileSync(filepath, matches[2], 'base64');
  return `/uploads/${filename}`;
};

// Authentication middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/status', (req, res) => {
  res.json({ 
    status: 'Monsignor Morrison Backend is running! 🚀',
    environment: process.env.NODE_ENV || 'development'
  });
});

// User endpoints
app.post('/api/signup', async (req, res) => {
  const { username, password, avatar } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const userExists = await new Promise((resolve) => {
      db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        resolve(!!row);
      });
    });

    if (userExists) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    let avatarPath = null;
    if (avatar && avatar.startsWith('data:image')) {
      avatarPath = saveImage(avatar, username);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
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

    const token = jwt.sign(
      { id: userId, username: username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

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

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
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

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

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

app.post('/api/update-profile', authenticate, async (req, res) => {
  const { currentUsername, newUsername, currentPassword, newPassword, newAvatar } = req.body;
  
  try {
    if (newUsername || newPassword) {
      const user = await new Promise((resolve) => {
        db.get('SELECT * FROM users WHERE username = ?', [currentUsername], (err, row) => resolve(row));
      });
      
      if (!user) return res.status(404).json({ error: 'User not found' });
      
      const passwordMatch = await bcrypt.compare(currentPassword, user.password);
      if (!passwordMatch) return res.status(401).json({ error: 'Current password is incorrect' });
    }

    let avatarPath = null;
    if (newAvatar && newAvatar.startsWith('data:image')) {
      avatarPath = saveImage(newAvatar, newUsername || currentUsername);
    }

    let updateQuery = 'UPDATE users SET ';
    const updateParams = [];
    
    if (newUsername) {
      updateQuery += 'username = ?, ';
      updateParams.push(newUsername);
    }
    
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += 'password = ?, ';
      updateParams.push(hashedPassword);
    }
    
    if (avatarPath) {
      updateQuery += 'avatar = ?, ';
      updateParams.push(avatarPath);
    }
    
    updateQuery = updateQuery.slice(0, -2);
    updateQuery += ' WHERE username = ?';
    updateParams.push(currentUsername);

    await new Promise((resolve, reject) => {
      db.run(updateQuery, updateParams, function(err) {
        if (err) return reject(err);
        resolve();
      });
    });

    const updatedUser = await new Promise((resolve) => {
      db.get(
        'SELECT id, username, avatar FROM users WHERE username = ?',
        [newUsername || currentUsername],
        (err, row) => resolve(row)
      );
    });

    let token;
    if (newUsername) {
      token = jwt.sign(
        { id: updatedUser.id, username: updatedUser.username },
        SECRET_KEY,
        { expiresIn: '1h' }
      );
    }

    res.json({ 
      success: true, 
      user: updatedUser,
      token: token || undefined
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Server error during profile update' });
  }
});

app.get('/api/verify-token', authenticate, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Admin endpoints
app.post('/api/admin/verify', (req, res) => {
  const { key } = req.body;
  
  if (key === ADMIN_KEY) {
    res.json({ verified: true });
  } else {
    res.status(401).json({ verified: false, error: 'Invalid admin key' });
  }
});

app.get('/api/admin/users', authenticate, (req, res) => {
  db.all('SELECT id, username, avatar, banned, disabled FROM users', [], (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users });
  });
});

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

app.post('/api/admin/disable', authenticate, (req, res) => {
  const { username } = req.body;
  db.run(
    'UPDATE users SET disabled = 1 WHERE username = ?',
    [username],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.post('/api/admin/enable', authenticate, (req, res) => {
  const { username } = req.body;
  db.run(
    'UPDATE users SET disabled = 0 WHERE username = ?',
    [username],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// News endpoints
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

app.delete('/api/news/:id', authenticate, (req, res) => {
  const { id } = req.params;
  db.run(
    'DELETE FROM news WHERE id = ?',
    [id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Listings endpoints
app.get('/api/listings', (req, res) => {
  db.all('SELECT * FROM listings ORDER BY date DESC', [], (err, listings) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ listings });
  });
});

app.post('/api/listings', authenticate, (req, res) => {
  const { itemName, itemLocation, itemPrice, itemImage } = req.body;
  
  // Enhanced validation
  if (!itemName || !itemLocation || !itemPrice || isNaN(parseFloat(itemPrice))) {
    return res.status(400).json({ error: 'Valid item name, location and price are required' });
  }

  let imagePath = null;
  if (itemImage && itemImage.startsWith('data:image')) {
    imagePath = saveImage(itemImage, `listing-${Date.now()}`);
  }

  // Convert price to number to ensure proper storage
  const price = parseFloat(itemPrice);

  db.run(
    'INSERT INTO listings (itemName, itemLocation, itemPrice, itemImage) VALUES (?, ?, ?, ?)',
    [itemName, itemLocation, price, imagePath],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ 
        id: this.lastID,
        itemName,
        itemLocation,
        itemPrice: price,
        itemImage: imagePath,
        date: new Date().toISOString()
      });
    }
  );
});

app.delete('/api/listings', authenticate, (req, res) => {
  db.run('DELETE FROM listings', [], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/api/listings/:id', authenticate, (req, res) => {
  const { id } = req.params;
  db.run(
    'DELETE FROM listings WHERE id = ?',
    [id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Chat endpoints
app.get('/api/chat', (req, res) => {
  db.all('SELECT * FROM chat_messages ORDER BY timestamp DESC LIMIT 50', [], (err, messages) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ messages });
  });
});

app.post('/api/chat', authenticate, (req, res) => {
  const { username, message } = req.body;
  
  if (username !== req.user.username) {
    return res.status(403).json({ error: 'Username does not match authenticated user' });
  }

  if (!message || message.trim() === '') {
    return res.status(400).json({ error: 'Message cannot be empty' });
  }

  db.run(
    'INSERT INTO chat_messages (username, message) VALUES (?, ?)',
    [username, message.trim()],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      db.get(
        'SELECT * FROM chat_messages WHERE id = ?',
        [this.lastID],
        (err, row) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json(row);
        }
      );
    }
  );
});

app.delete('/api/chat/:id', authenticate, (req, res) => {
  const { id } = req.params;
  db.run(
    'DELETE FROM chat_messages WHERE id = ?',
    [id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Catch-all route
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  const uploadDir = path.join(__dirname, 'public/uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  console.log(`Server running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log('- POST /api/signup');
  console.log('- POST /api/login');
  console.log('- POST /api/update-profile');
  console.log('- GET  /api/news');
  console.log('- POST /api/news (protected)');
  console.log('- DELETE /api/news/:id (protected)');
  console.log('- GET  /api/admin/users (protected)');
  console.log('- POST /api/admin/verify (admin key check)');
  console.log('- GET  /api/chat');
  console.log('- POST /api/chat (protected)');
  console.log('- DELETE /api/chat/:id (protected)');
  console.log('- GET  /api/listings');
  console.log('- POST /api/listings (protected)');
  console.log('- DELETE /api/listings (protected)');
  console.log('- DELETE /api/listings/:id (protected)');
});