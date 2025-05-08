const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';
const path = require('path');

app.use(express.json());
app.use(cors()); // Thêm dòng này để cho phép tất cả các nguồn truy cập
app.use(express.static('public'));

// 📦 Init SQLite
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to SQLite database.');
});

// 🛠️ Create users table and sample user
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT,
      phone_number TEXT UNIQUE,
      age INTEGER,
      position TEXT,
      password TEXT
    )
  `);

  // Add sample user
  const samplePhone = '0356547701';
  const defaultPassword = bcrypt.hashSync('Admin123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (full_name, phone_number, age, position, password) VALUES (?, ?, ?, ?, ?)`,
    ['Hoàng Xuân Lộc', samplePhone, 22, 'Quản Lý', defaultPassword]
  );
});

// 🔐 Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}
app.get('/', authenticateToken, (req, res) => {
  // Get user details to check position
  db.get('SELECT position FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).send('Server error');
    if (!user) return res.redirect('/login.html');
    
    // Check if user is "Quản Lý"
    if (user.position.toLowerCase() === 'quản lý') {
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
      res.redirect('/login.html');
    }
  });
});
// 🚪 POST /register
app.post('/register', (req, res) => {
  const { full_name, phone_number, age, position } = req.body;

  if (!full_name || !phone_number || !age || !position) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  db.get('SELECT * FROM users WHERE phone_number = ?', [phone_number], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (user) return res.status(400).json({ error: 'Phone number already registered' });

    const hashedPassword = bcrypt.hashSync('Nhanvienuit123', 10);

    db.run(
      'INSERT INTO users (full_name, phone_number, age, position, password) VALUES (?, ?, ?, ?, ?)',
      [full_name, phone_number, age, position, hashedPassword],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  });
});
app.get('/employees', (req, res) => {
  db.all('SELECT full_name, phone_number, age, position,password FROM users', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);  // Return all employees
  });
});
// 🚪 POST /login
app.post('/login', (req, res) => {
  const phone_number = req.body.phone_number || req.query.phone_number;
  const password = req.body.password || req.query.password;

  if (!phone_number || !password) {
    return res.status(400).json({ error: 'Phone number and password are required' });
  }

  db.get('SELECT * FROM users WHERE phone_number = ?', [phone_number], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid phone number or password' });

    const isValid = bcrypt.compareSync(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid phone number or password' });

    const token = jwt.sign({ id: user.id, phone_number: user.phone_number }, SECRET_KEY, {
      expiresIn: '1h',
    });

    res.json({ access_token: token });
  });
});

// 👤 GET /profile (Protected)
app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT id, full_name, phone_number, age, position FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ profile: user });
  });
});

app.get('/logout', authenticateToken, (req, res) => {
    res.json({ status: 'Đăng xuát thành công' });
  });

// 🔁 Ping
app.get('/ping', (req, res) => {
  res.json({ status: 'API is online 🚀' });
});

// 🚀 Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
