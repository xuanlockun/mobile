const crypto = require('crypto');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io'); 
const app = express();
const PORT = 3000;
const SECRET_KEY = 'bi_mat_ne';
const path = require('path');
const nodemailer = require('nodemailer');
require('dotenv').config();
const setupRestaurantModule = require('./restaurant-module');

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Tạo HTTP server và Socket.io
// Todo : phải refactor lại module ;-;
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const db = new sqlite3.Database('./users.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to SQLite database.');
});

const otpDb = new sqlite3.Database('./otps.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to SQLite database.');
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

otpDb.serialize(() => {
  otpDb.run(`
    CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      code TEXT,
      expires_at INTEGER,
      temp_token TEXT,        
      temp_expires INTEGER    
      )
      `);
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT,
      phone_number TEXT UNIQUE,
      age INTEGER,
      position TEXT,
      password TEXT,
      email TEXT
      )
      `);
      
  // Add sample user
  const samplePhone = '0356547701';
  const defaultPassword = bcrypt.hashSync('Admin123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (full_name, phone_number, age, position, password,email) VALUES (?, ?, ?, ?, ?,?)`,
    ['Hoàng Xuân Lộc', samplePhone, 22, 'Quản Lý', defaultPassword,'xuanlockun594@gmail.com']
  );
});

function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: 'xuanlockun594@gmail.com',
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}`,
  };
  
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.log('Error sending email:', err);
    } else {
      console.log('Email sent:', info.response);
    }
  });
}

// 🔐 Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access token missing' });
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

app.get(['/chef.html', '/index.html'], (req, res) => {
  res.redirect('/');
});

// Setup restaurant module và truyền io instance
const restaurantModule = setupRestaurantModule(app, SECRET_KEY, io);
app.use('/restaurant', restaurantModule.router);

app.get('/', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  
  if (!token) {
    return res.redirect('/login.html');
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.redirect('/login.html');
    }
    
    db.get('SELECT position FROM users WHERE id = ?', [decoded.id], (dbErr, user) => {
      if (dbErr || !user) {
        return res.redirect('/login.html');
      }
      
      if (user.position.toLowerCase() === 'quản lý') {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
      } else if (user.position.toLowerCase() === 'đầu bếp') {
        res.sendFile(path.join(__dirname, 'public', 'chef.html'));
      } else {
        res.redirect('/login.html');
      }
    });
  });
});

app.post('/register', (req, res) => {
  const { full_name, phone_number, age, position, password, email } = req.body;

  if (!full_name || !phone_number || !age || !position || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (user) return res.status(400).json({ error: 'Email này đã được đăng ký' });

    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(
      'INSERT INTO users (full_name, phone_number, age, position, password,email) VALUES (?, ?, ?, ?, ?, ?)',
      [full_name, phone_number, age, position, hashedPassword, email],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Đăng ký thành công' });
      }
    );
  });
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    otpDb.run(
      'INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt],
      (err) => {
        if (err) return res.status(500).json({ error: 'Failed to save OTP' });
        sendOTPEmail(email, otp);
        res.status(200).json({
          message: 'An OTP has been sent to your email',
        });
      }
    );
  });
});

app.post('/verify-otp', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and code are required' });
  }

  otpDb.get(
    'SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1',
    [email],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row || row.code !== code || Date.now() > row.expires_at) {
        return res.status(400).json({ error: 'Invalid or expired OTP' });
      }

      const tempToken = crypto.randomBytes(20).toString('hex');
      const tempTokenExpires = Date.now() + 10 * 60 * 1000;

      otpDb.run(
        'UPDATE otps SET temp_token = ?, temp_expires = ? WHERE id = ?',
        [tempToken, tempTokenExpires, row.id],
        (err) => {
          if (err) return res.status(500).json({ error: 'Failed to set temp token' });
          res.status(200).json({ message: 'OTP verified', temp_token: tempToken });
        }
      );
    }
  );
});

app.post('/reset-password', (req, res) => {
  const { email, temp_token, newPassword } = req.body;

  if (!email || !temp_token || !newPassword) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  otpDb.get(
    'SELECT * FROM otps WHERE email = ? AND temp_token = ? ORDER BY id DESC LIMIT 1',
    [email, temp_token],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row || Date.now() > row.temp_expires) {
        return res.status(400).json({ error: 'Invalid or expired session' });
      }

      const hashedPassword = bcrypt.hashSync(newPassword, 10);

      db.run('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        otpDb.run('DELETE FROM otps WHERE id = ?', [row.id]);
        res.status(200).json({ message: 'Password has been reset successfully' });
      });
    }
  );
});

app.get('/employees', (req, res) => {
  db.all('SELECT id,full_name, phone_number, age, position,email FROM users', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

app.delete('/employees/:id', (req, res) => {
  const id = req.params.id;

  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });

    if (this.changes === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  });
});
app.put('/employees/:id', (req, res) => {
  const id = req.params.id;
  const { full_name, phone_number, age, position, email } = req.body;

  if (!full_name || !phone_number || !age || !position || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  db.run(
    `UPDATE users 
     SET full_name = ?, phone_number = ?, age = ?, position = ?, email = ? 
     WHERE id = ?`,
    [full_name, phone_number, age, position, email, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });

      if (this.changes === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({ message: 'User updated successfully' });
    }
  );
});

app.post('/login', (req, res) => {
  const phone_number = req.body.phone_number || req.query.phone_number;
  const password = req.body.password || req.query.password;

  if (!phone_number || !password) {
    return res.status(400).json({ error: 'Phone number and password are required' });
  }

  db.get('SELECT * FROM users WHERE phone_number = ? or email = ?', [phone_number, phone_number], (err, user) => {
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

app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT id, full_name, phone_number, age, position,email FROM users WHERE id = ?', [userId], (err, user) => {
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

server.listen(PORT, () => {
  console.log(`🚀 Server running on ${PORT}`);
});