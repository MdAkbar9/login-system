const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'antigravity-secure-jwt-secret-key-2026';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

// ----------------------------------------------------
// AUTHENTICATION API ROUTES
// ----------------------------------------------------

// Register New User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields (username, email, password) are required.' });
    }

    if (username.trim().length < 3) {
      return res.status(400).json({ success: false, message: 'Username must be at least 3 characters long.' });
    }

    if (!email.includes('@') || !email.includes('.')) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
    }

    // Check existing users
    if (db.findUserByEmail(email)) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists.' });
    }

    if (db.findUserByUsername(username)) {
      return res.status(400).json({ success: false, message: 'Username is already taken.' });
    }

    // Hash password with bcrypt (10 rounds)
    const saltRounds = 10;
    const startTime = Date.now();
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const hashTimeMs = Date.now() - startTime;

    // Create user in database
    const userId = db.createUser(username.trim(), email.trim(), passwordHash);
    db.updateLastLogin(userId);

    // Create JWT Token
    const token = jwt.sign(
      { userId, username, email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // set to true in HTTPS production
      maxAge: 24 * 60 * 60 * 1000
    });

    const user = db.findUserById(userId);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully!',
      token,
      user,
      securityInfo: {
        algorithm: 'bcrypt',
        saltRounds,
        hashTimeMs,
        hashPreview: passwordHash.substring(0, 20) + '...'
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { loginId, password } = req.body;

    if (!loginId || !password) {
      return res.status(400).json({ success: false, message: 'Username/Email and password are required.' });
    }

    // Find user by email or username
    let user = db.findUserByEmail(loginId) || db.findUserByUsername(loginId);

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Verify password hash using bcrypt.compare()
    const startTime = Date.now();
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    const verifyTimeMs = Date.now() - startTime;

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Update last login
    db.updateLastLogin(user.id);

    // Create JWT Token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000
    });

    const userProfile = db.findUserById(user.id);

    return res.json({
      success: true,
      message: 'Login successful!',
      token,
      user: userProfile,
      securityInfo: {
        hashComparison: 'bcrypt.compare() matched',
        verifyTimeMs
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Server error during login.' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ success: true, message: 'Logged out successfully.' });
});

// Get Current Logged-in User (Protected)
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.findUserById(req.user.userId);
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const userWithPass = db.findUserByIdWithPassword(req.user.userId);
  const totalUsers = db.getAllUsersCount();

  return res.json({
    success: true,
    user: {
      ...user,
      passwordHashPreview: userWithPass ? userWithPass.password_hash : null
    },
    systemStats: {
      totalRegisteredUsers: totalUsers
    }
  });
});

// Change Password (Protected)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Both current and new password are required.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters.' });
    }

    const user = db.findUserByIdWithPassword(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify current password
    const isCurrentValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isCurrentValid) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    }

    // Hash new password
    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    db.updatePassword(req.user.userId, newPasswordHash);

    return res.json({
      success: true,
      message: 'Password updated successfully with new bcrypt hash!',
      newHashPreview: newPasswordHash
    });
  } catch (error) {
    console.error('Change password error:', error);
    return res.status(500).json({ success: false, message: 'Failed to update password.' });
  }
});

// ----------------------------------------------------
// BCRYPT INTERACTIVE VISUALIZER API ROUTES
// ----------------------------------------------------

// Generate live Bcrypt Hash for Sandbox
app.post('/api/bcrypt/hash', async (req, res) => {
  try {
    const { text, saltRounds = 10 } = req.body;

    if (!text) {
      return res.status(400).json({ success: false, message: 'Input text is required.' });
    }

    const rounds = Math.min(Math.max(parseInt(saltRounds, 10) || 10, 4), 14); // safety clamp 4 to 14

    const start = process.hrtime.bigint();
    const salt = await bcrypt.genSalt(rounds);
    const hash = await bcrypt.hash(text, salt);
    const end = process.hrtime.bigint();

    const durationMs = Number(end - start) / 1e6;

    // Bcrypt format breakdown: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
    // Format: $[algo]$[cost]$[22 chars salt][31 chars hash]
    const parts = hash.split('$');
    const algo = parts[1] || '2b';
    const cost = parts[2] || rounds;
    const saltAndHash = parts[3] || '';
    const saltPart = saltAndHash.substring(0, 22);
    const hashPart = saltAndHash.substring(22);

    return res.json({
      success: true,
      plainText: text,
      hash,
      salt,
      saltRounds: rounds,
      durationMs: durationMs.toFixed(2),
      breakdown: {
        algorithm: `$${algo}$`,
        costFactor: cost,
        salt22Chars: saltPart,
        hash31Chars: hashPart
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Error generating hash.' });
  }
});

// Verify Plaintext against Hash for Sandbox
app.post('/api/bcrypt/verify', async (req, res) => {
  try {
    const { plainText, hash } = req.body;

    if (!plainText || !hash) {
      return res.status(400).json({ success: false, message: 'Plaintext and Hash are required.' });
    }

    const start = process.hrtime.bigint();
    const isMatch = await bcrypt.compare(plainText, hash);
    const end = process.hrtime.bigint();

    const durationMs = Number(end - start) / 1e6;

    return res.json({
      success: true,
      isMatch,
      durationMs: durationMs.toFixed(2),
      message: isMatch ? 'Match! The password produces this exact hash.' : 'No match! Passwords do not match.'
    });
  } catch (error) {
    return res.status(400).json({ success: false, message: 'Invalid bcrypt hash format or error verifying.' });
  }
});

// Catch-all route to serve index.html for SPA feel
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`================================================`);
  console.log(`🔐 Bcrypt Authentication Server running!`);
  console.log(`🌐 Web App available at: http://localhost:${PORT}`);
  console.log(`================================================`);
});
