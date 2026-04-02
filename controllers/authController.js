const db = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateRecoveryKey } = require('../utils/recoveryPhrase');

// REGISTER
exports.registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Username, email, and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const recoveryKey = generateRecoveryKey();
    const recoveryHash = await bcrypt.hash(recoveryKey, 10);

    const sql = `
      INSERT INTO users (username, email, password_hash, recovery_phrase_hash)
      VALUES (?, ?, ?, ?)
    `;

    db.query(sql, [username, email, hashedPassword, recoveryHash], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'An account with that email already exists.' });
        }

        return res.status(500).json({ error: err.message });
      }

      return res.status(201).json({
        message: 'User registered successfully',
        recoveryKey,
      });
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// LOGIN
exports.loginUser = (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';

  db.query(sql, [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = results[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.user_id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
      },
    });
  });
};

// RESET PASSWORD WITH RECOVERY TOKEN
exports.resetPasswordWithRecoveryToken = (req, res) => {
  const { email, recoveryKey, newPassword } = req.body;

  if (!email || !recoveryKey || !newPassword) {
    return res.status(400).json({
      message: 'Email, recovery token, and new password are required.',
    });
  }

  const trimmedRecoveryKey = String(recoveryKey).trim();

  const sql = 'SELECT user_id, recovery_phrase_hash FROM users WHERE email = ? LIMIT 1';

  db.query(sql, [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Account not found.' });
    }

    const user = results[0];

    if (!user.recovery_phrase_hash) {
      return res.status(400).json({ message: 'No recovery token is stored for this account.' });
    }

    const validRecoveryKey = await bcrypt.compare(trimmedRecoveryKey, user.recovery_phrase_hash);

    if (!validRecoveryKey) {
      return res.status(401).json({ message: 'Recovery token does not match our records.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    db.query(
      'UPDATE users SET password_hash = ? WHERE user_id = ?',
      [passwordHash, user.user_id],
      (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: updateErr.message });
        }

        return res.json({
          message: 'Password reset successful. You can now sign in with your new password.',
        });
      }
    );
  });
};

