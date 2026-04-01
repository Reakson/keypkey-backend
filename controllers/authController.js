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
    });
  });
};
