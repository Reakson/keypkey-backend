const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// REGISTER
exports.registerUser = async (req, res) => {
  try {
    const { username, email, password, recovery_phrase } = req.body;

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // hash recovery phrase
    const recoveryHash = await bcrypt.hash(recovery_phrase, 10);

    const sql = `
      INSERT INTO users (username, email, password_hash, recovery_phrase_hash)
      VALUES (?, ?, ?, ?)
    `;

    db.query(
      sql,
      [username, email, hashedPassword, recoveryHash],
      (err, result) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        res.json({
          message: "User registered successfully"
        });
      }
    );

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// LOGIN
exports.loginUser = (req, res) => {

  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], async (err, results) => {

    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const user = results[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user.user_id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token: token
    });

  });
};
