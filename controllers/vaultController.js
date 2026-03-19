const db = require("../config/db");
const { encrypt } = require("../utils/encryption");

// Add Password
exports.addPassword = (req, res) => {
  const { website, site_username, password } = req.body;
  const userId = req.user.userId;

  if (!website || !site_username || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  const encryptedData = encrypt(password);

  const sql = `
    INSERT INTO vault 
    (user_id, website, site_username, password_encrypted, iv, auth_tag)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [
      userId,
      website,
      site_username,
      encryptedData.encrypted,
      encryptedData.iv,
      encryptedData.authTag
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({ message: "Password saved successfully" });
    }
  );
};

const { decrypt } = require("../utils/encryption");

// GET ALL PASSWORDS
exports.getPasswords = (req, res) => {
  const userId = req.user.userId;

  const sql = "SELECT * FROM vault WHERE user_id = ?";

  db.query(sql, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // decrypt each password
    const decryptedData = results.map(item => {
      const decryptedPassword = decrypt(
        item.password_encrypted,
        item.iv,
        item.auth_tag
      );

      return {
        id: item.vault_id,
        website: item.website,
        site_username: item.site_username,
        password: decryptedPassword
      };
    });

    res.json(decryptedData);
  });
};

// DELETE PASSWORD
exports.deletePassword = (req, res) => {
  const userId = req.user.userId;
  const vaultId = req.params.id;

  const sql = `
    DELETE FROM vault 
    WHERE vault_id = ? AND user_id = ?
  `;

  db.query(sql, [vaultId, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Password not found" });
    }

    res.json({ message: "Password deleted successfully" });
  });
};

// UPDATE PASSWORD
exports.updatePassword = (req, res) => {
  const userId = req.user.userId;
  const vaultId = req.params.id;

  const { website, site_username, password } = req.body;

  const encryptedData = encrypt(password);

  const sql = `
    UPDATE vault
    SET website = ?, site_username = ?, password_encrypted = ?, iv = ?, auth_tag = ?
    WHERE vault_id = ? AND user_id = ?
  `;

  db.query(
    sql,
    [
      website,
      site_username,
      encryptedData.encrypted,
      encryptedData.iv,
      encryptedData.authTag,
      vaultId,
      userId
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Password not found" });
      }

      res.json({ message: "Password updated successfully" });
    }
  );
};