const express = require("express");
const router = express.Router();

const auth = require("../middleware/authMiddleware");
const { addPassword, getPasswords, deletePassword, updatePassword } = require("../controllers/vaultController");

router.post("/add", auth, addPassword);
router.get("/", auth, getPasswords);
router.delete("/:id", auth, deletePassword);
router.put("/:id", auth, updatePassword);

module.exports = router;