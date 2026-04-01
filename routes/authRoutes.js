const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  resetPasswordWithRecoveryToken,
} = require("../controllers/authController");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/reset-password", resetPasswordWithRecoveryToken);

module.exports = router;

