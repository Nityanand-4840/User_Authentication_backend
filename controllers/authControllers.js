const User = require("../models/User");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const authmiddleware = require("../middleware/authmiddleware"); // Adjust the path as necessary

const SECRET_KEY = 
  "8be165cb3e1816b9370d87866649742a7ee214b06bb26dd47fe355a04af50d03"; // Use environment variables in production

// Email Transporter Setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "pandeynityanand4840@gmail.com",
    pass: "eqblhjvbrmhkbhre",
  },
});

// Generate OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

// Register User and Send OTP
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });

    if (user) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    user = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiry,
      isVerified: false,
    });
    await user.save();

    await transporter.sendMail({
      from: "pandeynityanand4840@gmail.com",
      to: email,
      subject: "OTP Verification",
      text: `Your OTP is: ${otp}`,
    });

    res
      .status(201)
      .json({ message: "User registered. Please verify OTP sent to email." });
  } catch (error) {
    res.status(500).json({ message: "Error registering user", error });
  }
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "User not found" });
    if (user.isVerified)
      return res.status(400).json({ message: "User already verified" });

    if (user.otp !== otp || user.otpExpiry < new Date()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    res.json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    res.status(500).json({ message: "Error verifying OTP", error });
  }
};

// Resend OTP
exports.resendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "User not found" });
    if (user.isVerified)
      return res.status(400).json({ message: "User already verified" });

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await transporter.sendMail({
      from: "pandeynityanand4840@gmail.com",
      to: email,
      subject: "Resend OTP Verification",
      text: `Your new OTP is: ${otp}`,
    });

    res.json({ message: "OTP resent successfully." });
  } catch (error) {
    res.status(500).json({ message: "Error resending OTP", error });
  }
};
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Incorrect password" });

    if (!user.isVerified) {
      return res
        .status(400)
        .json({ message: "Email not verified. Please verify OTP." });
    }

    //  Hardcoded Secret Key
    const SECRET_KEY =
      "8be165cb3e1816b9370d87866649742a7ee214b06bb26dd47fe355a04af50d03";

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    // Send token as an HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true, // Prevents access via JavaScript
      secure: process.env.NODE_ENV === "production", // Secure in production
      sameSite: "Strict", // Prevent CSRF attacks
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    //  Return token in JSON response too
    res.json({
      message: "Login successful",
      // token, // Send token in response body
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
};

// Logout User
exports.logout = (req, res) => {
  try {
    res.clearCookie("token"); // Remove the JWT cookie
    res.json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ message: "Error logging out", error });
  }
};

// Dashboard (Protected Route)
exports.dashboard = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); // Exclude password

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({
      message: "Welcome to the dashboard",
      user,
    });
  } catch (error) {
    res.status(500).json({ message: "Error fetching dashboard", error });
  }
};
