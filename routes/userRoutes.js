const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const crypto = require('crypto');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { window } = new JSDOM('');
const { getStoredRefreshToken } = require('../utils/authUtils');
const purify = DOMPurify(window);

// Load the env variables
dotenv.config();

async function sendMail(mailOptions) {
  try {
    const refreshToken = await getStoredRefreshToken('google');
    const oAuth2Client = new google.auth.OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      'http://localhost'
    );

    oAuth2Client.setCredentials({
      refresh_token: refreshToken
    });
    const accessToken = await oAuth2Client.getAccessToken();
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.EMAIL,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: refreshToken,
        accessToken: accessToken.token
      }
    });

    const result = await transporter.sendMail(mailOptions);
    return result;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}

// Middleware for JWT authentication
function authenticateToken(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
}

// Register a new user
router.post('/register', [
  check('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  check('email').isEmail().withMessage('Please enter a valid email'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword
    });
    const newUser = await user.save();
    res.status(201).json(newUser);
  } catch (err) {
    console.error('Error saving user:', err);
    if (err.name === 'MongoError' && err.code === 11000) {
      res.status(400).json({ message: 'User already exists' });
    } else {
      res.status(400).json({ message: err.message });
    }
  }
});

// User login
router.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(400).json({ message: 'Email not found, please register' });
    }

    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password, please try again' });
    }

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Save refresh token in the database
    user.refreshToken = refreshToken;
    await user.save();

    // Set the userEmail cookie if biometric is true
    if (user.biometricEnabled === true) {
      const sanitizedEmail = purify.sanitize(req.body.email.trim());
      res.cookie('userEmail', sanitizedEmail, {
        domain: '.himalayanrasa.com',
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production', // Ensure this is true in production
        sameSite: 'Strict',
        maxAge: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years in milliseconds
      });
    }

    res.json({ token, refreshToken, userId: user._id });
  } catch (err) {
    console.error('Server error during login:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh Token is required' });
  }

  try {
    // Verify the refresh token
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Check if the refresh token matches the one in the database
    const user = await User.findById(payload.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: 'Invalid Refresh Token' });
    }

    // Generate a new access token
    const newAccessToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error('Error during token refresh:', err);
    return res.status(403).json({ message: 'Invalid or Expired Refresh Token' });
  }
});

router.post('/logout', async (req, res) => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);
    if (user) {
      user.refreshToken = null; // Clear the refresh token
      await user.save();
    }
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Error during logout:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// Get user profile (Protected route)
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user.email);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Enable Biometric
router.post('/enable-biometric', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.biometricEnabled = true;
    await user.save();
    res.status(200).json({ message: 'Biometric login enabled successfully' });
  } catch (err) {
    console.error('Error enabling biometric login:', err);
    res.status(500).json({ message: 'Error enabling biometric login' });
  }
});

router.get('/biometric-status', async (req, res) => {
  let { email } = req.query;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ biometricEnabled: user.biometricEnabled });
  } catch (err) {
    console.error('Error fetching biometric status:', err);
    res.status(500).json({ message: 'Error fetching biometric status' });
  }
});



// Request OTP for password reset
router.post('/request-reset-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Generate OTP
  const otp = crypto.randomBytes(3).toString('hex');
  user.resetPasswordOTP = otp;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  await user.save();

  // Send OTP email
  const mailOptions = {
    from: process.env.EMAIL,
    to: user.email,
    subject: 'Password Reset OTP',
    text: `Your OTP for password reset is ${otp}`
  };

  try {
    await sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent to email' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending email', error: error.toString() });
  }
});

// Verify OTP and reset password
router.post('/verify-otp', [
  check('email').isEmail().withMessage('Please enter a valid email'),
  check('otp').isLength({ min: 6 }).withMessage('OTP must be 6 characters long'),
  check('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'No user found with this email' });
    }

    if (user.resetPasswordOTP === otp && user.resetPasswordExpires > Date.now()) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.resetPasswordOTP = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      res.status(200).json({ message: 'Password reset successfully' });
    } else {
      res.status(400).json({ message: 'Invalid OTP or OTP expired' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Error resetting password:' });
  }
});


// ---------- Address Management Routes ------------------
router.post('/addresses', authenticateToken, async (req, res) => {
  const { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    if (isDefault) {
      user.addresses.forEach(address => address.isDefault = false);
    }
    user.addresses.push({ label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault });
    await user.save();
    res.status(200).json(user.addresses);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('addresses');
    res.status(200).json(user.addresses);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.delete('/addresses/:addressId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    user.addresses = user.addresses.filter(address => address._id.toString() !== req.params.addressId);
    await user.save();
    res.status(200).json(user.addresses);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.put('/addresses/:addressId', authenticateToken, async (req, res) => {
  const { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    const address = user.addresses.id(req.params.addressId);
    if (!address) return res.status(404).json({ message: 'Address not found' });

    if (isDefault) {
      user.addresses.forEach(address => address.isDefault = false);
    }
    Object.assign(address, { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault });
    await user.save();
    res.status(200).json(user.addresses);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = {
  router,
  authenticateToken
};
