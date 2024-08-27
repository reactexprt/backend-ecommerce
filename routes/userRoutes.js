const express = require('express');
const mongoose = require('mongoose');
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

// For Cookies
const secureCookieOptions = {
  domain: '.himalayanrasa.com',
  httpOnly: false,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Strict',
  maxAge: 5 * 365 * 24 * 60 * 60 * 1000 // 5 years
};

// User login
const loginUser = async (email, password) => {
  if (!email || !password) {
    throw new Error('Email and password must be provided');
  }
  try {
    const user = await User.findOne({ email }).select('email password').exec();
    if (!user) {
      throw new Error('Email not found');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Incorrect password');
    }
    return user;
  } catch (error) {
    console.error('Login error:', error);
    throw error; // Rethrowing the error to handle it or log it appropriately in the calling context
  }
};

const generateTokens = (user) => {
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
  return { token, refreshToken };
};

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

function authenticateToken(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied' }); // No token, return 401
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    // Check the specific error message for better error handling
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' }); // Invalid token, return 401
    } else if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Expired token' }); // Expired token, return 401
    } else {
      return res.status(400).json({ message: 'Bad Request' }); // Generic 400 for other cases
    }
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
    const { email, username, password } = req.body;
    // Optimize by checking for the existence of the user using projection to fetch minimal fields
    const existingUser = await User.findOne({ email }).select('_id').exec();
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await loginUser(email, password);
    const { token, refreshToken } = generateTokens(user);

    user.refreshToken = refreshToken;
    await user.save();

    if (user.biometricEnabled) {
      const sanitizedEmail = purify.sanitize(email.trim());
      res.cookie('userEmail', sanitizedEmail, secureCookieOptions);
    }

    res.json({ token, refreshToken, userId: user._id });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(400).json({ message: error.message });
  }
});

router.post('/token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token is required.' });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Use an indexed field for faster lookup and ensure the refreshToken is checked
    const user = await User.findOne({ _id: payload.userId, refreshToken: refreshToken }).exec();

    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token.' });
    }

    const newAccessToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(403).json({ message: 'Invalid or expired refresh token.' });
    }
    console.error('Error during token refresh:', err);
    return res.status(500).json({ message: 'Server error during token refresh.' });
  }
});

router.post('/logout', async (req, res) => {
  const userId = req.user.userId;
  try {
    // No need to check if user exists; just attempt to unset the token
    const result = await User.updateOne({ _id: userId }, { $unset: { refreshToken: "" } });

    if (result.nModified === 0) {
      return res.status(404).json({ message: 'User not found' });
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
    const user = await User.findById(req.user.userId).select('email isAdmin -_id').lean();  // Select email and isAdmin, exclude _id

    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    res.send({ email: user.email, isAdmin: user.isAdmin });  // Sending email and isAdmin status
  } catch (err) {
    console.error("Error retrieving user profile:", err);
    res.status(500).send({ message: "Failed to retrieve user profile" });
  }
});


// ---------------- Biometric Routes --------------------
router.post('/enable-biometric', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Using findOneAndUpdate to directly update the document in the database
    const updateResult = await User.findOneAndUpdate(
      { email, biometricEnabled: { $ne: true } }, // Condition to check if biometricEnabled is not already true
      { $set: { biometricEnabled: true } }, // Update operation
      { new: true } // Returns the updated document
    );

    if (!updateResult) {
      return res.status(404).json({ message: 'User not found or biometric already enabled' });
    }

    res.status(200).json({ message: 'Biometric login enabled successfully' });
  } catch (err) {
    console.error('Error enabling biometric login:', err);
    res.status(500).json({ message: 'Error enabling biometric login' });
  }
});

router.get('/biometric-status', async (req, res) => {
  const { email } = req.query;

  // Early return if email is not provided
  if (!email) {
    return res.status(400).json({ message: 'Email parameter is required' });
  }

  try {
    // Optimize query by selecting only the needed field
    const user = await User.findOne({ email }).select('biometricEnabled -_id').lean();

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ biometricEnabled: user.biometricEnabled });
  } catch (err) {
    console.error('Error fetching biometric status:', err);
    res.status(500).json({ message: 'Error fetching biometric status' });
  }
});

// ----------------Reset password and verify otp -------------
// Request OTP for password reset
router.post('/request-reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }
  try {
    // Optimize by selecting only necessary fields
    const user = await User.findOne({ email }).select('email resetPasswordOTP resetPasswordExpires -_id').lean();

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    // Generate OTP only if the previous one has expired or doesn't exist
    const currentTime = Date.now();
    if (!user.resetPasswordExpires || user.resetPasswordExpires < currentTime) {
      const otp = crypto.randomBytes(3).toString('hex');

      // Save the OTP and expiry time atomically using findOneAndUpdate
      await User.updateOne({ email }, {
        $set: {
          resetPasswordOTP: otp,
          resetPasswordExpires: currentTime + 3600000 // 1 hour from now
        }
      });

      // Prepare the email with the new OTP
      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is ${otp}`
      };

      try {
        await sendMail(mailOptions);
        res.status(200).json({ message: 'OTP sent to email' });
      } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: 'Error sending email' });
      }
    } else {
      res.status(200).json({ message: 'OTP is still valid. Please check your email.' });
    }
  } catch (error) {
    console.error('Error handling reset password request:', error);
    res.status(500).json({ message: 'Error processing request' });
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

  const { email, otp, newPassword } = req.body;

  try {
    // Optimize query by using indexed fields and project only needed fields
    const user = await User.findOne({ email, resetPasswordOTP: otp, resetPasswordExpires: { $gt: Date.now() } })
      .select('password').exec();

    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP, expired, or no user found with this email' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});


// ---------- Address Management Routes ------------------

router.post('/addresses', authenticateToken, async (req, res) => {
  const { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } = req.body;
  const userId = req.user.userId;

  try {
    // First, unset the default flag on all addresses if the new address is marked as default
    if (isDefault) {
      await User.updateOne(
        { _id: userId },
        { $set: { "addresses.$[].isDefault": false } }  // Unset default on all addresses
      );
    }

    // Then, add the new address
    const updateResult = await User.updateOne(
      { _id: userId },
      { $push: { addresses: { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } } }
    );

    // Check if the update was successful
    if (updateResult.nModified === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Fetch and return the updated list of addresses
    const user = await User.findById(userId);
    res.status(200).json(user.addresses);
  } catch (err) {
    console.error('Error updating addresses:', err);
    res.status(500).json({ message: err.message });
  }
});

router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    // Ensure that only necessary data is fetched
    const user = await User.findById(req.user.userId).select('addresses -_id').lean();  // Adding lean() for faster performance
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user.addresses);
  } catch (err) {
    console.error('Error retrieving addresses:', err);
    res.status(500).json({ message: 'Server error retrieving addresses' });
  }
});

router.delete('/addresses/:addressId', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const addressId = req.params.addressId;

  try {
    // Ensure the addressId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(addressId)) {
      return res.status(400).json({ message: 'Invalid address ID' });
    }

    // Convert string ID to ObjectId
    const objectId = new mongoose.Types.ObjectId(addressId);

    // Use the $pull operator to remove the address from the addresses array
    const updateResult = await User.updateOne(
      { _id: userId },
      { $pull: { addresses: { _id: objectId } } }
    );

    if (updateResult.nModified === 0) {
      return res.status(404).json({ message: 'Address not found or user not found' });
    }

    // Fetch and return the updated list of addresses
    const user = await User.findById(userId);
    res.status(200).json(user.addresses);
  } catch (err) {
    console.error('Error deleting address:', err);
    res.status(500).json({ message: err.message });
  }
});

router.put('/addresses/:addressId', authenticateToken, async (req, res) => {
  const { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } = req.body;
  const userId = req.user.userId;
  const addressId = req.params.addressId;

  try {
    // Ensure the addressId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(addressId)) {
      return res.status(400).json({ message: 'Invalid address ID' });
    }

    const updateData = {
      'addresses.$.label': label,
      'addresses.$.firstName': firstName,
      'addresses.$.lastName': lastName,
      'addresses.$.flat': flat,
      'addresses.$.street': street,
      'addresses.$.city': city,
      'addresses.$.state': state,
      'addresses.$.zip': zip,
      'addresses.$.country': country,
      'addresses.$.phoneNumber': phoneNumber,
      'addresses.$.isDefault': isDefault
    };

    // Unset all defaults if necessary
    if (isDefault) {
      await User.updateMany(
        { _id: userId, 'addresses.isDefault': true },
        { $set: { 'addresses.$[].isDefault': false } }
      );
    }

    // Update the specific address
    const result = await User.updateOne(
      { _id: userId, 'addresses._id': addressId },
      { $set: updateData }
    );

    if (result.nModified === 0) {
      return res.status(404).json({ message: 'Address not found or no update needed' });
    }

    // Fetch and return the updated addresses
    const user = await User.findById(userId).select('addresses');
    res.status(200).json(user.addresses);
  } catch (err) {
    console.error('Error updating address:', err);
    res.status(500).json({ message: err.message });
  }
});


module.exports = {
  router,
  authenticateToken
};
