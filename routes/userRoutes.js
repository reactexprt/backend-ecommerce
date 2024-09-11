const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
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

// Apply rate limiting to prevent brute force attacks
const tokenRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Rate limiter middleware to prevent abuse of the login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: 'Too many login attempts from this IP, please try again later'
});

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
router.post('/register', loginLimiter, [
  check('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  check('email').isEmail().withMessage('Please enter a valid email'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email, username, password } = req.body;

    // Check if the email is already in use
    const existingEmail = await User.findOne({ email }).select('_id').session(session).exec();
    if (existingEmail) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Email already in use' });
    }

    // Check if the username is already in use
    const existingUsername = await User.findOne({ username }).select('_id').session(session).exec();
    if (existingUsername) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Username already in use. Please choose a different one.' });
    }

    // Hash the password and save the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save({ session });

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    // Rollback the transaction in case of error
    await session.abortTransaction();
    session.endSession();
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

router.post('/login', loginLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      throw new Error('Email and password must be provided');
    }

    // Use findOneAndUpdate to authenticate and update the refreshToken in one step
    const user = await User.findOne({ email }).select('email password refreshToken biometricEnabled').session(session).exec();

    if (!user) {
      throw new Error('Email not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Incorrect password');
    }

    // Generate tokens
    const { token, refreshToken } = generateTokens(user);

    // Update the user's refreshToken within the session
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { refreshToken } },
      { session, new: true }
    );

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();

    // Set the refresh token in an HTTP-only, Secure cookie
    res.cookie('refreshToken', refreshToken, {
      domain: '.himalayanrasa.com',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure secure cookies in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    if (user.biometricEnabled) {
      const sanitizedEmail = purify.sanitize(email.trim());
      res.cookie('userEmail', sanitizedEmail, {
        domain: '.himalayanrasa.com',
        httpOnly: false, // Allow access by client-side JavaScript
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 5 * 365 * 24 * 60 * 60 * 1000 // 5 years
      });
    }

    res.status(200).json({ token, userId: user._id });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Login error:', error.message);
    res.status(400).json({ message: error.message });
  }
});

router.post('/token', tokenRateLimiter, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token is required.' });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Verify the current refresh token
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Find the user with the provided refresh token
    let user = await User.findOne({ _id: payload.userId, refreshToken: refreshToken })
      .session(session)
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ message: 'Invalid refresh token.' });
    }

    // Check if refresh token reuse is detected
    if (user.refreshToken !== refreshToken) {
      // Log out the user across all sessions
      await User.updateOne({ _id: user._id }, { refreshToken: null }); // Clear refresh token
      await session.commitTransaction();
      session.endSession();
      return res.status(403).json({ message: 'Refresh token reuse detected. You have been logged out.' });
    }

    // Check if the refresh token has expired
    const tokenExpirationDate = new Date(payload.exp * 1000);
    const currentDate = new Date();
    const expirationThreshold = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

    let newRefreshToken = refreshToken;

    if (tokenExpirationDate - currentDate <= expirationThreshold) {
      // Generate a new refresh token if the old one is about to expire
      newRefreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      // Update the refresh token in the database
      user = await User.findOneAndUpdate(
        { _id: user._id },
        { $set: { refreshToken: newRefreshToken } },
        { new: true, session }  // Include session for transaction
      ).exec();
    }

    // Create a new access token
    const newAccessToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();

    // Set the refresh token in an HTTP-only, Secure cookie
    res.cookie('refreshToken', newRefreshToken, {
      domain: '.himalayanrasa.com',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure secure cookies in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Send the new access token to the client
    res.status(200).json({ accessToken: newAccessToken, userId: user._id });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();

    if (err instanceof jwt.TokenExpiredError) {
      return res.status(403).json({ message: 'Expired refresh token.' });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res.status(403).json({ message: 'Invalid refresh token.' });
    }
    console.error('Error during token refresh:', err);
    return res.status(500).json({ message: 'Server error during token refresh.' });
  }
});

router.post('/logout', tokenRateLimiter, authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Unset the refresh token within the transaction
    const result = await User.updateOne(
      { _id: userId }, 
      { $unset: { refreshToken: "" } },
      { session }
    );

    if (result.nModified === 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    await session.commitTransaction();
    session.endSession();

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
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

// PUT: Update User Profile
router.put('/profile', authenticateToken, async (req, res) => {
  const { username } = req.body;
  const userId = req.user.userId;

  try {
    // Update the username directly
    const user = await User.findByIdAndUpdate(
      userId,
      { username },  // Update only the username field
      { new: true, runValidators: true, select: 'username' }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Username updated successfully', username: user.username });
  } catch (err) {
    console.error('Error updating username:', err);
    res.status(500).json({ message: 'Server error updating username' });
  }
});


router.get('/user-details', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -refreshToken -resetPasswordOTP -resetPasswordExpires -webauthnCredentials');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.status(200).json({ user });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Server error' });
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

router.get('/biometric-status', tokenRateLimiter, async (req, res) => {
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



// ---------------- Reset, Change password and verify otp -------------
// Verify OTP and reset password
// Rate limiter middleware to prevent brute-force attacks
// Apply rate limiting to the password change route
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many password change attempts, please try again later.'
});

router.post('/verify-otp', changePasswordLimiter, [
  check('email').isEmail().withMessage('Please enter a valid email'),
  check('otp').isLength({ min: 6 }).withMessage('OTP must be 6 characters long'),
  check('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, otp, newPassword } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Optimize query by using indexed fields and project only needed fields
    const user = await User.findOne({ email, resetPasswordOTP: otp, resetPasswordExpires: { $gt: Date.now() } })
      .select('password')
      .session(session)  // Use session for transaction
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Invalid OTP, expired, or no user found with this email' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordExpires = undefined;
    await user.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error resetting password:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Reset Password
router.post('/request-reset-password', changePasswordLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Optimize by selecting only necessary fields
    const user = await User.findOne({ email }).select('email resetPasswordOTP resetPasswordExpires').session(session).lean();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
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
      }, { session });

      // Prepare the email with the new OTP
      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is ${otp}`
      };

      try {
        await sendMail(mailOptions);
      } catch (error) {
        await session.abortTransaction();
        session.endSession();
        console.error('Error sending email:', error);
        return res.status(500).json({ message: 'Error sending email' });
      }
    } else {
      await session.commitTransaction();
      session.endSession();
      return res.status(200).json({ message: 'OTP is still valid. Please check your email.' });
    }

    await session.commitTransaction();
    session.endSession();
    res.status(200).json({ message: 'OTP sent to email' });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error handling reset password request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

router.post('/change-password', authenticateToken, changePasswordLimiter, [
  check('oldPassword').isLength({ min: 6 }).withMessage('Old password is required'),
  check('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { oldPassword, newPassword } = req.body;
  const userId = req.user.userId;

  try {
    // Fetch the user with the current password
    const user = await User.findById(userId).select('password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Compare the old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect old password' });
    }

    // Check if the new password is different from the old one
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: 'New password must be different from the old password' });
    }

    // Hash the new password and update it
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ message: 'Error changing password' });
  }
});



// ---------- Address Management Routes ------------------

router.post('/addresses', authenticateToken, async (req, res) => {
  const { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } = req.body;
  const userId = req.user.userId;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Unset the default flag on all addresses if the new address is marked as default
    if (isDefault) {
      await User.updateOne(
        { _id: userId },
        { $set: { "addresses.$[].isDefault": false } },
        { session }
      );
    }

    // Add the new address
    const updateResult = await User.updateOne(
      { _id: userId },
      { $push: { addresses: { label, firstName, lastName, flat, street, city, state, zip, country, phoneNumber, isDefault } } },
      { session }
    );

    // Check if the update was successful
    if (updateResult.matchedCount === 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    await session.commitTransaction();
    session.endSession();

    // Fetch and return the updated list of addresses
    const user = await User.findById(userId);
    res.status(200).json(user.addresses);

  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    console.error('Error updating addresses:', err);
    res.status(500).json({ message: err.message });
  }
});


router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    // Fetch only the necessary data, lean() for better performance
    const user = await User.findById(req.user.userId)
      .select('addresses -_id')
      .lean();

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

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Use the $pull operator to remove the address from the addresses array
      const updateResult = await User.updateOne(
        { _id: userId },
        { $pull: { addresses: { _id: objectId } } },
        { session }
      );

      if (updateResult.nModified === 0) {
        await session.abortTransaction();
        session.endSession();
        return res.status(404).json({ message: 'Address not found or user not found' });
      }

      await session.commitTransaction();
      session.endSession();

      // Fetch and return the updated list of addresses
      const user = await User.findById(userId).select('addresses -_id').lean();
      res.status(200).json(user.addresses);

    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      console.error('Error deleting address:', err);
      res.status(500).json({ message: 'Error deleting address', error: err.message });
    }
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'Error processing request', error: err.message });
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

    const session = await mongoose.startSession();
    session.startTransaction();

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

    try {
      // Unset all other default flags if necessary
      if (isDefault) {
        await User.updateMany(
          { _id: userId, 'addresses.isDefault': true },
          { $set: { 'addresses.$[].isDefault': false } },
          { session }
        );
      }

      // Update the specific address
      const result = await User.updateOne(
        { _id: userId, 'addresses._id': addressId },
        { $set: updateData },
        { session }
      );

      if (result.nModified === 0) {
        await session.abortTransaction();
        session.endSession();
        return res.status(404).json({ message: 'Address not found or no update needed' });
      }

      await session.commitTransaction();
      session.endSession();

      // Fetch and return the updated addresses
      const user = await User.findById(userId).select('addresses').lean();
      res.status(200).json(user.addresses);
    } catch (err) {
      await session.abortTransaction();
      session.endSession();
      console.error('Error updating address:', err);
      res.status(500).json({ message: 'Error updating address', error: err.message });
    }
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'Error processing request', error: err.message });
  }
});


module.exports = {
  router,
  authenticateToken
};
