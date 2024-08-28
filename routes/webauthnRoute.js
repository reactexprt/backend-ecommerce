const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const base64url = require('base64url');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { window } = new JSDOM('');
const purify = DOMPurify(window);

dotenv.config();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 verification requests per windowMs
  message: 'Too many verification attempts from this IP, please try again later'
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit each IP to 50 registration requests per windowMs
  message: 'Too many registration attempts from this IP, please try again later'
});

// Route to get registration options
router.post('/registration-options', registerLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email } = req.body;

    if (!email) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Email is required' });
    }

    // Sanitize the email input to prevent injection attacks and ensure clean lookup
    const sanitizedEmail = email.trim();

    // Optimize query by using indexed fields and project only needed fields
    const user = await User.findOne({ email: sanitizedEmail })
      .select('_id email currentChallenge')
      .session(session)
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      console.log('User not found for email:', sanitizedEmail);
      return res.status(404).json({ message: 'User not found' });
    }

    // Convert userID to a Buffer
    const userIDBuffer = Buffer.from(user._id.toString(), 'utf-8');
    
    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName: 'Himalayan Rasa',
      rpID: process.env.WEBAUTHN_RPID,
      userID: userIDBuffer,
      userName: user.email,
      attestationType: 'direct',
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'discouraged',
      },
    });

    // Store the generated challenge in the user's document
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { currentChallenge: options.challenge } },
      { session, new: true }
    ).exec();

    await session.commitTransaction();
    session.endSession();

    res.status(200).json(options);
  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    console.error('Error generating registration options:', err);
    res.status(500).json({ message: 'Error generating registration options' });
  }
});

// Route to register user 
router.post('/register', registerLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email, credential } = req.body;

    if (!email || !credential) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Email and credential are required.' });
    }

    // Sanitize the email input
    const sanitizedEmail = purify.sanitize(email).trim();

    // Minimize the data fetched and ensure fields are indexed
    const user = await User.findOne({ email: sanitizedEmail })
      .select('currentChallenge webauthnCredentials biometricEnabled')
      .session(session)
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      console.log('User not found for email:', sanitizedEmail);
      return res.status(404).json({ message: 'User not found' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN,
      expectedRPID: process.env.WEBAUTHN_RPID,
    });

    if (!verification.verified) {
      await session.abortTransaction();
      session.endSession();
      console.log('Registration verification failed for user:', sanitizedEmail);
      return res.status(400).json({ message: 'Registration verification failed' });
    }

    const publicKeyBase64 = base64url.encode(Buffer.from(verification.registrationInfo.credentialPublicKey));

    // Efficiently update the user record
    const updatedUser = await User.findOneAndUpdate(
      { _id: user._id },
      {
        $push: {
          webauthnCredentials: {
            credentialID: verification.registrationInfo.credentialID,
            publicKey: publicKeyBase64,
            counter: verification.registrationInfo.counter,
          },
        },
        $set: {
          biometricEnabled: true,
          currentChallenge: undefined, // Clear the challenge
        },
      },
      { session, new: true }
    ).exec();

    if (!updatedUser) {
      await session.abortTransaction();
      session.endSession();
      console.log('Failed to update user after registration verification:', sanitizedEmail);
      return res.status(500).json({ message: 'Failed to update user after registration' });
    }

    await session.commitTransaction();
    session.endSession();

    // Send a secure cookie for the user's email
    res.cookie('userEmail', sanitizedEmail, {
      domain: '.himalayanrasa.com',
      httpOnly: false,  // Set to false because client-side JavaScript needs to access it; otherwise, use true for better security
      secure: process.env.NODE_ENV === 'production', // Ensure this is true in production
      sameSite: 'Strict',
      maxAge: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years in milliseconds
    });

    res.status(200).json({ message: 'Biometric registration successful' });
  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    console.error('Error during registration verification:', err);
    res.status(500).json({ message: 'Error during registration verification' });
  }
});

// Route to get authentication options
router.post('/authentication-options', authLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email } = req.body;

    if (!email) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Email is required' });
    }

    // Decode and trim the email to ensure a clean lookup and prevent errors
    const sanitizedEmail = decodeURIComponent(email).trim();

    // Optimize query by using indexed fields and project only needed fields
    const user = await User.findOne({ email: sanitizedEmail })
      .select('webauthnCredentials currentChallenge')
      .session(session)
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      console.log('User not found for email:', sanitizedEmail);
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate the authentication options
    const options = await generateAuthenticationOptions({
      allowCredentials: user.webauthnCredentials.map(cred => ({
        id: cred.credentialID,
        type: 'public-key',
        transports: cred.transports || ['usb', 'ble', 'nfc', 'internal'], // Use stored transports or default
      })),
      userVerification: 'preferred',
    });

    // Store the generated challenge in the user's document in the database
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { currentChallenge: options.challenge } },
      { session, new: true }
    ).exec();

    await session.commitTransaction();
    session.endSession();

    res.status(200).json(options);
  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    console.error('Error generating authentication options:', err);
    res.status(500).json({ message: 'Error generating authentication options' });
  }
});

// Route to verify authentication response
router.post('/verify-authentication', authLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email, credential } = req.body;

    if (!email || !credential) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Email and credential are required' });
    }

    // Decode and trim the email to prevent errors and ensure a clean lookup
    const sanitizedEmail = decodeURIComponent(email).trim();

    // Optimize query by using indexed fields and project only needed fields
    const user = await User.findOne({ email: sanitizedEmail })
      .select('webauthnCredentials currentChallenge refreshToken isAdmin')
      .session(session)
      .exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      console.log('User not found for email:', sanitizedEmail);
      return res.status(404).json({ message: 'User not found' });
    }

    const authenticator = user.webauthnCredentials.find(cred => cred.credentialID === credential.id);
    if (!authenticator) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Authenticator not found' });
    }
    const publicKeyBuffer = base64url.toBuffer(authenticator.publicKey);

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN,
      expectedRPID: process.env.WEBAUTHN_RPID,
      authenticator: {
        credentialPublicKey: publicKeyBuffer,
        counter: authenticator.counter,
      },
    });

    if (!verification.verified) {
      await session.abortTransaction();
      session.endSession();
      console.log('Authentication verification failed');
      return res.status(400).json({ message: 'Authentication failed' });
    }

    // Generate a new refresh token
    const newRefreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Update refresh token and clear the challenge atomically
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { refreshToken: newRefreshToken, currentChallenge: undefined } },
      { session, new: true }
    ).exec();

    await session.commitTransaction();
    session.endSession();

    // Issue a new JWT
    const token = jwt.sign(
      {
        userId: user._id,
        isAdmin: user.isAdmin
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Set the refresh token in an HTTP-only, Secure cookie
    res.cookie('refreshToken', newRefreshToken, {
      domain: '.himalayanrasa.com',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure secure cookies in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({ token, userId: user._id });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error verifying authentication response:', err);
    res.status(500).json({ message: 'Error verifying authentication response' });
  }
});

module.exports = router;
