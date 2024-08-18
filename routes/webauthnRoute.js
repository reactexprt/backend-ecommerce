const express = require('express');
const router = express.Router();
const { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const base64url = require('base64url');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { window } = new JSDOM('');
const purify = DOMPurify(window);

dotenv.config();

// Route to get registration options
router.post('/registration-options', async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Convert userID to a Buffer
      const userIDBuffer = Buffer.from(user._id.toString(), 'utf-8');
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
  
      // Store the generated challenge in the user's session or database
      user.currentChallenge = options.challenge;
      await user.save();
  
      res.json(options);
    } catch (err) {
      console.error('Error generating registration options:', err);
      res.status(500).json({ message: 'Error generating registration options' });
    }
});

// Route to verify registration response
router.post('/register', async (req, res) => {
  const { email, credential } = req.body;

  const sanitizedEmail = purify.sanitize(email);

  try {
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN,
      expectedRPID: process.env.WEBAUTHN_RPID,
    });

    if (!verification.verified) {
      return res.status(400).json({ message: 'Registration verification failed' });
    }

    const publicKeyBase64 = base64url.encode(Buffer.from(verification.registrationInfo.credentialPublicKey));

    // Save the credential to the user's account
    user.webauthnCredentials.push({
      credentialID: verification.registrationInfo.credentialID,
      publicKey: publicKeyBase64,
      counter: verification.registrationInfo.counter,
    });

    // Enable biometric login
    user.biometricEnabled = true;
    // Clear the challenge
    user.currentChallenge = undefined;
    await user.save();
    // Set a long-lived, secure, HttpOnly cookie for the user's email (5 years)
    res.cookie('userEmail', sanitizedEmail, {
      domain: '.himalayanrasa.com',
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production', // Ensure this is true in production
      sameSite: 'Strict',
      maxAge: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years in milliseconds
    });

    res.status(200).json({ message: 'Biometric registration successful' });
  } catch (err) {
    console.error('Error during registration verification:', err);
    res.status(500).json({ message: 'Error during registration verification' });
  }
});

// Route to get authentication options
router.post('/authentication-options', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const options = await generateAuthenticationOptions({
        allowCredentials: user.webauthnCredentials.map(cred => ({
          id: cred.credentialID,
          type: 'public-key',
          transports: ['usb', 'ble', 'nfc', 'internal'],
        })),
        userVerification: 'preferred',
    });
  
    // Store the generated challenge in the user's session or database
    user.currentChallenge = options.challenge;
    await user.save();

    res.json(options);
  } catch (err) {
    console.error('Error generating authentication options:', err);
    res.status(500).json({ message: 'Error generating authentication options' });
  }
});

// Route to verify authentication response
router.post('/verify-authentication', async (req, res) => {
    const { email, credential } = req.body;
  
    try {
      const user = await User.findOne({ email }); //email: decodeURIComponent(email).trim()
      if (!user) {
        console.log('User not found for email:', email);
        return res.status(404).json({ message: 'User not found' });
      }
  
      const authenticator = user.webauthnCredentials.find(cred => cred.credentialID === credential.id);
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
        console.log('Authentication verification failed');
        return res.status(400).json({ message: 'Authentication failed' });
      }
  
      user.currentChallenge = undefined;
  
      // Proceed with issuing a JWT or session
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
  
      res.json({ token, refreshToken, userId: user._id });
    } catch (err) {
      console.error('Error verifying authentication response:', err);
      res.status(500).json({ message: 'Error verifying authentication response' });
    }
});
  

module.exports = router;
