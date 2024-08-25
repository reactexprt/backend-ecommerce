const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const WebAuthnCredentialSchema = new mongoose.Schema({
  credentialID: String,
  publicKey: String,
  counter: Number,
});

const addressSchema = new mongoose.Schema({
  label: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  flat: { type: String, required: true },
  street: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  zip: { type: String, required: true },
  country: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  isDefault: { type: Boolean, default: false },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    match: [/.+@.+\..+/, 'Please enter a valid email address'] 
  },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  biometricEnabled: { type: Boolean, default: false },
  currentChallenge: { type: String },
  addresses: [addressSchema],
  refreshToken: { type: String },
  resetPasswordOTP: { type: String },
  resetPasswordExpires: { type: Date },
  webauthnCredentials: [WebAuthnCredentialSchema],
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  next();
});

module.exports = mongoose.model('User', userSchema);
