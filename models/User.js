const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const cartItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 1,
    default: 1
  }
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
  cart: [cartItemSchema],
  resetPasswordOTP: { type: String },
  resetPasswordExpires: { type: Date },
}, { timestamps: true });

// Hash password before saving the user
userSchema.pre('save', async function (next) {
  // // Only hash the password if it has been modified (or is new)
  // if (this.isModified('password')) {
  //   try {
  //     const salt = await bcrypt.genSalt(10);
  //     this.password = await bcrypt.hash(this.password, salt);
  //     console.log('Hashed again', this.password)
  //   } catch (error) {
  //     return next(error);
  //   }
  // }
  next();
});

module.exports = mongoose.model('User', userSchema, 'User');
