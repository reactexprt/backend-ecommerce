const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const User = require('../models/User');
const { authenticateToken } = require('./userRoutes');

// Fetch the cart items from the database
router.get('/', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('cart.productId');
    res.json(user.cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Save or update the cart in the database
router.post('/', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const { productId, quantity } = req.body;
    const objectId = new mongoose.Types.ObjectId(productId); // Properly create a new ObjectId
    const existingItem = user.cart.find(item => item.productId.equals(objectId));

    if (existingItem) {
      existingItem.quantity += quantity;
    } else {
      user.cart.push({ productId: objectId, quantity });
    }
    await user.save();
    const updatedUser = await User.findById(req.user.userId).populate('cart.productId'); // Populate after save
    res.status(201).json(updatedUser.cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Update cart item quantity
router.put('/:productId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const { productId } = req.params;
    const objectId = new mongoose.Types.ObjectId(productId); // Properly create a new ObjectId
    const { quantity } = req.body;

    const cartItem = user.cart.find(item => item.productId.equals(objectId));
    if (cartItem) {
      cartItem.quantity = quantity;
      await user.save();
      const updatedUser = await User.findById(req.user.userId).populate('cart.productId'); // Populate after save
      res.json(updatedUser.cart);
    } else {
      res.status(404).json({ message: 'Item not found in cart' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Remove from cart
router.delete('/:productId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const objectId = new mongoose.Types.ObjectId(req.params.productId); // Properly create a new ObjectId
    user.cart = user.cart.filter(item => !item.productId.equals(objectId));
    await user.save();
    const updatedUser = await User.findById(req.user.userId).populate('cart.productId'); // Populate after save
    res.json(updatedUser.cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
