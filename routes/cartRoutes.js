const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const { authenticateToken } = require('./userRoutes');

// A utility function to check if a string is a valid ObjectId
function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id) && new mongoose.Types.ObjectId(id).toString() === id;
}

// Fetch the cart items from the database
// Example of ensuring a cart exists whenever needed
router.get('/', authenticateToken, async (req, res) => {
  try {
    let cart = await Cart.findOne({ user: req.user.userId }).populate('items.productId');
    if (!cart) {
      // Initialize a new empty cart if none found
      cart = new Cart({ user: req.user.userId, items: [] });
      await cart.save();  // Optionally save the new empty cart
      return res.json(cart.items);  // Return an empty cart
    }
    res.json(cart.items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Save or update the cart in the database
router.post('/', authenticateToken, async (req, res) => {
  const { userId } = req.user;
  const { productId, quantity } = req.body;

  try {
    const update = {
      $addToSet: {
        items: {
          $each: [{ productId, quantity }],
          $not: { productId }
        }
      }
    };

    // Find item first to decide if we need to $addToSet or $inc
    let cart = await Cart.findOne({ user: userId, "items.productId": productId });

    if (cart && cart.items.some(item => item.productId.equals(productId))) {
      // If item exists, increment its quantity
      update.$inc = { "items.$.quantity": quantity };
      delete update.$addToSet;
    }

    await Cart.updateOne({ user: userId }, update, { upsert: true });
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId');
    res.status(201).json(updatedCart.items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Update cart item quantity
router.put('/:productId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const productId = new mongoose.Types.ObjectId(req.params.productId); // Ensure proper ObjectId conversion
    const { quantity } = req.body;

    // Use the $set operator to directly update the item quantity in the array
    const updateResult = await Cart.updateOne(
      { user: userId, 'items.productId': productId },
      { $set: { 'items.$.quantity': quantity } }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({ message: 'Cart or item not found' });
    }

    // Fetch the updated cart to return to the client
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId');
    res.json(updatedCart.items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Remove from cart
router.delete('/:productId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const productId = req.params.productId;

    // Validate productId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ message: 'Invalid product ID' });
    }

    const objectId = new mongoose.Types.ObjectId(productId); // Convert string to ObjectId

    // Use the $pull operator to directly remove the item from the array
    const updateResult = await Cart.updateOne(
      { user: userId },
      { $pull: { items: { productId: objectId } } }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(404).json({ message: 'Cart not found or item not found in cart' });
    }

    // Fetch the updated cart to return to the client
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId');
    res.json(updatedCart.items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Merge the local products to server
router.post('/merge', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const localItems = req.body.items;

  try {
    // Initialize bulk operations array
    const bulkOps = [];

    // Check for existing cart or create a new one if it doesn't exist
    let cart = await Cart.findOne({ user: userId });
    if (!cart) {
      cart = new Cart({ user: userId, items: [] });
      await cart.save();
    }

    // Iterate over each local item to determine the operation
    for (const item of localItems) {
      const productId = new mongoose.Types.ObjectId(item.productId._id);  // Convert to ObjectId
      const existingItem = cart.items.find(ci => ci.productId.equals(productId));

      if (existingItem) {
        // Prepare to increment the quantity of an existing item
        bulkOps.push({
          updateOne: {
            filter: { user: userId, 'items.productId': productId },
            update: { $inc: { 'items.$.quantity': item.quantity } }
          }
        });
      } else {
        // Prepare to add a new item if it doesn't exist
        bulkOps.push({
          updateOne: {
            filter: { user: userId },
            update: { $push: { items: { productId: productId, quantity: item.quantity } } }
          }
        });
      }
    }
    // Perform the bulk write operation
    if (bulkOps.length > 0) {
      await Cart.bulkWrite(bulkOps, { ordered: false });
    }

    // Fetch and return the updated cart
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId');
    res.status(201).json(updatedCart.items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Clear the cart
router.post('/clear', authenticateToken, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.userId });
    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }
    cart.items = []; // Clear all items from the cart
    await cart.save();
    res.status(200).json({ message: 'Cart cleared successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error clearing cart', error: err.message });
  }
});

module.exports = router;
