const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const { authenticateToken } = require('./userRoutes');


// Example of ensuring a cart exists whenever needed
router.get('/', authenticateToken, async (req, res) => {
  try {
    // Optimize the query by projecting only the necessary fields
    let cart = await Cart.findOne({ user: req.user.userId })
      .populate('items.productId', 'name price images discountPrice') // Populate only necessary fields
      .exec();

    if (!cart) {
      // Initialize a new empty cart if none found
      cart = new Cart({ user: req.user.userId, items: [] });
      await cart.save(); // Optionally save the new empty cart to the database
      return res.status(200).json(cart.items); // Return an empty cart with a 200 status
    }

    res.status(200).json(cart.items); // Return the cart items with a 200 status
  } catch (err) {
    console.error('Error fetching cart:', err);
    res.status(500).json({ message: 'Error fetching cart' }); // Improved error message for better clarity
  }
});

// Update and save cart
router.post('/', authenticateToken, async (req, res) => {
  const { userId } = req.user;
  const { productId, quantity } = req.body;
  if (!productId || !quantity || quantity <= 0) {
    return res.status(400).json({ message: 'Product ID and a positive quantity are required.' });
  }

  try {
    // Use transactions for ensuring consistency in concurrent scenarios
    const session = await Cart.startSession();
    session.startTransaction();
    // Find the cart with the specific item
    let cart = await Cart.findOne({ user: userId }).session(session);
    if (!cart) {
      // If no cart exists, create one
      cart = new Cart({ user: userId, items: [] });
    }
    const existingItemIndex = cart.items.findIndex(item => item.productId.equals(productId));
    if (existingItemIndex !== -1) {
      // If item exists, increment its quantity
      cart.items[existingItemIndex].quantity += quantity;
    } else {
      // If item does not exist, add it to the cart
      cart.items.push({ productId, quantity });
    }
    // Save the updated cart with session to ensure atomicity
    await cart.save({ session });
    // Commit the transaction to finalize changes
    await session.commitTransaction();
    session.endSession();
    // Populate the cart items with necessary fields from product
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId', 'name price images discountPrice');
    res.status(201).json(updatedCart.items);
  } catch (err) {
    console.error('Error updating cart:', err);
    // If an error occurs during the transaction, abort it
    if (session && session.inTransaction()) {
      await session.abortTransaction();
      session.endSession();
    }
    res.status(500).json({ message: 'Error updating cart' });
  }
});

// Update cart item quantity
router.put('/:productId', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const userId = req.user.userId;
    const productId = new mongoose.Types.ObjectId(req.params.productId);
    const { quantity } = req.body;

    if (!quantity || quantity <= 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Quantity must be a positive number' });
    }

    // Ensure there are no ongoing transactions before proceeding
    const cart = await Cart.findOne({ user: userId }).session(session);
    if (!cart) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Cart not found' });
    }

    const itemIndex = cart.items.findIndex(item => item.productId.equals(productId));
    if (itemIndex === -1) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Item not found in cart' });
    }

    cart.items[itemIndex].quantity = quantity;
    await cart.save({ session });

    await session.commitTransaction();
    session.endSession();

    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId', 'name price images discountPrice');
    res.status(200).json(updatedCart.items);

  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    console.error('Error updating cart item quantity:', err);
    res.status(500).json({ message: 'Error updating cart item quantity' });
  }
});

// Remove from cart
router.delete('/:productId', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const userId = req.user.userId;
    const productId = req.params.productId;

    // Validate productId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Invalid product ID' });
    }

    const objectId = new mongoose.Types.ObjectId(productId); // Convert string to ObjectId

    // Use the $pull operator to directly remove the item from the array
    const updateResult = await Cart.updateOne(
      { user: userId },
      { $pull: { items: { productId: objectId } } },
      { session } // Ensure this operation is part of the transaction
    );

    if (updateResult.modifiedCount === 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Cart not found or item not found in cart' });
    }

    // Fetch the updated cart within the same session to ensure consistency
    const updatedCart = await Cart.findOne({ user: userId }).populate('items.productId', 'name price images discountPrice').session(session);

    await session.commitTransaction();
    session.endSession();

    res.status(200).json(updatedCart.items);
  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
      session.endSession();
    }
    console.error('Error deleting cart item:', err);
    res.status(500).json({ message: 'Error deleting cart item' });
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
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const cart = await Cart.findOne({ user: req.user.userId }).session(session);

    if (!cart) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Cart not found' });
    }

    cart.items = []; // Clear all items from the cart
    await cart.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.status(200).json({ message: 'Cart cleared successfully' });
  } catch (err) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    res.status(500).json({ message: 'Error clearing cart', error: err.message });
  }
});


module.exports = router;
