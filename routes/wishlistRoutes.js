// routes/wishlist.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Product = require('../models/Product'); // Assuming you have a Product model
const { router: userRoutes, authenticateToken } = require('./userRoutes');

// Add a product to the wishlist
router.post('/add', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;

        // Find the product by ID
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Find the user and update their wishlist
        const user = await User.findById(req.user.userId);
        if (user.wishlist.includes(productId)) {
            return res.status(400).json({ message: 'Product already in wishlist' });
        }

        user.wishlist.push(productId);
        await user.save();

        res.status(200).json({ message: 'Product added to wishlist', wishlist: user.wishlist });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

router.get('/', authenticateToken, async (req, res) => {
    try {
        // Populate the wishlist array with product details
        const user = await User.findById(req.user.userId).populate({
            path: 'wishlist',
            model: 'Product',
            select: 'name price images'
        });

        res.status(200).json(user.wishlist);
    } catch (error) {
        console.error('Error fetching wishlist:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Remove a product from the wishlist
router.post('/remove', authenticateToken, async (req, res) => {
    try {
      const { productId } = req.body;
  
      const user = await User.findById(req.user.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Remove the product from the wishlist
      user.wishlist = user.wishlist.filter(id => id.toString() !== productId);
      await user.save();
  
      res.status(200).json({ message: 'Product removed from wishlist', wishlist: user.wishlist });
    } catch (error) {
      console.error('Error removing product from wishlist:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

module.exports = router;
