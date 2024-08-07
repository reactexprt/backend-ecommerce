const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const { router: userRoutes, authenticateToken } = require('./userRoutes');

// Get all products
router.get('/', authenticateToken, async (req, res, next) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    next(err);
  }
});

// Get a single product by ID
router.get('/:id', authenticateToken, async (req, res, next) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json(product);
  } catch (err) {
    next(err);
  }
});

// Add a new product (Admin only)
router.post('/', async (req, res, next) => {
  try {
    // Assume req.user.isAdmin is set after authentication middleware
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }
    const product = new Product(req.body);
    const newProduct = await product.save();
    res.status(201).json(newProduct);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
