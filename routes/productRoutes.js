const express = require('express');
const router = express.Router();
const fs = require('fs');
const multer = require('multer');
const expressSanitizer = require('express-sanitizer');
const path = require('path');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const User = require('../models/User');
const Product = require('../models/Product');
const { router: userRoutes, authenticateToken } = require('./userRoutes');
const NodeCache = require('node-cache');
const productCache = new NodeCache({ stdTTL: 3600, checkperiod: 120 }); // Cache TTL set to 1 hour, check every 2 minutes

// Multer setup for file uploads with file type validation
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const categoryDir = path.join(__dirname, '../uploads', req.body.category);
    const productDir = path.join(categoryDir, req.body.name);

    // Create the category directory if it doesn't exist
    if (!fs.existsSync(categoryDir)) {
      fs.mkdirSync(categoryDir);
    }

    // Create the product directory if it doesn't exist
    if (!fs.existsSync(productDir)) {
      fs.mkdirSync(productDir);
    }

    // Set the destination to the product directory
    cb(null, productDir);
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`); // Generate a unique filename
  }
});

const upload = multer({
  storage: storage,
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only .jpeg, .jpg, and .png files are allowed!'));
    }
  }
});

// Rate limiter middleware
const productLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 30, // Limit each IP to 30 requests per windowMs
  message: 'Too many requests from this IP, please try again after a minute'
});

// Use the sanitizer middleware before defining the routes
router.use(expressSanitizer());

// Get all products
router.get('/', async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1; // Get the current page from query or default to 1
    const limit = parseInt(req.query.limit) || 5; // Get the limit from query or default to 5

    const totalCount = await Product.countDocuments(); // Get the total count of products
    const products = await Product.find()
      .select('name price description images')
      .skip((page - 1) * limit) // Skip the records based on the current page and limit
      .limit(limit) // Limit the number of products returned
      .exec();

    const hasMore = (page * limit) < totalCount; // Determine if more products are available

    res.json({
      products,
      hasMore, // Return whether there are more products to load
      totalCount, // Optional: Return the total count if needed for frontend calculations
    });
  } catch (err) {
    console.error('Failed to fetch products:', err);
    next(err);
  }
});

// Get a single product by ID
router.get('/:id', authenticateToken, productLimiter, async (req, res, next) => {
  try {
    const cacheKey = `product_${req.params.id}`;

    // Try to get the product from the cache first
    const cachedProduct = productCache.get(cacheKey);
    if (cachedProduct) {
      return res.json(cachedProduct);
    }

    // Fetch the product from the database with lean() for better performance
    const product = await Product.findById(req.params.id).lean().exec();

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Store the fetched product in the cache
    productCache.set(cacheKey, product); // Cache with default TTL (1 hour)

    res.json(product);
  } catch (err) {
    // Handle specific errors, like invalid object IDs
    if (err instanceof mongoose.Error.CastError) {
      return res.status(400).json({ message: 'Invalid product ID' });
    }
    next(err);
  }
});


// Create a new product (Admin only)
router.post(
  '/',
  [
    upload.array('images', 10),
    check('name').not().isEmpty().withMessage('Product name is required'),
    check('price').isFloat({ gt: 0 }).withMessage('Price must be greater than 0'),
    check('description').not().isEmpty().withMessage('Description is required'),
    check('category').not().isEmpty().withMessage('Category is required'),
  ],
  authenticateToken,
  productLimiter,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user.userId).select('email isAdmin -_id').lean();  
      const errors = validationResult(req);
      if (!errors.isEmpty() || !user.isAdmin) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Since multer already handles file paths, we simply get the paths from req.files
      const imagePaths = req.files.map(file => {
        const relativePath = file.path.replace(path.join(__dirname, '../'), '');
        return `${req.protocol}://${req.get('host')}/${relativePath}`;
      });

      const sanitizedData = {
        name: req.body.name.trim(),
        price: parseFloat(req.body.price),
        description: req.body.description.trim(),
        category: req.body.category.trim(),
        images: imagePaths,
        stock: parseInt(req.body.stock, 10),
      };

      const product = new Product(sanitizedData);
      const newProduct = await product.save();

      // Invalidate relevant cache (e.g., product list cache)
      productCache.del('product_list');

      return res.status(201).json(newProduct);
    } catch (err) {
      console.error('Error creating product:', err.message || err);
      return res.status(500).json({ message: 'An error occurred while creating the product.', error: err.message || err });
    }
  }
);

module.exports = router;
