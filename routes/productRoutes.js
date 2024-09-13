const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
const multer = require('multer');
const expressSanitizer = require('express-sanitizer');
const path = require('path');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const User = require('../models/User');
const Product = require('../models/Product');
const Synonym = require('../models/Synonym');
const { router: userRoutes, authenticateToken } = require('./userRoutes');
const NodeCache = require('node-cache');
const productCache = new NodeCache({ stdTTL: 3600, checkperiod: 120 }); // Cache TTL set to 1 hour, check every 2 minutes

dotenv.config();

// Initialize S3 Client
const s3 = new S3Client({
  region: 'ap-south-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
  },
});

// Multer setup for file uploads with memory storage
const storage = multer.memoryStorage();
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

const uploadToS3 = async (file, category, productName) => {
  const params = {
    Bucket: 'himalayanrasa-product-images', // Replace with your bucket name
    Key: `uploads/Products/${category}/${productName}/${Date.now()}-${file.originalname}`, // File path in S3
    Body: file.buffer,
    ContentType: file.mimetype,
    // ACL: 'public-read' // Remove this line since ACLs are not allowed
  };

  try {
    const command = new PutObjectCommand(params);
    const data = await s3.send(command);
    return { Location: `https://${params.Bucket}.s3.${await s3.config.region()}.amazonaws.com/${params.Key}` };
  } catch (err) {
    console.error("Error uploading file to S3:", err);
    throw err;
  }
};

// Rate limiter middleware
const productLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 500, // Limit each IP to 30 requests per windowMs
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
      .select('name price description images discountPrice')
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
router.get('/:id', productLimiter, async (req, res, next) => {
  try {
    // Fetch the product from the database without checking the cache temporarily
    const product = await Product.findById(req.params.id)
      .populate('comments.userId', 'username') // Populate the username for comments
      .exec();

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Respond with the product including the updated averageRating
    res.json(product);
  } catch (err) {
    if (err instanceof mongoose.Error.CastError) {
      return res.status(400).json({ message: 'Invalid product ID' });
    }
    next(err);
  }
});

// POST route to add a comment
router.post('/:productId/comment', authenticateToken, async (req, res) => {
  try {
    const { productId } = req.params;
    const { comment, rating } = req.body;
    const userId = req.user.userId;

    const user = await User.findById(userId).select('username');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const username = user.username;

    // Add the comment and rating to the product's comments array
    const updatedProduct = await Product.findByIdAndUpdate(
      productId,
      { $push: { comments: { userId, username, comment, rating } } },
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Recalculate the average rating using aggregation
    const productWithUpdatedAverage = await Product.aggregate([
      { $match: { _id: new mongoose.Types.ObjectId(productId) } },
      { $unwind: "$comments" }, // Unwind comments array
      {
        $group: {
          _id: "$_id",
          averageRating: { $avg: "$comments.rating" } // Calculate average rating
        }
      }
    ]);

    const averageRating = productWithUpdatedAverage.length ? productWithUpdatedAverage[0].averageRating : 0;

    // Update the product's average rating
    await Product.findByIdAndUpdate(productId, { averageRating: averageRating.toFixed(1) });

    // Fetch the updated product to return in the response
    const finalUpdatedProduct = await Product.findById(productId);

    res.status(201).json({ message: 'Comment and rating added successfully', product: finalUpdatedProduct });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error adding comment and rating', error });
  }
});

// Route to fetch related products based on category or other criteria
router.post('/related', authenticateToken, async (req, res) => {
  const { productIds } = req.body; // Array of product IDs to find similar products
  try {
    // Fetch products with similar categories (or tags or attributes)
    const originalProducts = await Product.find({ _id: { $in: productIds } });

    if (originalProducts.length === 0) {
      return res.status(404).json({ message: 'Products not found' });
    }

    // Collect the categories or tags of the original products
    const categories = originalProducts.map(product => product.category);

    // Find other products in the same category but exclude the original products
    const relatedProducts = await Product.find({
      category: { $in: categories },
      _id: { $nin: productIds } // Exclude the original products
    }).limit(5); // Limit to a certain number of related products

    res.status(200).json({ products: relatedProducts });
  } catch (error) {
    console.error('Error fetching related products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new product or update one (Admin only)
router.post(
  '/',
  [
    upload.array('images', 10), // Allow up to 10 images
    check('name').not().isEmpty().withMessage('Product name is required'),
    check('price').isFloat({ gt: 0 }).withMessage('Price must be greater than 0'),
    check('description').not().isEmpty().withMessage('Description is required'),
    check('category').not().isEmpty().withMessage('Category is required'),
    check('shop').not().isEmpty().withMessage('Shop is required'), // Ensure shop ID is provided
    check('synonyms').optional().isString().withMessage('Synonyms must be a comma-separated string') // Validate synonyms
  ],
  authenticateToken,
  productLimiter, // Apply rate limiting middleware for heavy traffic
  async (req, res) => {
    try {
      // Check if the user is an admin
      const user = await User.findById(req.user.userId).select('email isAdmin -_id').lean();
      const errors = validationResult(req);
      if (!errors.isEmpty() || !user.isAdmin) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Sanitize incoming product data
      const sanitizedData = {
        name: req.body.name.trim(),
        price: parseFloat(req.body.price),
        description: req.body.description.trim(),
        category: req.body.category.trim(),
        discountPrice: parseFloat(req.body.discountPrice),
        stock: parseInt(req.body.stock, 10),
        shop: req.body.shop.trim(), // Include shop reference from the request
      };

      const { synonyms } = req.body; // Extract synonyms from request body

      // Check if a product with the same name already exists
      let product = await Product.findOne({ name: sanitizedData.name }).exec();

      // Handle image uploads
      const imageUploadPromises = req.files.map(file =>
        uploadToS3(file, req.body.category.trim(), req.body.name.trim())
      );
      const uploadedImages = await Promise.all(imageUploadPromises);
      const imagePaths = uploadedImages.map(data => data.Location);

      if (product) {
        // Append new images if updating an existing product
        if (imagePaths.length > 0) {
          product.images = [...product.images, ...imagePaths];
        }

        // Update product details
        Object.assign(product, sanitizedData);

        // Save updated product
        const updatedProduct = await product.save();

        // Update synonyms if provided
        if (synonyms) {
          const synonymArray = synonyms.split(',').map(s => s.trim().toLowerCase());
          await Synonym.findOneAndUpdate(
            { baseTerm: sanitizedData.name.toLowerCase() },
            { $set: { synonyms: synonymArray } },
            { upsert: true, new: true }
          );
        }

        // Cache invalidation for updated product
        productCache.del('product_list');
        productCache.del(`product_${updatedProduct._id}`);

        return res.status(200).json({ message: 'Product updated successfully', product: updatedProduct });
      }

      // Create new product if not found
      const newProduct = new Product({
        ...sanitizedData,
        images: imagePaths,
      });

      // Save the new product
      const savedProduct = await newProduct.save();

      // Save synonyms if provided
      if (synonyms) {
        const synonymArray = synonyms.split(',').map(s => s.trim().toLowerCase());
        const synonymEntry = new Synonym({
          baseTerm: sanitizedData.name.toLowerCase(),
          synonyms: synonymArray,
        });
        await synonymEntry.save();
      }

      // Cache the new product and invalidate product list cache
      productCache.del('product_list');
      productCache.set(`product_${savedProduct._id}`, savedProduct);

      return res.status(201).json({ message: 'Product created successfully', product: savedProduct });
    } catch (err) {
      console.error('Error handling product:', err.message || err);
      return res.status(500).json({
        message: 'An error occurred while processing the product.',
        error: err.message || err,
      });
    }
  }
);

module.exports = router;
