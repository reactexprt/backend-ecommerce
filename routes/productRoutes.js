const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
const multer = require('multer');
const sharp = require('sharp');
const fs = require('fs');
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

const uploadToS3 = async (buffer, file, category, productName, fileName) => {
  const params = {
    Bucket: 'himalayanrasa-product-images', // Replace with your bucket name
    Key: `uploads/Products/${category}/${productName}/${Date.now()}-${fileName}.webp`, // Save as webp format
    Body: buffer,
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
      .select('name price description images discountPrice stock')
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
    // Conditionally validate required fields only for new products
    check('name').not().isEmpty().withMessage('Product name is required'),
    check('price').optional({ checkFalsy: true }).isFloat({ gt: 0 }).withMessage('Price must be greater than 0'),
    check('description').optional({ checkFalsy: true }).not().isEmpty().withMessage('Description is required'),
    check('category').optional({ checkFalsy: true }).not().isEmpty().withMessage('Category is required'),
    check('shop').optional({ checkFalsy: true }).not().isEmpty().withMessage('Shop is required'), // Ensure shop ID is provided
    check('length').optional({ checkFalsy: true }).isFloat({ gt: 0.5 }).withMessage('Length must be greater than 0.5 cm'),
    check('breadth').optional({ checkFalsy: true }).isFloat({ gt: 0.5 }).withMessage('Breadth must be greater than 0.5 cm'),
    check('height').optional({ checkFalsy: true }).isFloat({ gt: 0.5 }).withMessage('Height must be greater than 0.5 cm'),
    check('weight').optional({ checkFalsy: true }).isFloat({ gt: 0.1 }).withMessage('Weight must be greater than 0.1 kg'),
    check('synonyms').optional({ checkFalsy: true }).isString().withMessage('Synonyms must be a comma-separated string') // Validate synonyms
  ],
  authenticateToken,
  productLimiter, // Apply rate limiting middleware for heavy traffic
  async (req, res) => {
    try {
      // Check if the user is an admin
      const user = await User.findById(req.user.userId).select('email isAdmin -_id').lean();
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      if (!user.isAdmin) {
        return res.status(403).json({ message: 'Admin access required' });
      }


      // Extract the product name to check if it exists
      const productName = req.body.name ? req.body.name.trim() : null;

      // Find the product by name if provided
      let product = productName ? await Product.findOne({ name: productName }).exec() : null;

      // If the product exists, handle updates
      if (product) {
        // This is an existing product, so allow partial updates

        // Only update the fields that are provided in the request body
        if (req.body.price) product.price = parseFloat(req.body.price);
        if (req.body.description) product.description = req.body.description.trim();
        if (req.body.category) product.category = req.body.category.trim();
        if (req.body.discountPrice) product.discountPrice = parseFloat(req.body.discountPrice);
        if (req.body.stock) product.stock = parseInt(req.body.stock, 10);
        if (req.body.shop) product.shop = req.body.shop.trim();
        if (req.body.length) product.length = parseFloat(req.body.length);
        if (req.body.breadth) product.breadth = parseFloat(req.body.breadth);
        if (req.body.height) product.height = parseFloat(req.body.height);
        if (req.body.weight) product.weight = parseFloat(req.body.weight);

        // Handle image uploads if any
        if (req.files && req.files.length > 0) {
          const imageUploadPromises = req.files.map(async (file) => {
            const compressedImageBuffer = await sharp(file.buffer)
              .webp({ quality: 80 })
              .toBuffer();
    
            const compressedFileName = `${file.originalname.split('.')[0]}`;
    
            // Upload the compressed image to S3
            const uploadResponse = await uploadToS3(compressedImageBuffer, file, req.body.category.trim(), req.body.name.trim(), compressedFileName);
    
            return uploadResponse.Location; // Return the S3 URL of the uploaded image
          });
    
          const uploadedImages = await Promise.all(imageUploadPromises);
          const imagePaths = uploadedImages.map(data => data); 
          product.images = [...product.images, ...imagePaths]; // Append new images to existing ones
        }

        // Update or add synonyms if provided
        if (req.body.synonyms) {
          const newSynonyms = req.body.synonyms.split(',').map(s => s.trim().toLowerCase());

          // Fetch existing synonyms from the database
          const existingSynonym = await Synonym.findOne({ baseTerm: product.name.toLowerCase() });

          if (existingSynonym) {
            // Merge new synonyms with existing ones (avoiding duplicates)
            const mergedSynonyms = [...new Set([...existingSynonym.synonyms, ...newSynonyms])];
            
            // Update the synonym document
            existingSynonym.synonyms = mergedSynonyms;
            await existingSynonym.save();
          } else {
            // Create a new synonym entry if it doesn't exist
            const synonymEntry = new Synonym({
              baseTerm: product.name.toLowerCase(),
              synonyms: newSynonyms,
            });
            await synonymEntry.save();
          }
        }

        // Save the updated product
        const updatedProduct = await product.save();

        // Cache invalidation for updated product
        productCache.del('product_list');
        productCache.del(`product_${updatedProduct._id}`);

        return res.status(200).json({ message: 'Product updated successfully', product: updatedProduct });
      }

      // If no product exists, this is a new product. Ensure all required fields are present.
      const requiredFields = ['name', 'price', 'description', 'category', 'shop', 'stock', 'synonyms', 'length', 'breadth', 'height', 'weight' ];
      const missingFields = requiredFields.filter(field => !req.body[field]);

      if (missingFields.length > 0) {
        return res.status(400).json({
          message: `Missing required fields: ${missingFields.join(', ')}`
        });
      }

      if (!req.files || req.files?.length === 0) {
        return res.status(400).json({ message: 'At least one image is required for a new product.' });
      }

      // Handle image uploads for new product
      const imageUploadPromises = req.files?.map(async (file) => {
        const compressedImageBuffer = await sharp(file.buffer)
          .webp({ quality: 80 })
          .toBuffer();

        const compressedFileName = `${file.originalname.split('.')[0]}`;

        // Upload the compressed image to S3
        const uploadResponse = await uploadToS3(compressedImageBuffer, file, req.body.category.trim(), req.body.name.trim(), compressedFileName);

        return uploadResponse.Location; // Return the S3 URL of the uploaded image
      });

      const uploadedImages = await Promise.all(imageUploadPromises);
      const imagePaths = uploadedImages.map(data => data);

      // Generate a SKU based on product name and a random number (or any other logic)
      const productNameForSKUKey = productName?.toUpperCase();
      const abbreviation = productNameForSKUKey?.substring(0, 4);
      const randomString = crypto.randomBytes(2).toString('hex').toUpperCase();
      const sku = `${abbreviation}-${randomString}`;

      // Sanitize and parse incoming product data after validation
      const sanitizedData = {
        name: req.body.name.trim(),
        price: parseFloat(req.body.price),
        description: req.body.description.trim(),
        category: req.body.category.trim(),
        discountPrice: req.body.discountPrice ? parseFloat(req.body.discountPrice) : null, // Optional field
        stock: req.body.stock ? parseInt(req.body.stock, 10) : 0, // Default to 0 if not provided
        length: req.body.length ? parseFloat(req.body.length) : null,
        breadth: req.body.breadth ? parseFloat(req.body.breadth) : null,
        height: req.body.height ? parseFloat(req.body.height) : null,
        weight: req.body.weight ? parseFloat(req.body.weight) : null,
        shop: req.body.shop.trim(),
        sku: sku
      };

      // Create new product if not found
      const newProduct = new Product({
        ...sanitizedData,
        images: imagePaths,
      });

      // Save the new product
      const savedProduct = await newProduct.save();

      // Save synonyms if provided
      if (req.body.synonyms) {
        const synonymArray = req.body.synonyms.split(',').map(s => s.trim().toLowerCase());
        const synonymEntry = new Synonym({
          baseTerm: savedProduct.name.toLowerCase(),
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
