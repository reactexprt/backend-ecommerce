const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const { check, validationResult } = require('express-validator');
const { router: userRoutes, authenticateToken } = require('./userRoutes');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const User = require('../models/User');
const Shop = require('../models/Shop');
const Product = require('../models/Product');

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
    Key: `uploads/${category}/${productName}/${Date.now()}-${file.originalname}`, // File path in S3
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

// Route to fetch products for a specific shop
router.get('/:shopId/products', async (req, res, next) => {
    const { shopId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;

    try {
        // Count total products for this shop
        const totalCount = await Product.countDocuments({ shop: shopId });

        // Fetch products for the specific shop
        const products = await Product.find({ shop: shopId })
            .select('name price description images')
            .skip((page - 1) * limit) // Pagination
            .limit(limit)
            .exec();

        const hasMore = (page * limit) < totalCount; // Check if there are more products

        res.json({
            products,
            hasMore, // Return whether more products are available
            totalCount, // Total count of products for the shop
        });
    } catch (err) {
        console.error('Failed to fetch products for shop:', err);
        next(err);
    }
});

// Route to fetch all shops
router.get('/', async (req, res) => {
    try {
        const shops = await Shop.find({});
        res.status(200).json(shops);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching shops' });
    }
});

// Create or update a shop (Admin only)
router.post(
    '/',
    [
        upload.array('images', 5), // Upload up to 5 images
        check('name').not().isEmpty().withMessage('Shop name is required'),
        check('description').not().isEmpty().withMessage('Description is required'),
        check('location').not().isEmpty().withMessage('Location is required'),
        check('contactEmail').isEmail().withMessage('A valid contact email is required'),
        authenticateToken, // Ensure the user is authenticated
    ],
    async (req, res, next) => {
        try {
            // Check if the user is an admin
            const user = await User.findById(req.user.userId).select('email isAdmin -_id').lean();
            const errors = validationResult(req);
            if (!errors.isEmpty() || !user.isAdmin) {
                return res.status(400).json({ errors: errors.array() });
            }

            // Sanitize incoming shop data
            const sanitizedData = {
                name: req.body.name.trim(),
                description: req.body.description.trim(),
                location: req.body.location.trim(),
                contactEmail: req.body.contactEmail.trim(),
                contactPhone: req.body.contactPhone?.trim(),
                socialMediaLinks: req.body.socialMediaLinks || {},
                categories: req.body.categories ? req.body.categories.split(',').map(c => c.trim()) : [],
                owner: req.user.userId, // Assuming owner is passed in the body
            };

            // Check if a shop with the same name already exists
            let shop = await Shop.findOne({ name: sanitizedData.name }).exec();

            // If the shop exists, update it
            if (shop) {
                // Upload new images if provided
                if (req.files.length > 0) {
                    const imageUploadPromises = req.files.map(file =>
                        uploadToS3(file, 'Shops', req.body.name.trim()) // Upload images to S3 bucket
                    );
                    const uploadedImages = await Promise.all(imageUploadPromises);
                    const imagePaths = uploadedImages.map(data => data.Location);

                    // Append new images to existing ones
                    shop.images = [...shop.images, ...imagePaths];
                }

                // Update shop details with new sanitized data
                Object.assign(shop, sanitizedData);

                // Save the updated shop
                const updatedShop = await shop.save();

                return res.status(200).json({ message: 'Shop updated successfully', shop: updatedShop });
            }

            // If no shop exists, create a new one
            const imageUploadPromises = req.files.map(file =>
                uploadToS3(file, 'Shops', req.body.name.trim()) // Upload images to S3 bucket
            );
            const uploadedImages = await Promise.all(imageUploadPromises);
            const imagePaths = uploadedImages.map(data => data.Location);

            const newShop = new Shop({
                ...sanitizedData,
                images: imagePaths, // Add uploaded images
            });

            // Save the new shop
            const savedShop = await newShop.save();

            return res.status(201).json({ message: 'Shop created successfully', shop: savedShop });
        } catch (err) {
            console.error('Error handling shop:', err.message || err);
            return res.status(500).json({ message: 'An error occurred while processing the shop.', error: err.message || err });
        }
    }
);

// Route to fetch details of a specific shop
router.get('/:shopId', async (req, res) => {
    const { shopId } = req.params;

    try {
        const shop = await Shop.findById(shopId);
        if (!shop) {
            return res.status(404).json({ message: 'Shop not found' });
        }
        res.status(200).json(shop);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching shop details', error: error.message });
    }
});

module.exports = router;
