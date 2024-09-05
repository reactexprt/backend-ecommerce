const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const Shop = require('../models/Shop');

// Search products and shops
router.get('/', async (req, res) => {
    try {
        let { query } = req.query;

        // Ensure query is a string, if not provided default to an empty string
        query = query ? String(query) : '';

        // If query is empty, don't use regex, otherwise perform the regex search
        let searchQuery = {};
        if (query.trim()) {
            searchQuery = {
                $or: [
                    { name: { $regex: query, $options: 'i' } },  // Text search
                    { description: { $regex: query, $options: 'i' } },  // Text search
                    { category: { $regex: query, $options: 'i' } },  // Text search
                ],
            };
        }

        // Search both products and shops and include image URLs in the result
        const products = await Product.find(searchQuery).select('name price images description');
        const shops = await Shop.find(searchQuery).select('name location description images');

        res.status(200).json({ products, shops });
    } catch (err) {
        console.error('Search failed:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});


module.exports = router;
