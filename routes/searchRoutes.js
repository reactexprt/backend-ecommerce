const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const Shop = require('../models/Shop');
const Synonym = require('../models/Synonym');

// Search products and shops with synonyms, pagination, and optimization
// Search products and shops
router.get('/', async (req, res) => {
    try {
        let { query, page = 1, limit = 10 } = req.query;

        // Ensure query is a string, if not provided default to an empty string
        query = query ? String(query) : '';

        let searchTerms = [query]; // Start with the original search term

        // Check if the search term has any synonyms
        if (query.trim()) {
            const synonymEntry = await Synonym.findOne({
                synonyms: { $regex: new RegExp(query, 'i') } // Case-insensitive search for synonyms
            });

            // If synonyms are found, add them and the base term to the search terms
            if (synonymEntry) {
                searchTerms = [synonymEntry.baseTerm, ...synonymEntry.synonyms];
            }
        }

        // Construct the search query using the original term and any found synonyms
        const searchQuery = {
            $or: [
                { name: { $in: searchTerms.map(term => new RegExp(term, 'i')) } },  // Search by name
                { description: { $in: searchTerms.map(term => new RegExp(term, 'i')) } },  // Search by description
                { category: { $in: searchTerms.map(term => new RegExp(term, 'i')) } },  // Search by category
            ]
        };

        // Pagination logic
        const products = await Product.find(searchQuery)
            .select('name price images description')
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const shops = await Shop.find(searchQuery)
            .select('name location description images')
            .limit(limit * 1)
            .skip((page - 1) * limit);

        // Count total results for front-end to know when to stop loading more
        const totalProducts = await Product.countDocuments(searchQuery);
        const totalShops = await Shop.countDocuments(searchQuery);

        res.status(200).json({
            products,
            shops,
            totalProducts,
            totalShops,
            currentPage: page,
            totalPages: Math.ceil((totalProducts + totalShops) / limit)
        });
    } catch (err) {
        console.error('Search failed:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
module.exports = router;
