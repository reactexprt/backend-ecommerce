const mongoose = require('mongoose');

const shopSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true }, // Unique and required name
  description: { type: String, required: true }, // Required description
  location: { type: String, required: true }, // Address or general location
  images: { type: [String], default: [] }, // Array to store shop images (URLs or paths)
  contactEmail: { type: String, required: true }, // Email for contact
  contactPhone: { type: String }, // Optional phone number for contact
  createdAt: { type: Date, default: Date.now }, // Date when the shop was created
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Reference to the owner (User)
  categories: [{ type: String }], // Categories the shop specializes in (e.g., Electronics, Clothing)
  socialMediaLinks: { 
    facebook: { type: String },
    instagram: { type: String },
    twitter: { type: String },
    website: { type: String } // Shop's official website
  },
  rating: { type: Number, default: 0 }, // Average rating for the shop
  reviews: [
    {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to the user leaving the review
      comment: { type: String }, // Review comment
      rating: { type: Number, min: 1, max: 5 }, // Rating given by the user
      createdAt: { type: Date, default: Date.now }, // Date when the review was added
    }
  ],
  isActive: { type: Boolean, default: true } // Indicates if the shop is active or inactive
});

const Shop = mongoose.model('Shop', shopSchema);
module.exports = Shop;
