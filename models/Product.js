const mongoose = require('mongoose');

const ratingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
});

const commentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true }, 
  comment: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 }, 
  createdAt: { type: Date, default: Date.now },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true, min: 0 },
  discountPrice: { type: Number, min: 0 },
  images: { type: [String] }, // Array of image URLs
  category: { type: String },
  stock: { type: Number, default: 0, min: 0 },
  ratings: [ratingSchema],
  averageRating: { type: Number, default: 0 },
  comments: [commentSchema],
  shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
}, { timestamps: true });

// Pre-save hook to calculate average rating
productSchema.pre('save', function(next) {
  if (this.ratings.length > 0) {
    const avg = this.ratings.reduce((acc, rating) => acc + rating.rating, 0) / this.ratings.length;
    this.averageRating = avg.toFixed(1);
  } else {
    this.averageRating = 0;
  }
  next();
});

// Add text index for better search performance, and index the images array for better query performance
productSchema.index(
  { name: 'text', description: 'text', category: 'text' },
  { weights: { name: 5, description: 3, category: 1 } }
);
productSchema.index({ images: 1 });  // Indexing the images array

const Product = mongoose.model('Product', productSchema);
module.exports = Product;
