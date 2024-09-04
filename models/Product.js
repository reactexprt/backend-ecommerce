const mongoose = require('mongoose');

const ratingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
});

const commentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true }, // Display username of the commenter
  comment: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 }, // Optional rating with the comment
  createdAt: { type: Date, default: Date.now },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true, min: 0 },
  discountPrice: { type: Number, min: 0 }, // New field for discount price
  images: { type: [String] },
  category: { type: String },
  stock: { type: Number, default: 0, min: 0 },
  ratings: [ratingSchema], // New field for user ratings
  averageRating: { type: Number, default: 0 }, // Computed average rating
  comments: [commentSchema], 
}, { timestamps: true });

// Calculate average rating before saving the document
productSchema.pre('save', function(next) {
  if (this.ratings.length > 0) {
    const avg = this.ratings.reduce((acc, rating) => acc + rating.rating, 0) / this.ratings.length;
    this.averageRating = avg.toFixed(1);
  } else {
    this.averageRating = 0;
  }
  next();
});

module.exports = mongoose.model('Product', productSchema);
