const mongoose = require('mongoose');

// Define the Synonym schema
const synonymSchema = new mongoose.Schema({
  baseTerm: {
    type: String,
    required: true,
    unique: true, // Base term should be unique
    trim: true,
    lowercase: true // Ensure all terms are lowercase for uniform search
  },
  synonyms: [
    {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    }
  ]
}, { timestamps: true });

// Export the Synonym model
const Synonym = mongoose.model('Synonym', synonymSchema);
module.exports = Synonym;
