const mongoose = require('mongoose');

// Define a schema for storing API tokens
const apiTokenSchema = new mongoose.Schema({
  service: { type: String, required: true, unique: true }, // E.g., 'shiprocket'
  token: { type: String, required: true },
  expiry: { type: Date, required: true }
});

const ShipRocketToken = mongoose.model('ShipRocketToken', apiTokenSchema);

module.exports = ShipRocketToken;
