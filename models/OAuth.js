const mongoose = require('mongoose');

const oAuthSchema = new mongoose.Schema({
    service: { type: String, required: true, unique: true }, // e.g., 'google'
    refreshToken: { type: String, required: true }
}, { timestamps: true });

const OAuth = mongoose.model('OAuth', oAuthSchema);
module.exports = OAuth;
