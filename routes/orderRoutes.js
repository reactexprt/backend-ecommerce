const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const { google } = require('googleapis');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const Order = require('../models/Order');
const User = require('../models/User');
const { getStoredRefreshToken } = require('../utils/authUtils');
const { router: userRoutes, authenticateToken } = require('./userRoutes');

dotenv.config();

// Rate limiter middleware to prevent abuse of the order endpoint
const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many orders from this IP, please try again later'
});

async function sendMail(mailOptions) {
  try {
    const refreshToken = await getStoredRefreshToken('google');
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    const oAuth2Client = new google.auth.OAuth2(
      process.env.CLIENT_ID, 
      process.env.CLIENT_SECRET, 
      'http://localhost'
    );
    oAuth2Client.setCredentials({ 
      refresh_token: refreshToken
    });
    const accessToken = await oAuth2Client.getAccessToken();
    if (!accessToken || !accessToken.token) {
      throw new Error('Failed to retrieve access token');
    }
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.EMAIL,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: refreshToken,
        accessToken: accessToken.token
      }
    });

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

// @route   POST /api/orders/order
// @desc    Post orders of the authenticated user
// @access  Private
router.post('/order', [authenticateToken, orderLimiter], async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { shippingAddress, cartItems, totalAmount, paymentStatus } = req.body;

    // Fetch the user in a lean way to improve performance
    const user = await User.findById(req.user.userId).select('_id email').lean().exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    // Prepare the order data
    const orderData = {
      userId: user._id,
      products: cartItems.map(item => ({
        productId: new mongoose.Types.ObjectId(item.productId._id),
        quantity: item.quantity
      })),
      totalAmount,
      paymentStatus,
      shippingAddress: `${shippingAddress.label}, ${shippingAddress.flat}, ${shippingAddress.street}, ${shippingAddress.city}, ${shippingAddress.state}, ${shippingAddress.zip}, ${shippingAddress.country}`
    };

    // Create and save the order atomically within the session
    const order = new Order(orderData);
    await order.save({ session });

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();

    // Prepare the mail options
    const mailOptions = {
      from: process.env.EMAIL,
      to: user.email,
      subject: 'Order Confirmation',
      text: `
        Thank you for your order!
        Shipping Address: ${order.shippingAddress}
        Total Amount: ₹${order.totalAmount.toFixed(2)}
        Items: ${cartItems.map(item => `${item.productId.name} (x${item.quantity})`).join(', ')}
      `
    };

    // Send mail asynchronously (non-blocking)
    sendMail(mailOptions).catch(console.error);

    res.status(200).json({ message: 'Order confirmed', order });
  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error('Error processing order:', error);
    res.status(500).json({ message: 'Server error processing order', error });
  }
});

// @route   GET /api/orders/previous
// @desc    Get previous orders of the authenticated user
// @access  Private
// routes/orders.js
router.get('/previous', authenticateToken, async (req, res) => {
  const limit = parseInt(req.query.limit) || 5; // Default limit is 5
  const page = parseInt(req.query.page) || 1;  // Default page is 1

  try {
    // Count total orders for the user
    const totalOrders = await Order.countDocuments({ userId: req.user.userId });

    // Fetch the orders for the current page
    const orders = await Order.find({ userId: req.user.userId })
      .sort({ createdAt: -1 }) // Sort orders by newest first
      .populate('products.productId', 'name price images') // Populate product details
      .skip((page - 1) * limit) // Skip the previous orders according to the page
      .limit(limit) // Limit the number of orders fetched
      .exec();

    // Calculate total pages
    const totalPages = Math.ceil(totalOrders / limit);

    res.status(200).json({ 
      orders, 
      currentPage: page,
      totalPages 
    });
  } catch (error) {
    console.error('Error fetching orders:', error.message);
    res.status(500).json({ error: 'Server Error' });
  }
});



module.exports = router;
