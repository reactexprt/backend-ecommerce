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
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; background-color: #ffffff;">
          <!-- Company Logo -->
          <div style="text-align: center; margin-bottom: 20px;">
            <img src="https://himalayanrasa-product-images.s3.ap-south-1.amazonaws.com/uploads/WebsiteImages/himalayanrasa.png" alt="Company Logo" style="max-width: 150px;">
          </div>
    
          <!-- Order Details -->
          <h2 style="color: #4CAF50;">Thank you for your order!</h2>
          <p>Your order has been placed successfully. Here are your order details:</p>
          
          <!-- Shipping Address -->
          <div style="background-color: #f9f9f9; padding: 10px; margin-bottom: 20px;">
            <h3>Shipping Address:</h3>
            <p>${order.shippingAddress}</p>
          </div>
    
          <!-- Order Summary -->
          <div style="background-color: #f9f9f9; padding: 10px; margin-bottom: 20px;">
            <h3>Order Summary</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr style="background-color: #e0e0e0;">
                  <th style="text-align: left; padding: 8px;">Item</th>
                  <th style="text-align: center; padding: 8px;">Quantity</th>
                  <th style="text-align: right; padding: 8px;">Price</th>
                </tr>
              </thead>
              <tbody>
                ${cartItems.map(item => `
                  <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #e0e0e0;">${item.productId.name}</td>
                    <td style="text-align: center; padding: 8px; border-bottom: 1px solid #e0e0e0;">${item.quantity}</td>
                    <td style="text-align: right; padding: 8px; border-bottom: 1px solid #e0e0e0;">₹${(item.productId.discountPrice * item.quantity).toFixed(2)}</td>
                  </tr>
                `).join('')}
              </tbody>
              <tfoot>
                <tr>
                  <td colspan="2" style="text-align: right; padding: 8px;">Total Amount:</td>
                  <td style="text-align: right; padding: 8px;">₹${order.totalAmount.toFixed(2)}</td>
                </tr>
              </tfoot>
            </table>
          </div>
    
          <!-- Call to Action Button -->
          <div style="text-align: center; margin-top: 20px;">
            <a href="https://www.himalayanrasa.com/previousOrders/${order._id}" 
               style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              View Order Details
            </a>
          </div>
    
          <!-- Social media icons -->
          <table align="center" style="margin-top: 30px;">
            <tr>
              <td align="center" style="padding: 10px;">
                <a href="https://facebook.com/himalayanrasa" style="margin: 0 5px;">
                  <img src="https://himalayanrasa-product-images.s3.ap-south-1.amazonaws.com/uploads/WebsiteImages/backend-email-icons/Facebook.png" 
                      alt="Facebook" 
                      style="width: 24px; height: 24px;">
                </a>
              </td>
              <td align="center" style="padding: 10px;">
                <a href="https://instagram.com/himalayanrasa" style="margin: 0 5px;">
                  <img src="https://himalayanrasa-product-images.s3.ap-south-1.amazonaws.com/uploads/WebsiteImages/backend-email-icons/Instagram.png" 
                      alt="Instagram" 
                      style="width: 24px; height: 24px;">
                </a>
              </td>
            </tr>
          </table>
    
          <!-- Footer -->
          <div style="margin-top: 30px; font-size: 12px; color: #777; text-align: center;">
            <p>Ħimalayan R̥asa Inc. | Rangri Road, Sarsai, Himachal Pradesh</p>
            <p><a href="https://www.himalayanrasa.com/terms" style="color: #4CAF50; text-decoration: none;">Terms of Service</a> | 
               <a href="https://www.himalayanrasa.com/privacy" style="color: #4CAF50; text-decoration: none;">Privacy Policy</a></p>
            <p>If you have any questions, contact us at <a href="mailto:contact@himalayanrasa.com" style="color: #4CAF50;">contact@himalayanrasa.com</a></p>
          </div>
        </div>
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

// @route   GET /api/orders/:orderId
// @desc    Get details of a specific order
// @access  Private
router.get('/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;

  try {
    // Fetch the order with populated product details
    const order = await Order.findById(orderId).lean()
    .populate('products.productId', 'name price images')
    .exec();

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Check if the order belongs to the authenticated user
    if (order.userId.toString() !== req.user.userId.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.status(200).json({ order });
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Server Error' });
  }
});

module.exports = router;
