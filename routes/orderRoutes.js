const express = require('express');
const router = express.Router();
const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const Order = require('../models/Order');
const User = require('../models/User');
const { getStoredRefreshToken } = require('../utils/authUtils');
const { router: userRoutes, authenticateToken } = require('./userRoutes');

dotenv.config();

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

router.post('/order', authenticateToken, async (req, res) => {
  const { shippingAddress, cartItems, totalAmount, paymentStatus } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    const order = new Order({
      userId: user._id,
      products: cartItems.map(item => ({ productId: item.productId._id, quantity: item.quantity })),
      totalAmount,
      paymentStatus,
      shippingAddress: `${shippingAddress.label}, ${shippingAddress.flat}, ${shippingAddress.street}, ${shippingAddress.city}, ${shippingAddress.state}, ${shippingAddress.zip}, ${shippingAddress.country}`
    });

    await order.save();

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

    // Send mail asynchronously
    sendMail(mailOptions).catch(console.error);

    res.status(200).json({ message: 'Order confirmed', order });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

module.exports = router;
