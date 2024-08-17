const express = require('express');
const router = express.Router();
const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const Order = require('../models/Order');
const User = require('../models/User');
const { router: userRoutes, authenticateToken } = require('./userRoutes');

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  'http://localhost'
);

oAuth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN
});

async function sendMail(mailOptions) {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.EMAIL,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.REFRESH_TOKEN,
        accessToken: accessToken.token
      }
    });

    const result = await transporter.sendMail(mailOptions);
    return result;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}

router.post('/order', authenticateToken, async (req, res) => {
  const { shippingAddress, cartItems, totalAmount, paymentStatus } = req.body;

  try {
    const user = await User.findById(req.user.userId);

    const order = new Order({
      userId: req.user.userId,
      products: cartItems.map(item => ({ productId: item.productId._id, quantity: item.quantity })),
      totalAmount,
      paymentStatus,
      shippingAddress: `${shippingAddress.label}, ${shippingAddress.flat}, ${shippingAddress.street}, ${shippingAddress.city}, ${shippingAddress.state}, ${shippingAddress.zip}, ${shippingAddress.country}`
    });

    await order.save();

    const mailOptions = {
      from: process.env.EMAIL,
      to: [user.email, 'himalayanrasa@gmail.com'].join(','),
      subject: 'Order Confirmation',
      text: `
        Thank you for your order!
        Shipping Address: ${order.shippingAddress}
        Total Amount: ₹${order.totalAmount.toFixed(2)}
        Items: ${cartItems.map(item => `${item.productId.name} (x${item.quantity})`).join(', ')}
      `
    };

    await sendMail(mailOptions);
    res.status(200).json({ message: 'Order confirmed and email sent', order });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

module.exports = router;

