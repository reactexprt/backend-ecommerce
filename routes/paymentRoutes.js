// paymentRoutes.js
const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const dotenv = require('dotenv')

const router = express.Router();

dotenv.config();

// Setup Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID, // Your Key ID
  key_secret: process.env.RAZORPAY_KEY_SECRET, // Your Key Secret
});

// Create Razorpay order
router.post('/create-razorpay-order', async (req, res) => {
  const { amount } = req.body; // amount in paise (100 INR = 10000 paise)

  const options = {
    amount: amount, // Amount in paise
    currency: "INR",
    receipt: `receipt_order_${Math.floor(Math.random() * 1000000)}`,
    payment_capture: 1, // Automatically capture the payment
  };

  try {
    const order = await razorpay.orders.create(options);
    res.status(200).json(order);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error creating Razorpay order' });
  }
});

// Verify Razorpay payment
router.post('/verify-razorpay-payment', (req, res) => {
  const { orderCreationId, razorpayPaymentId, razorpayOrderId, razorpaySignature } = req.body;

  const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
  shasum.update(`${orderCreationId}|${razorpayPaymentId}`);
  const digest = shasum.digest('hex');

  if (digest === razorpaySignature) {
    res.status(200).json({ status: 'success' });
  } else {
    res.status(400).json({ status: 'failure', message: 'Payment verification failed' });
  }
});

module.exports = router;
