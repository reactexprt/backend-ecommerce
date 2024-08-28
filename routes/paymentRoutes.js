// paymentRoutes.js
const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const dotenv = require('dotenv')
const rateLimit = require('express-rate-limit');

const router = express.Router();

dotenv.config();

// Setup Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID, // Your Key ID
  key_secret: process.env.RAZORPAY_KEY_SECRET, // Your Key Secret
});

// Rate limiter middleware to prevent abuse of the create order endpoint
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many order creation attempts from this IP, please try again later'
});

router.post('/create-razorpay-order', limiter, async (req, res) => {
  const { amount } = req.body; // amount in paise (100 INR = 10000 paise)

  // Input validation
  if (!amount || isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount specified' });
  }

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
    console.error('Error creating Razorpay order:', error);

    // Enhanced error handling
    if (error instanceof SomeRazorpaySpecificError) { // Replace with actual error check if applicable
      return res.status(400).json({ error: 'Razorpay error: ' + error.message });
    }

    res.status(500).json({ error: 'Server error creating Razorpay order' });
  }
});

// Verify Razorpay payment
router.post('/verify-razorpay-payment', limiter, (req, res) => {
  const { orderCreationId, razorpayPaymentId, razorpayOrderId, razorpaySignature } = req.body;

  // Validate input
  if (!orderCreationId || !razorpayPaymentId || !razorpaySignature) {
    return res.status(400).json({ status: 'failure', message: 'Invalid input data' });
  }

  try {
    // Generate the expected signature using the secret key
    const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    shasum.update(`${orderCreationId}|${razorpayPaymentId}`);
    const digest = shasum.digest('hex');

    // Use a constant-time comparison to prevent timing attacks
    const isSignatureValid = crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(razorpaySignature));

    if (isSignatureValid) {
      // Log the successful verification for audit purposes
      console.log(`Payment verification successful for order ${razorpayOrderId}`);
      res.status(200).json({ status: 'success' });
    } else {
      console.warn(`Payment verification failed for order ${razorpayOrderId}`);
      res.status(400).json({ status: 'failure', message: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('Error during payment verification:', error);
    res.status(500).json({ status: 'failure', message: 'Server error during payment verification' });
  }
});


module.exports = router;
