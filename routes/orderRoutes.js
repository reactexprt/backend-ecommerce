const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const router = express.Router();
const { google } = require('googleapis');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const Order = require('../models/Order');
const User = require('../models/User');
const Product = require('../models/Product');
const ShipRocketToken = require('../models/ShipRocketToken');
const { getStoredRefreshToken } = require('../utils/authUtils');
const { router: userRoutes, authenticateToken } = require('./userRoutes');

dotenv.config();

// Rate limiter middleware to prevent abuse of the order endpoint
const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many orders from this IP, please try again later'
});

// Function to authenticate with Shiprocket and store/retrieve the token from DB
async function authenticateShiprocket() {
  try {
    // Check if a valid token is stored in the database
    let storedToken = await ShipRocketToken.findOne({ service: 'shiprocket' });

    if (storedToken && new Date() < storedToken.expiry) {
      // Return the stored token if it hasn't expired
      return storedToken.token;
    }

    // If no valid token is found, fetch a new one from the Shiprocket API
    const response = await axios.post('https://apiv2.shiprocket.in/v1/external/auth/login', {
      email: process.env.DEVELOPER_EMAIL,
      password: process.env.DEVELOPER_PASS // It's better to store passwords in environment variables
    });

    const newToken = response.data.token;
    const tokenExpiry = Date.now() + (10 * 24 * 60 * 60 * 1000); // 10 days expiry in ms

    // Save or update the token in the database
    if (storedToken) {
      // Update existing token
      storedToken.token = newToken;
      storedToken.expiry = new Date(tokenExpiry);
      await storedToken.save();
    } else {
      // Create a new token record
      const tokenEntry = new ShipRocketToken({
        service: 'shiprocket',
        token: newToken,
        expiry: new Date(tokenExpiry)
      });
      await tokenEntry.save();
    }

    return newToken;
  } catch (error) {
    console.error('Error fetching Shiprocket token:', error.response ? error.response.data : error.message);
    throw new Error('Failed to authenticate with Shiprocket');
  }
}

function calculateCourierScore(courier) {
  let score = 0;

  // Ensure freight charge is valid and apply the scoring
  const freightCharge = courier.freight_charge > 0 ? courier.freight_charge : 1;
  score += (1 / freightCharge) * 25; // Prioritize lower freight charges

  // Ensure estimated delivery days are valid and apply the scoring
  const deliveryDays = courier.estimated_delivery_days > 0 ? courier.estimated_delivery_days : 1;
  score += (1 / deliveryDays) * 20; // Prioritize faster delivery

  // Rating (consider minimum rating of 1 if missing)
  const rating = courier.rating > 0 ? courier.rating : 1;
  score += rating * 15; // Higher rating gets a better score

  // Delivery performance (apply only if available)
  if (courier.delivery_performance > 0) {
    score += courier.delivery_performance * 10;
  }

  // Pickup performance (apply only if available)
  if (courier.pickup_performance > 0) {
    score += courier.pickup_performance * 10;
  }

  // COD availability // TODO --> what if user selected online payment
  if (courier.cod === 1) {
    score += 5;
  }

  // Real-time tracking
  if (courier.realtime_tracking === "Real Time") {
    score += 5;
  }

  // Instant POD availability
  if (courier.pod_available === "Instant") {
    score += 5; // Adding score for instant POD
  }

  // Penalize for high RTO charges
  const rtoCharges = courier.rto_charges > 0 ? courier.rto_charges : 0;
  score -= rtoCharges * 0.01; // Reduce score for high RTO charges

  // Penalize if the courier has suppression dates
  if (courier.suppress_date) {
    score -= 10;
  }
  
  return score;
}

function getTop5Couriers(couriers) {
  // Map each courier to its score and sort by the score in descending order
  const courierScores = couriers
    .map(courier => ({
      courier,
      score: calculateCourierScore(courier)
    }))
    .sort((a, b) => b.score - a.score); // Sort by score in descending order

  // Get the top 5 couriers
  const top5Couriers = courierScores.slice(0, 5).map(courierScore => courierScore.courier);

  // Mark the first courier as isRecommended
  if (top5Couriers.length > 0) {
    top5Couriers[0].isRecommended = true;
  }

  return top5Couriers;
}

// API endpoint to get serviceability
router.get('/shiprocket/serviceability', async (req, res) => {
  const { pickupPostcode, deliveryPostcode, weight, cod } = req.query;

  try {
    const token = await authenticateShiprocket();
    const response = await axios.get('https://apiv2.shiprocket.in/v1/external/courier/serviceability/', {
      params: {
        pickup_postcode: pickupPostcode,
        delivery_postcode: deliveryPostcode,
        weight: weight,
        cod: cod
      },
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    const couriers = response?.data?.data?.available_courier_companies;

    // Select the best courier using the scoring system
    const best5Couriers = getTop5Couriers(couriers);

    // Return the best courier information to the frontend
    res.status(200).json({ best5Couriers });

  } catch (error) {
    console.error('Error fetching serviceable couriers:', error);
    res.status(500).json({ message: 'Error fetching serviceable couriers', error: error.message });
  }
});

// Function to create Shiprocket order
async function createShiprocketOrder(user, order, products, billingAddress, shippingAddress, preferredCourierId = null, paymentMethod) {
  const token = await authenticateShiprocket();

  const updateBillingPhonenumber = billingAddress.phoneNumber?.replace('+91', '');
  const updatedShippingPhoneNumber = shippingAddress.phoneNumber?.replace('+91', '');

  // Check if the billing and shipping addresses are the same
  const shippingIsBilling = (
    billingAddress.firstName === shippingAddress.firstName &&
    billingAddress.lastName === shippingAddress.lastName &&
    billingAddress.flat === shippingAddress.flat &&
    billingAddress.street === shippingAddress.street &&
    billingAddress.city === shippingAddress.city &&
    billingAddress.state === shippingAddress.state &&
    billingAddress.zip === shippingAddress.zip &&
    billingAddress.country === shippingAddress.country
  );

  const totalWeight = order.products.reduce((total, item) => {
    const product = products.find(p => p._id.toString() === item.productId.toString());
    return total + (product.weight * item.quantity);
  }, 0);

  const totalDimensions = order.products.reduce((total, item) => {
    const product = products.find(p => p._id.toString() === item.productId.toString());
    return {
      length: Math.max(total.length, product.length), // Max length
      breadth: Math.max(total.breadth, product.breadth), // Max breadth
      height: total.height + (product.height * item.quantity) // Sum of heights
    };
  }, { length: 0, breadth: 0, height: 0 });  

  // simple box dimensions assumption (optional):
  // Need to add logic later ----> TODO --> Once we have boxes dimensions!!
  const packageDimensions = {
    length: 15,
    breadth: 10,
    height: 5
  };

  // Prepare order details for Shiprocket
  const orderDetails = {
    order_id: order._id, // Use your own order ID
    order_date: new Date().toISOString(),
    pickup_location: 'home',
    billing_customer_name: `${billingAddress.firstName}`,
    billing_last_name: `${billingAddress.lastName}`,
    billing_address: `${billingAddress.flat}, ${billingAddress.street}`,
    billing_city: billingAddress.city,
    billing_pincode: billingAddress.zip,
    billing_state: billingAddress.state,
    billing_country: billingAddress.country,
    billing_email: user.email, // TODO --> check if it is working as expected
    billing_phone: updateBillingPhonenumber,
    shipping_is_billing: shippingIsBilling, // TODO --> Conditionally send shipping address
    shipping_customer_name: `${shippingAddress.firstName}`,
    shipping_last_name: `${shippingAddress.lastName}`,
    shipping_address: `${shippingAddress.flat}, ${shippingAddress.street}`,
    shipping_city: shippingAddress.city,
    shipping_pincode: shippingAddress.zip,
    shipping_country: shippingAddress.country,
    shipping_state: shippingAddress.state,
    shipping_phone: updatedShippingPhoneNumber,
    order_items: order.products.map(item => {
      const product = products.find(p => p._id.toString() === item.productId.toString());
      return {
        name: product.name,
        sku: product.sku || 'SKU12345',  // Using _id as SKU
        units: item.quantity,
        selling_price: product.discountPrice || product.price, // Use discountPrice or fallback to price
        discount: 0, // Adjust accordingly
        tax: 0, // Adjust accordingly
        hsn: '0801' // TODO --> Harmonized System Code (if required)
      };
    }),
    payment_method: paymentMethod, // COD || Prepaid
    sub_total: order.totalAmount,
    length: 10, // Set appropriate package dimensions
    breadth: 10,
    height: 5,
    weight: 1
    // length: packageDimensions.length, // TODO --> totalDimensions -> creating a realistic approximation of how much space the products will occupy
    // breadth: packageDimensions.breadth,
    // height: packageDimensions.height,
    // weight: totalWeight
  };

  // Log the request to debug
  console.log('ShipRocket Order Details:', JSON.stringify(orderDetails, null, 2));

  // Step 1: Create Shiprocket order
  const orderResponse = await axios.post('https://apiv2.shiprocket.in/v1/external/orders/create/adhoc', orderDetails, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const { shipment_id } = orderResponse.data;
  console.log('shipmentr id', shipment_id);

  // Step 2: Assign AWB and Courier
  const assignCourierData = {
    shipment_id: [shipment_id]
  };

  // If a preferred courier is provided, add it to the request
  if (preferredCourierId) {
    assignCourierData.courier_id = preferredCourierId;
  }

  const assignCourierResponse = await axios.post('https://apiv2.shiprocket.in/v1/external/courier/assign/awb', assignCourierData, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  console.log(orderResponse.data, 'orderResponse & assignCourierResponse', assignCourierResponse.data);

  const { awb_code, courier_name } = assignCourierResponse.data; // Extract AWB and Courier name

  // Step 3: Generate Pickup Request
  // const pickupResponse = await axios.post('https://apiv2.shiprocket.in/v1/external/courier/generate/pickup', {
  //   shipment_id: [shipment_id],
  //   pickup_location: 'home' // Use your pickup location here
  // }, {
  //   headers: {
  //     Authorization: `Bearer ${token}`
  //   }
  // });

  // const pickupResult = pickupResponse.data; // Handle the pickup response

  // Return all relevant details
  return {
    orderResponse: orderResponse.data,
    assignCourierResponse: assignCourierResponse.data,
    // pickupResult
  };
}



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

  const { billingAddress, shippingAddress, cartItems, totalAmount, paymentStatus, recommendedCourierId, paymentMethod } = req?.body;
  let order = null;
  let user;
  try {
    // Fetch the user in a lean way to improve performance
    user = await User.findById(req.user.userId).select('_id email').lean().exec();

    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    // Fetch product details for the cart items to get full information (name, price, discountPrice)
    const productIds = cartItems.map(item => item.productId._id);
    const products = await Product.find({ _id: { $in: productIds } }).lean().exec();

    if (!products || products.length !== cartItems.length) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'One or more products not found' });
    }

    // Prepare the order data with full product details
    const orderData = {
      userId: user._id,
      products: cartItems.map(item => ({
        productId: new mongoose.Types.ObjectId(item.productId._id),
        quantity: item.quantity
      })),
      totalAmount,
      paymentStatus,
      billingAddress: `${billingAddress.label}, ${billingAddress.flat}, ${billingAddress.street}, ${billingAddress.city}, ${billingAddress.state}, ${billingAddress.zip}, ${billingAddress.country}`,
      shippingAddress: `${shippingAddress.label}, ${shippingAddress.flat}, ${shippingAddress.street}, ${shippingAddress.city}, ${shippingAddress.state}, ${shippingAddress.zip}, ${shippingAddress.country}`,
      paymentMethod
    };

    // Create and save the order atomically within the session
    order = new Order(orderData);
    await order.save({ session });

    // Prepare bulk update operations for stock decrement
    const bulkOps = cartItems.map(item => ({
      updateOne: {
        filter: { _id: item.productId._id, stock: { $gte: item.quantity } }, // Ensure sufficient stock
        update: { $inc: { stock: -item.quantity } }, // Decrease stock by the quantity ordered
      }
    }));

    // Perform bulk write operation for stock updates
    const bulkWriteResult = await Product.bulkWrite(bulkOps, { session });

    // Check if any update failed (e.g., insufficient stock)
    if (bulkWriteResult.modifiedCount !== cartItems.length) {
      throw new Error('Stock update failed for one or more products');
    }

    // Create Order in ShipRocket to deliver the product
    // Uncommmenting below line, dont want this in production right now
    // Need more testing
    // await createShiprocketOrder(user, order, products, billingAddress, shippingAddress, recommendedCourierId, paymentMethod);

    // Commit the transaction
    await session.commitTransaction();
    session.endSession();

    res.status(200).json({ message: 'Order confirmed and saved' });
  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error('Error processing order:', error);
    res.status(500).json({ message: 'Server error processing order', error });
  } finally {
    // Send the email to the user regardless of success or failure
    if (user) {
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
      // Send email asynchronously and handle any errors
      sendMail(mailOptions).catch(err => {
        console.error('Error sending confirmation email:', err);
      });
    }
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
