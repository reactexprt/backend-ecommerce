const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const dotenv = require('dotenv');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const { OAuth2Client } = require('google-auth-library');
const { updateExpiredRefreshToken } = require('./utils/authUtils');
// Import routes
const { router: userRoutes, authenticateToken } = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');
const orderRoutes = require('./routes/orderRoutes');
const cartRoutes = require('./routes/cartRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const webauthnRoutes = require('./routes/webauthnRoute');
const wishlistRoutes = require('./routes/wishlistRoutes');
const shopRoutes = require('./routes/shopRoutes');
const searchRoutes = require('./routes/searchRoutes');
const notificationRoutes = require('./routes/notificationRoutes');


// Load environment variables
dotenv.config();
const isProduction = process.env.NODE_ENV === 'production';


// Check for required environment variables
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.CLIENT_ID) {
  console.error('FATAL ERROR: MONGO_URI, JWT_SECRET, or GOOGLE_CLIENT_ID is not defined.');
  process.exit(1);
}

const app = express();

let dbConnected= false;
// Trust the first proxy (Elastic Load Balancer)
app.set('trust proxy', 1);
// If your app is behind multiple proxies, you can adjust the argument 
// accordingly (e.g., app.set('trust proxy', 'loopback') 
// for local development or app.set('trust proxy', true) to trust all proxies).

const corsOptions = {
  origin: isProduction ? 'https://www.himalayanrasa.com' : 'http://localhost:3000',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204  // Some legacy browsers (e.g., IE11) choke on 204
};

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(helmet());
app.use(helmet.frameguard({ action: 'deny' })); // Prevent clickjacking
app.use(helmet.hsts({ maxAge: 31536000 })); // Enforce HTTPS
app.use(compression({ threshold: 1024 }));
// Use cookie-parser middleware
app.use(cookieParser());

app.use(cors(corsOptions));

// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit to 200 requests per 15 minutes
});
app.use(generalLimiter); 

// MongoDB Connection
async function connectWithRetry() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    dbConnected = true;
    console.log('Holla - MongoDB connected. Have fun! Good luck!');
  } catch (err) {
    dbConnected = false;
    console.error('Oops, MongoDB connection error:', err);
    setTimeout(connectWithRetry, 5000); // Retry connection after 5 seconds
  }
}
connectWithRetry();

// AWS Beanstalk health check responds on /
app.get('/', (req, res) => {
  const healthCheck = {
    status: 'Ok',
    dbState: dbConnected ? 'connected' : 'disconnected',
    uptime: process.uptime(),
    timestamp: Date.now(),
  };

  // Return 503 if the database is not connected
  if (!dbConnected) {
    return res.status(503).json(healthCheck);
  }

  res.status(200).json(healthCheck);
});

// Initialize the Google OAuth2 client for Single Sign-On with Google
const client = new OAuth2Client(process.env.CLIENT_ID);
// Rate limiter middleware to prevent abuse of the sign-in endpoint
const googleSignInLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit each IP to 50 requests per windowMs
  message: 'Too many sign-in attempts from this IP, please try again later'
});
app.post('/api/auth/google', googleSignInLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { token } = req.body;

    // Verify the Google ID token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload['email'];
    const username = `${email.split('@')[0]}_gmail`;
    const googleId = payload['sub'];

    // Check if the user exists in the database
    let user = await User.findOne({ email }).select('_id isAdmin refreshToken').session(session).exec();

    if (!user) {
      // User does not exist, create a new user record
      const randomPassword = crypto.randomBytes(32).toString('hex');
      user = new User({
        googleId: googleId,
        email: email,
        username: username,
        password: randomPassword
      });
      await user.save({ session });
    }

    // Generate the authentication token (JWT)
    const authToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Generate a new refresh token
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Update the refresh token in the database
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { refreshToken: refreshToken } },
      { session, new: true }
    ).exec();

    await session.commitTransaction();
    session.endSession();

    // Set the refresh token in an HTTP-only, Secure cookie
    res.cookie('refreshToken', refreshToken, {
      domain: '.himalayanrasa.com',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure secure cookies in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({ authToken, userId: user._id, username, email });
  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error('Error verifying Google ID token:', error);
    res.status(401).json({ message: 'Invalid Google ID token' });
  }
});

app.post('/api/auth/facebook', googleSignInLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { accessToken } = req.body;

    // Verify the Facebook access token and get user info
    const facebookResponse = await axios.get(
      `https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`
    );

    const { email, id: facebookId, name } = facebookResponse.data;
    const username = `${email.split('@')[0]}_facebook`;

    // Check if the user exists in the database
    let user = await User.findOne({ email }).select('_id isAdmin refreshToken').session(session).exec();

    if (!user) {
      // User does not exist, create a new user record
      const randomPassword = crypto.randomBytes(32).toString('hex');
      user = new User({
        facebookId: facebookId,
        email: email,
        username: username,
        password: randomPassword,
      });
      await user.save({ session });
    }

    // Generate the authentication token (JWT)
    const authToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Generate a new refresh token
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Update the refresh token in the database
    await User.findOneAndUpdate(
      { _id: user._id },
      { $set: { refreshToken: refreshToken } },
      { session, new: true }
    ).exec();

    await session.commitTransaction();
    session.endSession();

    // Set the refresh token in an HTTP-only, Secure cookie
    res.cookie('refreshToken', refreshToken, {
      domain: '.himalayanrasa.com',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure secure cookies in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({ authToken, userId: user._id, username, email });
  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error('Error verifying Facebook access token:', error);
    res.status(401).json({ message: 'Invalid Facebook access token' });
  }
});


// Automatically retrieve a new refresh token
updateExpiredRefreshToken()
  .then(() => {
    console.log('New Refresh token obtained')
  })
  .catch(console.error);


// Ensure that all routes are defined and properly exported in their respective files
if (!userRoutes || !productRoutes || !orderRoutes) {
  console.error('One or more route modules are not defined.');
  process.exit(1);
}
// Use routes
app.use('/api/users', userRoutes);
app.use('/api/webauthn', webauthnRoutes);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/wishlist', wishlistRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/shops', shopRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/payment', paymentRoutes);

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],  // Allow content from the same origin
      scriptSrc: [
        "'self'",               // Allow scripts from the same origin
        "https://trusted.cdn.com",
        "https://connect.facebook.net",
        "https://checkout.razorpay.com",
        "https://apiv2.shiprocket.in",
        "https://apis.google.com", // Google APIs
        "https://accounts.google.com", // Google OAuth
      ],
      styleSrc: [
        "'self'",
        "https://fonts.googleapis.com",
        "'unsafe-inline'"
      ],
      imgSrc: [
        "'self'",               // Allow images from the same origin
        "https://*.s3.ap-south-1.amazonaws.com", // Allow images from all AWS S3 bucket URLs
        "https://himalayanrasa-product-images.s3.ap-south-1.amazonaws.com", // Restrict to your specific bucket
        "data:",
        "https://*.googleusercontent.com",
      ],
      connectSrc: [
        "'self'",               // Allow API requests from the same origin
        "https://api.himalayanrasa.com", 
        "https://himalayanrasa-product-images.s3.ap-south-1.amazonaws.com",
        "https://graph.facebook.com",
        "https://connect.facebook.net",
        "https://checkout.razorpay.com",
        "https://www.googleapis.com", // Google API connections
        "https://accounts.google.com"  // Google OAuth server connections
      ],
      frameSrc: [
        "'self'",
        "https://checkout.razorpay.com",
        "https://accounts.google.com",
        "https://www.facebook.com"
      ],     // Prevent clickjacking
      fontSrc: [
        "'self'",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com"
      ],
      objectSrc: ["'none'"],     // Disallow plugins like Flash
      upgradeInsecureRequests: [], // Enforce HTTPS
    },
  })
);

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Something went wrong!' });
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
