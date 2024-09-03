const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
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


// Load environment variables
dotenv.config();
const isProduction = process.env.NODE_ENV === 'production';


// Check for required environment variables
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.CLIENT_ID) {
  console.error('FATAL ERROR: MONGO_URI, JWT_SECRET, or GOOGLE_CLIENT_ID is not defined.');
  process.exit(1);
}

const app = express();

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
app.use(compression());
// Use cookie-parser middleware
app.use(cookieParser());

app.use(cors(corsOptions));

// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 350, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
});
app.use(limiter);


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));


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
    const username = email.split('@')[0];
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

    res.status(200).json({ authToken, userId: user._id });
  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error('Error verifying Google ID token:', error);
    res.status(401).json({ message: 'Invalid Google ID token' });
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
app.use('/api/payment', paymentRoutes);

// app.use(
//   helmet.contentSecurityPolicy({
//     directives: {
//       defaultSrc: ["'self'"],
//       scriptSrc: ["'self'", "https://trusted.cdn.com"],
//       styleSrc: ["'self'", "'unsafe-inline'"],
//       imgSrc: ["'self'", "data:", "https://trusted.cdn.com"],
//       connectSrc: ["'self'", "https://api.yourservice.com"],
//       frameSrc: ["'self'"],
//       upgradeInsecureRequests: [],
//     },
//   })
// );


// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
