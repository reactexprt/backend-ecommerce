const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const { OAuth2Client } = require('google-auth-library'); // Import Google OAuth2 Client

// Import routes
const { router: userRoutes, authenticateToken } = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');
const orderRoutes = require('./routes/orderRoutes');
const cartRoutes = require('./routes/cartRoutes');

// Load environment variables
dotenv.config();

// Check for required environment variables
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.CLIENT_ID) {
  console.error('FATAL ERROR: MONGO_URI, JWT_SECRET, or GOOGLE_CLIENT_ID is not defined.');
  process.exit(1);
}

const app = express();
app.use(express.json());

const corsOptions = {
  origin: 'http://localhost:3000',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204
};

// Middleware
app.use(bodyParser.json());
app.use(cors(corsOptions));
app.use(helmet());
app.options('*', cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
});
app.use(limiter);


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));



// Initialize the Google OAuth2 client got Single Sign in with Google
const client = new OAuth2Client(process.env.CLIENT_ID);
// Route to handle Google Sign-In
app.post('/api/auth/google', async (req, res) => {
  const { token } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload['email'];
    // Extract the username from the email (everything before the @ symbol)
    const username = email.split('@')[0];
    const googleId = payload['sub'];
    // Check if user exists in the database
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({
        googleId: googleId,
        email: email,
        username: username,
        password: 'NotRequiredForGoogleSignIn'
      });
      await user.save();
    }
    const authToken = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );
    res.json({ authToken });
  } catch (error) {
    console.error('Error verifying Google ID token:', error);
    res.status(401).json({ message: 'Invalid Google ID token' });
  }
});



// Ensure that all routes are defined and properly exported in their respective files
if (!userRoutes || !productRoutes || !orderRoutes) {
  console.error('One or more route modules are not defined.');
  process.exit(1);
}
// Use routes
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/cart', cartRoutes);


// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
