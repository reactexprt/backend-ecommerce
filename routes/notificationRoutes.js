const express = require('express');
const router = express.Router();
const Notification = require('../models/Notification');
const { router: userRoutes, authenticateToken } = require('./userRoutes');
const User = require('../models/User');

const sendNotificationToAllUsers = async (req, res) => {
  const { message, type } = req.body;

  try {
    // Find all users
    const users = await User.find({});

    // Create a notification for each user
    const notifications = users.map(user => ({
      userId: user._id,
      message,
      type
    }));

    // Insert all notifications in one go
    await Notification.insertMany(notifications);

    res.status(200).json({ success: true, message: 'Notification sent to all users' });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ success: false, message: 'Error sending notification' });
  }
};

const getUnreadNotificationCount = async (req, res) => {
    try {
      const userId = req.user.userId;
      const unreadCount = await Notification.countDocuments({ userId, read: false });
  
      res.status(200).json({ unreadCount });
    } catch (error) {
      console.error('Error fetching unread notifications count:', error);
      res.status(500).json({ success: false, message: 'Error fetching unread notifications count' });
    }
  };

// Send a notification
router.post('/send', authenticateToken, sendNotificationToAllUsers);

// Get Unread count
router.get('/unread-count', authenticateToken, getUnreadNotificationCount);

// Fetch notifications for the authenticated user
router.get('/', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Mark a notification as read
router.post('/read', authenticateToken, async (req, res) => {
    try {
        const { notificationId } = req.body;

        const notification = await Notification.findById(notificationId);

        if (!notification) {
            return res.status(404).json({ message: 'Notification not found' });
        }

        if (notification.userId.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        notification.read = true;
        await notification.save();

        res.status(200).json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


module.exports = router;
