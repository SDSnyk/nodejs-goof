// routes/index.js
const mongoose = require('mongoose');

// Sample User model
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  bio: String, // Vulnerable field
}));

// Middleware to check if user is logged in
exports.isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// GET /account_details
exports.get_account_details = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user.username });
    // Render user bio unsafely using <%- %> (XSS vulnerability)
    res.render('account_details', { user });
  } catch (err) {
    res.status(500).send('Server Error');
  }
};

// POST /account_details
exports.save_account_details = async (req, res) => {
  try {
    const { bio } = req.body;
    // Store user input without sanitization (XSS vulnerability)
    await User.updateOne(
      { username: req.session.user.username },
      { $set: { bio } }
    );
    res.redirect('/account_details');
  } catch (err) {
    res.status(500).send('Server Error');
  }
};

// Other routes (placeholders)
exports.current_user = (req, res, next) => { next(); };
exports.index = (req, res) => { res.render('index'); };
exports.login = (req, res) => { res.render('login'); };
exports.loginHandler = (req, res) => { /* Login logic */ };
exports.admin = (req, res) => { res.render('admin'); };
exports.logout = (req, res) => { req.session.destroy(); res.redirect('/'); };
exports.create = (req, res) => { /* Create logic */ };
exports.destroy = (req, res) => { /* Destroy logic */ };
exports.edit = (req, res) => { /* Edit logic */ };
exports.update = (req, res) => { /* Update logic */ };
exports.import = (req, res) => { /* Import logic */ };
exports.about_new = (req, res) => { res.render('about_new'); };
exports.chat = {
  get: (req, res) => { /* Chat get logic */ },
  add: (req, res) => { /* Chat add logic */ },
  delete: (req, res) => { /* Chat delete logic */ },
};