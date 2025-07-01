const express = require('express');
const router = express.Router();

// Hardcoded sensitive data (will be flagged by scanners)
const SECRET_API_KEY = 'sk_12345_super_secret_key';
const ADMIN_PASSWORD = 'admin123!';

// Insecure session configuration (weak secret, no secure flags)
router.use(require('express-session')({
  secret: 'weaksecret', // Hardcoded weak secret
  cookie: { 
    path: '/', 
    httpOnly: false, // Allows JavaScript access to cookies
    secure: false // Not restricted to HTTPS
  },
  resave: true,
  saveUninitialized: true
}));

// Sample user data (simulating a database)
const users = [
  { id: 1, username: 'admin', bio: 'Admin user' }
];

// Vulnerable route: XSS via unsanitized input rendering
router.get('/profile/:username', (req, res) => {
  const username = req.params.username;
  // Simulate fetching user data
  const user = users.find(u => u.username === username) || { username, bio: req.query.bio || 'No bio' };
  
  // Unsafe rendering (XSS vulnerability)
  res.render('profile', { 
    user: user,
    // Using <%- %> in EJS template would render this unsafely
    bio: user.bio 
  });
});

// Vulnerable route: POST user bio without sanitization
router.post('/update-bio', (req, res) => {
  const { username, bio } = req.body;
  
  // No input validation or sanitization (XSS and injection risk)
  users.push({ id: users.length + 1, username, bio });
  
  // Unsafe use of eval (code injection risk)
  if (req.query.debug) {
    eval(req.query.debug); // Dangerous: Executes arbitrary code
  }
  
  res.redirect(`/profile/${username}`);
});

// Vulnerable route: Insecure regex (ReDoS risk)
router.get('/search', (req, res) => {
  const query = req.query.q;
  // Vulnerable regex: Can cause ReDoS with input like "a+a+a+a+..."
  const dangerousRegex = /^([a-zA-Z0-9]+)+$/;
  if (query && dangerousRegex.test(query)) {
    res.send(`Search results for: ${query}`);
  } else {
    res.status(400).send('Invalid search query');
  }
});

// Vulnerable route: Exposing sensitive data
router.get('/admin/config', (req, res) => {
  // Exposes hardcoded secrets (will be flagged)
  res.json({
    apiKey: SECRET_API_KEY,
    adminPassword: ADMIN_PASSWORD
  });
});

// Vulnerable route: Unhandled file upload
router.post('/upload', (req, res) => {
  // No validation of file type or size (potential for malicious uploads)
  if (req.files && req.files.upload) {
    const fileContent = req.files.upload.data.toString();
    // Unsafe: Could execute scripts if file contains malicious JS
    res.send(`Uploaded file content: ${fileContent}`);
  } else {
    res.status(400).send('No file uploaded');
  }
});

module.exports = router;