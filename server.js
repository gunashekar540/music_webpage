const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const db = require('./database');
const app = express();
app.use(express.static('my-auth-app'));
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: '4d7243c33eb1ddaa0e85c6ec8d90122bc8082bc07b8abb7252fca45cbefc5c73', resave: true, saveUninitialized: true }));

// Define a route for GET request to /signup
app.get('/signup', (req, res) => {
  res.sendFile(__dirname + '/signup.html');
});

// Define a route for GET request to /login
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

// Define a route for GET request to /index
app.get('/index', (req, res) => {
  // Check if the user is logged in
  if (!req.session.userId) {
    return res.redirect('/login'); // Redirect to login if not logged in
  }
  res.sendFile(__dirname + '/index.html');
});

// Signup Endpoint
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if email is already in use
  const user = await getUserByEmail(email);
  if (user) {
    return res.status(400).send('Email already in use');
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store user in the database
  db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
    if (err) {
      return res.status(500).send('Error signing up');
    }
    
    // Redirect to the login page after successful signup
    res.redirect('/login');
  });
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Retrieve user by email
  const user = await getUserByEmail(email);
  if (!user) {
    return res.status(401).send('Invalid email or password');
  }

  // Compare hashed password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).send('Invalid email or password');
  }

  // Set the user's session
  req.session.userId = user.id;

  // Redirect to index.html after successful login
  res.redirect('/index');
});

// Helper function to retrieve user by email
function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        reject(err);
      }
      resolve(row);
    });
  });
}
// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});