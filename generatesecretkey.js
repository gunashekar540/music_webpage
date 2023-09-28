// generateSecretKey.js
const crypto = require('crypto');

// Generate a random secret key
const secretKey = crypto.randomBytes(32).toString('hex');

console.log('Generated Secret Key:', secretKey);

// Export the generated secret key
module.exports = secretKey;
