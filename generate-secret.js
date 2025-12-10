// Generate secure random secret
const crypto = require('crypto');
const secret = crypto.randomBytes(32).toString('hex');
console.log('\n🔐 New SESSION_SECRET generated:');
console.log(secret);
console.log('\n✅ Copy this value to your .env file\n');
