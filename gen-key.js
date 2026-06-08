#!/usr/bin/env node
/**
 * Generate self-signed certificate for SAML signing.
 * Run: node gen-key.js
 */
const { execSync } = require('child_process');
const fs = require('fs');

console.log('🔐 Generating certificate...');

execSync(`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 3650 -nodes \
  -subj "/C=ID/ST=Jakarta/L=Jakarta/O=Etteum/CN=sso.etteum.tech"`, {
  stdio: 'inherit'
});

console.log('');
console.log('✅ Generated:');
console.log('   cert.pem  (certificate)');
console.log('   key.pem   (private key)');
console.log('');
console.log('Next: npm start');
