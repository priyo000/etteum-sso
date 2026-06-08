#!/usr/bin/env node
/**
 * Minimal SAML IdP for etteum.tech
 *
 * Flow yang kamu mau:
 *   User buka chatgpt.com → Sign in with SSO
 *   → Input: budi (otomatis jadi budi@etteum.tech)
 *   → Langsung masuk. No OTP, no verification.
 *
 * Setup:
 *   1. npm install
 *   2. node gen-key.js
 *   3. Set env: export SP_ENTITY_ID="..." SP_ACS_URL="..."
 *   4. npm start
 *   5. Deploy, arahkan sso.etteum.tech ke server ini
 *   6. Upload /metadata ke ChatGPT Team SSO
 */

const express = require('express');
const bodyParser = require('body-parser');
const { SignedXml } = require('xml-crypto');
const { parseStringPromise } = require('xml2js');
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const { promisify } = require('util');

const inflate = promisify(zlib.inflateRaw);

// ═══════════════════════════════════════════
// Konfigurasi
// ═══════════════════════════════════════════
const CONFIG = {
  ALLOWED_DOMAIN: 'etteum.tech',
  IDP_BASE_URL: process.env.IDP_BASE_URL || 'https://sso.etteum.tech',
  SP_ENTITY_ID: process.env.SP_ENTITY_ID || 'vb8vR1EybcREB1tkJYinejQfu',
  SP_ACS_URL: process.env.SP_ACS_URL || 'https://external.auth.openai.com/sso/saml/acs/vb8vR1EybcREB1tkJYinejQfu',
  PORT: parseInt(process.env.PORT || '3000'),
};

// Load cert & key (auto-generate kalau belum ada)
let CERT_PEM, PRIVATE_KEY;
const certPath = './cert.pem';
const keyPath = './key.pem';

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.log('🔐 Certificate not found, generating...');
  const { execSync } = require('child_process');
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} \
    -days 3650 -nodes -subj "/C=ID/O=Etteum/CN=sso.etteum.tech"`, { stdio: 'pipe' });
  console.log('✅ Certificate generated');
}
CERT_PEM = fs.readFileSync(certPath, 'utf8');
PRIVATE_KEY = fs.readFileSync(keyPath, 'utf8');

const CERT_B64 = CERT_PEM
  .replace(/-----BEGIN CERTIFICATE-----/, '')
  .replace(/-----END CERTIFICATE-----/, '')
  .replace(/\s/g, '');

// ═══════════════════════════════════════════
// App
// ═══════════════════════════════════════════
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(__dirname));

// ─── Metadata endpoint ───
app.get('/metadata', (req, res) => {
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="${CONFIG.IDP_BASE_URL}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>${CERT_B64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${CONFIG.IDP_BASE_URL}/sso"/>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${CONFIG.IDP_BASE_URL}/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`);
});

// ─── GET /sso → show login form ───
app.get('/sso', (req, res) => {
  const samlRequest = req.query.SAMLRequest || '';
  const relayState = req.query.RelayState || '';

  res.send(`<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>etteum.tech - SSO Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0d1117;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      padding: 20px;
    }
    .card {
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 20px;
      padding: 50px 40px;
      width: 100%;
      max-width: 420px;
    }
    .header {
      text-align: center;
      margin-bottom: 40px;
    }
    .logo-img {
      width: 80px;
      height: 80px;
      margin: 0 auto 20px;
      display: block;
    }
    .logo {
      font-size: 36px;
      font-weight: 800;
      color: #fff;
      margin-bottom: 16px;
      letter-spacing: -1px;
    }
    .logo span {
      color: #2ea043;
    }
    .subtitle {
      display: inline-block;
      background: #2ea043;
      color: #fff;
      padding: 8px 24px;
      border-radius: 50px;
      font-size: 15px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1.5px;
    }
    .form-group {
      margin-bottom: 24px;
    }
    label {
      display: block;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 600;
      color: #c9d1d9;
    }
    input[type="email"] {
      width: 100%;
      padding: 16px 20px;
      border: 2px solid #30363d;
      border-radius: 12px;
      background: #0d1117;
      color: #fff;
      font-size: 16px;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="email"]:focus {
      border-color: #2ea043;
    }
    input[type="email"]::placeholder {
      color: #484f58;
    }
    button {
      width: 100%;
      padding: 16px;
      background: #2ea043;
      color: #fff;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover {
      background: #3fb950;
    }
    button:active {
      background: #238636;
    }
    .info {
      margin-top: 24px;
      padding: 16px;
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 12px;
      text-align: center;
    }
    .info p {
      font-size: 13px;
      color: #8b949e;
      line-height: 1.6;
    }
    .info strong {
      color: #2ea043;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <img src="/logo.png" alt="etteum.tech" class="logo-img">
      <div class="logo">etteum<span>.tech</span></div>
      <div class="subtitle">🎉 INI GRATISSSS!!! 🎉</div>
    </div>
    <form method="POST" action="/sso">
      <input type="hidden" name="SAMLRequest" value="${samlRequest}">
      <input type="hidden" name="RelayState" value="${relayState}">
      <div class="form-group">
        <label for="email">Email SSO</label>
        <input type="email" id="email" name="email"
               placeholder="nama@etteum.tech" required autofocus>
      </div>
      <button type="submit">Masuk Sekarang</button>
    </form>
    <div class="info">
      <p>
        Login dengan email <strong>@etteum.tech</strong><br>
        Akses ChatGPT Team gratis!
      </p>
    </div>
  </div>
</body>
</html>`);
});

// ─── POST /sso → generate SAML response & redirect ───
app.post('/sso', async (req, res) => {
  const rawInput = (req.body.email || '').trim().toLowerCase();
  const samlRequest = req.body.SAMLRequest || '';
  const relayState = req.body.RelayState || '';

  // Parse SAML request
  let acsUrl = CONFIG.SP_ACS_URL;
  let requestID = '';
  let spIssuer = CONFIG.SP_ENTITY_ID;

  if (samlRequest) {
    try {
      const decoded = Buffer.from(samlRequest, 'base64');
      const xml = (await inflate(decoded)).toString();
      const parsed = await parseStringPromise(xml, { explicitArray: false });

      const authnReq = parsed['samlp:AuthnRequest'] || parsed['AuthnRequest'] || {};
      requestID = authnReq.$?.ID || '';
      acsUrl = authnReq.$?.AssertionConsumerServiceURL || acsUrl;

      const issuer = authnReq['saml:Issuer'] || authnReq['Issuer'];
      if (issuer) spIssuer = typeof issuer === 'string' ? issuer : issuer._ || '';
    } catch (e) {
      console.error('Parse SAML request error:', e.message);
    }
  }

  if (!acsUrl) {
    return res.status(400).send('ACS URL not configured. Set SP_ACS_URL env.');
  }

  // Build email from full email input
  let email, username;
  if (rawInput.includes('@')) {
    // User input full email like budi@etteum.tech
    email = rawInput;
    username = rawInput.split('@')[0];
    const domain = rawInput.split('@')[1];
    if (domain !== CONFIG.ALLOWED_DOMAIN) {
      return res.status(400).send(`❌ Domain tidak valid. Gunakan @${CONFIG.ALLOWED_DOMAIN}`);
    }
  } else {
    // User input just username like "budi"
    username = rawInput.replace(/[^a-z0-9._-]/g, '');
    email = `${username}@${CONFIG.ALLOWED_DOMAIN}`;
  }
  if (!username) {
    return res.status(400).send('❌ Email tidak valid');
  }
  const displayName = username.charAt(0).toUpperCase() + username.slice(1);

  // Build SAML Response
  const now = new Date();
  const notAfter = new Date(now.getTime() + 5 * 60 * 1000);
  const responseID = '_' + crypto.randomBytes(16).toString('hex');
  const assertionID = '_' + crypto.randomBytes(16).toString('hex');

  const samlResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseID}" Version="2.0" IssueInstant="${now.toISOString()}" Destination="${acsUrl}" InResponseTo="${requestID}"><saml:Issuer>${CONFIG.IDP_BASE_URL}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="${assertionID}" IssueInstant="${now.toISOString()}"><saml:Issuer>${CONFIG.IDP_BASE_URL}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notAfter.toISOString()}" Recipient="${acsUrl}" InResponseTo="${requestID}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${now.toISOString()}" NotOnOrAfter="${notAfter.toISOString()}"><saml:AudienceRestriction><saml:Audience>${spIssuer}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${assertionID}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>${displayName}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue>${displayName}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

  // Sign
  const signed = signXml(samlResponse, responseID);
  const base64Response = Buffer.from(signed).toString('base64');

  // Auto-submit
  res.send(`<!DOCTYPE html>
<html><head><title>Redirecting...</title></head>
<body>
<form id="saml" method="POST" action="${acsUrl}">
  <input type="hidden" name="SAMLResponse" value="${base64Response}">
  <input type="hidden" name="RelayState" value="${relayState}">
</form>
<script>document.getElementById('saml').submit();</script>
</body></html>`);

  console.log(`✅ ${email} logged in`);
});

// ─── Sign XML ───
function signXml(xml, refId) {
  const sig = new SignedXml();
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.addReference({
    xpath: `//*[@ID='${refId}']`,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.privateKey = PRIVATE_KEY;
  sig.publicCert = CERT_PEM;
  sig.keyInfoProvider = {
    getKeyInfo: () => `<X509Data><X509Certificate>${CERT_B64}</X509Certificate></X509Data>`,
  };

  sig.computeSignature(xml, {
    prefix: 'ds',
    location: { reference: "//*[local-name()='Issuer']", action: 'after' },
  });

  return sig.getSignedXml();
}

// ─── Health ───
app.get('/', (req, res) => {
  res.json({ status: 'ok', metadata: '/metadata', sso: '/sso' });
});

// ─── Keep-alive ping (prevent Render free tier spin down) ───
const KEEPALIVE_INTERVAL = 14 * 60 * 1000; // 14 minutes (before 15min spin down)
const PING_URL = process.env.PING_URL || `http://localhost:${CONFIG.PORT}/`;

setInterval(() => {
  const url = process.env.PING_URL || `https://${CONFIG.IDP_BASE_URL.replace('https://', '')}/`;
  fetch(url)
    .then(r => console.log(`💓 Keep-alive ping: ${r.status} at ${new Date().toISOString()}`))
    .catch(e => console.error(`❌ Keep-alive failed: ${e.message}`));
}, KEEPALIVE_INTERVAL);

app.listen(CONFIG.PORT, () => {
  console.log(`
╔═══════════════════════════════════════════╗
║  Etteum SSO Identity Provider             ║
║  Port: ${CONFIG.PORT}                              ║
║  Metadata: http://localhost:${CONFIG.PORT}/metadata  ║
║  SSO:      http://localhost:${CONFIG.PORT}/sso        ║
║  Keep-alive: every 14 minutes             ║
╚═══════════════════════════════════════════╝
`);
});
