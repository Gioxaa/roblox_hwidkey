'use strict';

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const [, , tokenArg, hwidArg] = process.argv;

if (!tokenArg || !hwidArg) {
  console.error('Usage: node verify-offline.js "<TOKEN>" "<HWID>"');
  process.exit(1);
}

const issuer = process.env.JWT_ISSUER;
const audience = process.env.JWT_AUDIENCE;

if (!issuer || !audience) {
  console.error('JWT_ISSUER and JWT_AUDIENCE must be set in the environment or .env file.');
  process.exit(1);
}

const publicKeyPath = path.resolve(process.env.PUBLIC_KEY_PATH || './keys/public.pem');

let publicKey;
try {
  publicKey = fs.readFileSync(publicKeyPath, 'utf8');
} catch (err) {
  console.error(`Failed to read public key at ${publicKeyPath}: ${err.message}`);
  process.exit(1);
}

try {
  const payload = jwt.verify(tokenArg, publicKey, {
    algorithms: ['RS256'],
    issuer,
    audience,
  });

  if (payload.sub !== 'license') {
    console.log(JSON.stringify({ ok: false, reason: 'invalid_or_expired' }));
    process.exit(0);
  }

  if (payload.hwid !== hwidArg) {
    console.log(JSON.stringify({ ok: false, reason: 'hwid_mismatch' }));
    process.exit(0);
  }

  console.log(JSON.stringify({ ok: true, plan: payload.plan || null, exp: payload.exp }));
} catch (err) {
  const reason = err && err.name === 'TokenExpiredError' ? 'invalid_or_expired' : 'invalid_or_expired';
  console.log(JSON.stringify({ ok: false, reason }));
}
