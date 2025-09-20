'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

const config = loadConfig();
let adminPassHash;
let revokedSet = new Set();
let persistQueue = Promise.resolve();

async function main() {
  await initializeAdminPassword();
  await ensureStorage();
  revokedSet = await loadRevokedSet(config.revokedFilePath);
  const app = createApp();

  app.listen(config.port, () => {
    console.log(`HWID license server listening on port ${config.port}`);
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});

function loadConfig() {
  const env = process.env.NODE_ENV || 'production';
  const port = parsePositiveInt(process.env.PORT || '4000', undefined, 'PORT');

  const adminUser = requireEnv('ADMIN_USER');
  const adminPass = requireEnv('ADMIN_PASS');
  const issuer = requireEnv('JWT_ISSUER');
  const audience = requireEnv('JWT_AUDIENCE');
  const kid = requireEnv('JWT_KID');

  const privateKeyPath = path.resolve(process.env.PRIVATE_KEY_PATH || './keys/private.pem');
  const publicKeyPath = path.resolve(process.env.PUBLIC_KEY_PATH || './keys/public.pem');

  const privateKey = readKey(privateKeyPath, 'private');
  const publicKey = readKey(publicKeyPath, 'public');

  const dataDir = path.resolve('./data');
  const logDir = path.join(dataDir, 'logs');
  const revokedFilePath = path.join(dataDir, 'revoked.json');
  const issuedLogPath = path.join(logDir, 'issued.jsonl');
  const revokedLogPath = path.join(logDir, 'revoked.jsonl');

  const rateMaxPerMin = parsePositiveInt(process.env.RATE_MAX_PER_MIN, 120, 'RATE_MAX_PER_MIN');
  const slowAfterPerMin = parsePositiveInt(process.env.SLOW_AFTER_PER_MIN, 20, 'SLOW_AFTER_PER_MIN');
  const slowDelayMs = parsePositiveInt(process.env.SLOW_DELAY_MS, 200, 'SLOW_DELAY_MS');

  const corsOrigins = (process.env.CORS_ORIGINS || '*')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);

  const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);

  return {
    env,
    port,
    adminUser,
    adminPass,
    issuer,
    audience,
    kid,
    privateKey,
    publicKey,
    privateKeyPath,
    publicKeyPath,
    dataDir,
    logDir,
    revokedFilePath,
    issuedLogPath,
    revokedLogPath,
    rateMaxPerMin,
    slowAfterPerMin,
    slowDelayMs,
    corsOrigins,
    trustProxy,
  };
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set`);
  }
  return value;
}

function parsePositiveInt(value, fallback, label) {
  if (value === undefined || value === null || value === '') {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error(`${label} must be a positive integer`);
  }

  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function parseTrustProxy(value) {
  if (value === undefined || value === null || value.trim() === '') {
    return 'loopback';
  }
  const trimmed = value.trim().toLowerCase();
  if (trimmed === 'false') {
    return false;
  }
  if (trimmed === 'true') {
    return 1;
  }
  const numeric = Number(trimmed);
  if (!Number.isNaN(numeric)) {
    return numeric;
  }
  return value.trim();
}

function readKey(filePath, label) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(`Failed to read ${label} key at ${filePath}: ${err.message}`);
  }
}

async function initializeAdminPassword() {
  const raw = config.adminPass;
  if (raw.startsWith('$2a$')) {
    adminPassHash = raw;
  } else {
    adminPassHash = await bcrypt.hash(raw, 12);
  }
  config.adminPass = undefined;
}

async function ensureStorage() {
  await fsp.mkdir(config.dataDir, { recursive: true });
  await fsp.mkdir(config.logDir, { recursive: true });
  await ensureFileExists(config.revokedFilePath, '[]');
  await ensureFileExists(config.issuedLogPath, '');
  await ensureFileExists(config.revokedLogPath, '');
}

async function ensureFileExists(filePath, defaultContent) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
  } catch (err) {
    if (err.code === 'ENOENT') {
      await fsp.writeFile(filePath, defaultContent, { encoding: 'utf8' });
    } else {
      throw err;
    }
  }
}

async function loadRevokedSet(filePath) {
  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    if (!raw.trim()) {
      return new Set();
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error('revoked.json must contain a JSON array');
    }
    const entries = parsed.filter((entry) => typeof entry === 'string' && entry.length > 0);
    return new Set(entries);
  } catch (err) {
    if (err.code === 'ENOENT') {
      const emptySet = new Set();
      await persistRevokedSet(filePath, emptySet);
      return emptySet;
    }
    if (err.name === 'SyntaxError') {
      throw new Error(`revoked.json contains invalid JSON: ${err.message}`);
    }
    throw err;
  }
}

async function persistRevokedSet(filePath, set) {
  const items = Array.from(set);
  items.sort();
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fsp.writeFile(tmpPath, JSON.stringify(items), { encoding: 'utf8' });
  await fsp.rename(tmpPath, filePath);
}

function queueRevokedPersist() {
  const task = persistQueue.then(() => persistRevokedSet(config.revokedFilePath, revokedSet));
  persistQueue = task.catch((err) => {
    persistQueue = Promise.resolve();
    throw err;
  });
  return task;
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  app.use(helmet());

  if (config.corsOrigins.length === 1 && config.corsOrigins[0] === '*') {
    app.use(cors({ origin: '*' }));
  } else {
    app.use(cors({ origin: config.corsOrigins, optionsSuccessStatus: 204 }));
  }

  app.use(morgan('combined'));
  app.use(compression());
  app.use(express.json({ limit: '256kb' }));

  const limiter = rateLimit({
    windowMs: 60_000,
    max: config.rateMaxPerMin,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    trustProxy: config.trustProxy,
    handler: (req, res, _next, options) => {
      res.status(options.statusCode).json({ reason: 'rate_limited' });
    },
  });

  const slowdown = slowDown({
    windowMs: 60_000,
    delayAfter: config.slowAfterPerMin,
    delayMs: () => config.slowDelayMs,
    maxDelayMs: config.slowDelayMs,
    validate: { delayMs: false },
  });

  app.use(limiter);
  app.use(slowdown);

  app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.post('/issue', requireAdmin, async (req, res, next) => {
    try {
      const { hwid, ttlSeconds, plan, note } = req.body || {};

      if (typeof hwid !== 'string' || hwid.trim().length === 0 || hwid.length > 256) {
        return res.status(400).json({ reason: 'invalid_hwid' });
      }

      const ttl = Number(ttlSeconds);
      if (!Number.isFinite(ttl) || !Number.isInteger(ttl) || ttl < 60 || ttl > 5184000) {
        return res.status(400).json({ reason: 'invalid_ttl' });
      }

      const hwidValue = hwid.trim();
      const planValue = typeof plan === 'string' && plan.trim().length > 0 ? plan.trim() : undefined;
      const noteValue = typeof note === 'string' && note.trim().length > 0 ? note.trim() : undefined;

      const jti = typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `${Date.now().toString(36)}-${crypto.randomBytes(8).toString('hex')}`;

      const issuedAt = Math.floor(Date.now() / 1000);
      const exp = issuedAt + ttl;

      const payload = { hwid: hwidValue };
      if (planValue) {
        payload.plan = planValue;
      }

      const token = jwt.sign(payload, config.privateKey, {
        algorithm: 'RS256',
        issuer: config.issuer,
        audience: config.audience,
        expiresIn: ttl,
        header: { kid: config.kid },
        jwtid: jti,
        subject: 'license',
      });

      await appendJsonLine(config.issuedLogPath, {
        ts: new Date().toISOString(),
        ip: getClientIp(req),
        jti,
        hwid: hwidValue,
        plan: planValue || null,
        exp,
        note: noteValue || null,
      });

      res.json({ token, jti, exp });
    } catch (err) {
      next(err);
    }
  });

  app.post('/verify', async (req, res, next) => {
    try {
      const { token, hwid } = req.body || {};
      if (typeof token !== 'string' || token.trim().length === 0 || typeof hwid !== 'string' || hwid.trim().length === 0) {
        return res.status(400).json({ ok: false, reason: 'invalid_payload' });
      }

      const hwidValue = hwid.trim();

      let payload;
      try {
        payload = jwt.verify(token, config.publicKey, {
          algorithms: ['RS256'],
          issuer: config.issuer,
          audience: config.audience,
        });
      } catch (err) {
        return res.status(200).json({ ok: false, reason: 'invalid_or_expired' });
      }

      if (payload.sub !== 'license') {
        return res.status(200).json({ ok: false, reason: 'invalid_or_expired' });
      }

      if (typeof payload.jti !== 'string') {
        return res.status(200).json({ ok: false, reason: 'invalid_or_expired' });
      }

      if (payload.hwid !== hwidValue) {
        return res.status(200).json({ ok: false, reason: 'hwid_mismatch' });
      }

      if (revokedSet.has(payload.jti)) {
        return res.status(200).json({ ok: false, reason: 'revoked' });
      }

      res.json({ ok: true, plan: payload.plan || null, exp: payload.exp });
    } catch (err) {
      next(err);
    }
  });

  app.post('/revoke', requireAdmin, async (req, res, next) => {
    try {
      const { jti } = req.body || {};
      if (typeof jti !== 'string' || jti.trim().length === 0) {
        return res.status(400).json({ reason: 'invalid_jti' });
      }

      const id = jti.trim();
      const alreadyRevoked = revokedSet.has(id);
      if (!alreadyRevoked) {
        revokedSet.add(id);
        await queueRevokedPersist();
        await appendJsonLine(config.revokedLogPath, {
          ts: new Date().toISOString(),
          ip: getClientIp(req),
          jti: id,
        });
      }

      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  app.get('/status/:jti', (req, res) => {
    const { jti } = req.params;
    const revoked = typeof jti === 'string' && revokedSet.has(jti.trim());
    res.json({ revoked: Boolean(revoked) });
  });

  app.use((req, res) => {
    res.status(404).json({ reason: 'not_found' });
  });

  app.use((err, req, res, next) => {
    console.error('Unhandled error processing request:', err);
    if (res.headersSent) {
      return next(err);
    }
    return res.status(500).json({ reason: 'server_error' });
  });

  return app;
}

function sendUnauthorized(res) {
  res.set('WWW-Authenticate', 'Basic realm="admin", charset="UTF-8"');
  return res.status(401).json({ reason: 'unauthorized' });
}

async function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (typeof header !== 'string' || !header.startsWith('Basic ')) {
      return sendUnauthorized(res);
    }

    const base64 = header.slice(6);
    let decoded;
    try {
      decoded = Buffer.from(base64, 'base64').toString('utf8');
    } catch (err) {
      return sendUnauthorized(res);
    }

    const separatorIndex = decoded.indexOf(':');
    if (separatorIndex === -1) {
      return sendUnauthorized(res);
    }

    const username = decoded.slice(0, separatorIndex);
    const password = decoded.slice(separatorIndex + 1);
    if (username !== config.adminUser) {
      return sendUnauthorized(res);
    }

    const match = await bcrypt.compare(password, adminPassHash);
    if (!match) {
      return sendUnauthorized(res);
    }

    return next();
  } catch (err) {
    return next(err);
  }
}

async function appendJsonLine(filePath, payload) {
  const line = `${JSON.stringify(payload)}\n`;
  await fsp.appendFile(filePath, line, { encoding: 'utf8' });
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return forwarded[0];
  }
  return req.ip;
}
