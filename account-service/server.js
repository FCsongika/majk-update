'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 3100);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 30);
const USERNAME_PATTERN = /^[A-Za-z0-9_]{3,16}$/;
const PASSWORD_MIN_LENGTH = 10;
const TOKEN_PATTERN = /^[a-f0-9]{64}$/;

if (!DATABASE_URL) throw new Error('Set DATABASE_URL before starting the account service.');
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('PORT must be a valid TCP port.');
if (!Number.isInteger(SESSION_TTL_DAYS) || SESSION_TTL_DAYS < 1 || SESSION_TTL_DAYS > 365) {
  throw new Error('SESSION_TTL_DAYS must be between 1 and 365.');
}

const pool = new Pool({ connectionString: DATABASE_URL });
const app = express();
const attempts = new Map();

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(helmet());
app.use(express.json({ limit: '8kb', strict: true }));

function fail(res, status, message) {
  return res.status(status).json({ error: message });
}

function rateLimit({ limit, windowMs }) {
  return (req, res, next) => {
    const key = `${req.path}:${req.ip || req.socket.remoteAddress || 'unknown'}`;
    const now = Date.now();
    if (attempts.size > 10000) {
      for (const [entryKey, entry] of attempts) {
        if (entry.resetAt <= now) attempts.delete(entryKey);
      }
    }
    const current = attempts.get(key);
    if (!current || current.resetAt <= now) {
      attempts.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }
    current.count += 1;
    if (current.count > limit) {
      res.set('Retry-After', String(Math.ceil((current.resetAt - now) / 1000)));
      fail(res, 429, 'Túl sok próbálkozás. Várj, majd próbáld újra.');
      return;
    }
    next();
  };
}

function validCredentials(body) {
  if (!body || typeof body.username !== 'string' || !USERNAME_PATTERN.test(body.username)) {
    return 'A felhasználónév 3–16 angol betű, szám vagy aláhúzás legyen.';
  }
  if (typeof body.password !== 'string' || body.password.length < PASSWORD_MIN_LENGTH
    || body.password.length > 128) {
    return `A jelszó ${PASSWORD_MIN_LENGTH}–128 karakter legyen.`;
  }
  return null;
}

function hashPassword(password, salt = crypto.randomBytes(16)) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(`scrypt$32768$8$1$${salt.toString('hex')}$${derivedKey.toString('hex')}`);
    });
  });
}

async function verifyPassword(password, storedHash) {
  const [algorithm, n, r, p, saltHex, keyHex] = storedHash.split('$');
  if (algorithm !== 'scrypt' || n !== '32768' || r !== '8' || p !== '1'
    || !/^[a-f0-9]{32}$/.test(saltHex) || !/^[a-f0-9]{128}$/.test(keyHex)) {
    throw new Error('The stored password hash has an unsupported format.');
  }
  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(password, Buffer.from(saltHex, 'hex'), 64,
      { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
      (error, derivedKey) => error ? reject(error) : resolve(derivedKey));
  });
  return crypto.timingSafeEqual(actual, Buffer.from(keyHex, 'hex'));
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(accountId, queryable = pool) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
  await queryable.query(
    'INSERT INTO sessions (token_hash, account_id, expires_at) VALUES ($1, $2, $3)',
    [hashToken(token), accountId, expiresAt]
  );
  return { token, expiresAt: expiresAt.toISOString() };
}

async function authenticate(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = /^Bearer ([a-f0-9]{64})$/.exec(authorization);
  if (!match || !TOKEN_PATTERN.test(match[1])) {
    fail(res, 401, 'Jelentkezz be a folytatáshoz.');
    return;
  }
  try {
    const result = await pool.query(
      `SELECT a.id, a.username
       FROM sessions s JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [hashToken(match[1])]
    );
    if (!result.rowCount) {
      fail(res, 401, 'A bejelentkezés lejárt. Jelentkezz be újra.');
      return;
    }
    req.account = result.rows[0];
    req.tokenHash = hashToken(match[1]);
    next();
  } catch (error) {
    next(error);
  }
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', rateLimit({ limit: 8, windowMs: 15 * 60 * 1000 }), async (req, res, next) => {
  const errorMessage = validCredentials(req.body);
  if (errorMessage) return fail(res, 400, errorMessage);
  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query('BEGIN');
    const passwordHash = await hashPassword(req.body.password);
    const result = await client.query(
      `INSERT INTO accounts (username, username_key, password_hash)
       VALUES ($1, $2, $3)
       ON CONFLICT (username_key) DO NOTHING
       RETURNING id, username`,
      [req.body.username, req.body.username.toLowerCase(), passwordHash]
    );
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return fail(res, 409, 'Ez a felhasználónév már foglalt.');
    }
    const session = await createSession(result.rows[0].id, client);
    await client.query('COMMIT');
    return res.status(201).json({ ...session, user: result.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', rateLimit({ limit: 10, windowMs: 15 * 60 * 1000 }), async (req, res, next) => {
  const errorMessage = validCredentials(req.body);
  if (errorMessage) return fail(res, 400, errorMessage);
  try {
    const result = await pool.query(
      'SELECT id, username, password_hash FROM accounts WHERE username_key = $1',
      [req.body.username.toLowerCase()]
    );
    const account = result.rows[0];
    const valid = account
      ? await verifyPassword(req.body.password, account.password_hash)
      : await verifyPassword(req.body.password, await hashPassword('dummy-password-value'));
    if (!account || !valid) return fail(res, 401, 'A felhasználónév vagy a jelszó nem megfelelő.');
    const session = await createSession(account.id);
    return res.json({ ...session, user: { id: account.id, username: account.username } });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: { id: req.account.id, username: req.account.username } });
});

app.post('/api/auth/logout', authenticate, async (req, res, next) => {
  try {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [req.tokenHash]);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/profiles', authenticate, async (req, res, next) => {
  const username = typeof req.query.username === 'string' ? req.query.username.trim() : '';
  if (!USERNAME_PATTERN.test(username)) return fail(res, 400, 'Adj meg érvényes felhasználónevet.');
  try {
    const result = await pool.query(
      `SELECT id, username FROM accounts
       WHERE username_key = $1 AND id <> $2`,
      [username.toLowerCase(), req.account.id]
    );
    if (!result.rowCount) return fail(res, 404, 'Nem található ilyen MajkClient-fiók.');
    const target = result.rows[0];
    const friendship = await pool.query(
      `SELECT 1 FROM friendships
       WHERE account_low = LEAST($1::bigint, $2::bigint)
         AND account_high = GREATEST($1::bigint, $2::bigint)`,
      [req.account.id, target.id]
    );
    const request = await pool.query(
      `SELECT sender_id, status FROM friend_requests
       WHERE LEAST(sender_id, recipient_id) = LEAST($1::bigint, $2::bigint)
         AND GREATEST(sender_id, recipient_id) = GREATEST($1::bigint, $2::bigint)
       ORDER BY created_at DESC LIMIT 1`,
      [req.account.id, target.id]
    );
    return res.json({
      profile: target,
      relationship: friendship.rowCount ? 'friends'
        : request.rows[0]?.status === 'pending'
          ? request.rows[0].sender_id === req.account.id ? 'outgoing-request' : 'incoming-request'
          : 'none'
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/friends/requests', authenticate, async (req, res, next) => {
  const username = req.body && typeof req.body.username === 'string' ? req.body.username.trim() : '';
  if (!USERNAME_PATTERN.test(username)) return fail(res, 400, 'Adj meg érvényes felhasználónevet.');
  try {
    const targetResult = await pool.query(
      'SELECT id, username FROM accounts WHERE username_key = $1',
      [username.toLowerCase()]
    );
    const target = targetResult.rows[0];
    if (!target) return fail(res, 404, 'Nem található ilyen MajkClient-fiók.');
    if (target.id === req.account.id) return fail(res, 400, 'Saját magadnak nem küldhetsz barátkérelmet.');
    const low = Math.min(Number(req.account.id), Number(target.id));
    const high = Math.max(Number(req.account.id), Number(target.id));
    const friendship = await pool.query(
      'SELECT 1 FROM friendships WHERE account_low = $1 AND account_high = $2',
      [low, high]
    );
    if (friendship.rowCount) return fail(res, 409, 'Ez a felhasználó már a barátod.');
    const existing = await pool.query(
      `SELECT id, sender_id FROM friend_requests
       WHERE LEAST(sender_id, recipient_id) = $1 AND GREATEST(sender_id, recipient_id) = $2
         AND status = 'pending' LIMIT 1`,
      [low, high]
    );
    if (existing.rowCount) {
      if (existing.rows[0].sender_id === target.id) {
        return fail(res, 409, 'Már kaptál ettől a felhasználótól kérelmet; kezeld a Barátkérelmek fülön.');
      }
      return fail(res, 409, 'Már küldtél ennek a felhasználónak barátkérelmet.');
    }
    const inserted = await pool.query(
      `INSERT INTO friend_requests (sender_id, recipient_id)
       VALUES ($1, $2) RETURNING id, created_at`,
      [req.account.id, target.id]
    );
    return res.status(201).json({ status: 'pending', requestId: inserted.rows[0].id });
  } catch (error) {
    if (error.code === '23505') return fail(res, 409, 'Ehhez a felhasználóhoz már van függőben lévő barátkérelem.');
    return next(error);
  }
});

app.get('/api/friends', authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.username, f.created_at
       FROM friendships f
       JOIN accounts a ON a.id = CASE WHEN f.account_low = $1 THEN f.account_high ELSE f.account_low END
       WHERE f.account_low = $1 OR f.account_high = $1
       ORDER BY a.username_key`,
      [req.account.id]
    );
    return res.json({ friends: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/friends/requests', authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT r.id,
              CASE WHEN r.sender_id = $1 THEN r.recipient_id ELSE r.sender_id END AS account_id,
              CASE WHEN r.sender_id = $1 THEN 'sent' ELSE 'received' END AS direction,
              a.username, r.created_at
       FROM friend_requests r
       JOIN accounts a ON a.id = CASE WHEN r.sender_id = $1 THEN r.recipient_id ELSE r.sender_id END
       WHERE (r.recipient_id = $1 OR r.sender_id = $1) AND r.status = 'pending'
       ORDER BY r.created_at DESC`,
      [req.account.id]
    );
    return res.json({ requests: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/friends/requests/:id/respond', authenticate, async (req, res, next) => {
  if (!/^\d{1,18}$/.test(req.params.id) || !['accept', 'decline'].includes(req.body && req.body.action)) {
    return fail(res, 400, 'A kérelem művelete érvénytelen.');
  }
  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT id, sender_id, recipient_id FROM friend_requests
       WHERE id = $1 AND recipient_id = $2 AND status = 'pending' FOR UPDATE`,
      [req.params.id, req.account.id]
    );
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return fail(res, 404, 'A barátkérelem nem található.');
    }
    const request = result.rows[0];
    const accepted = req.body.action === 'accept';
    await client.query(
      `UPDATE friend_requests SET status = $1, responded_at = NOW() WHERE id = $2`,
      [accepted ? 'accepted' : 'declined', request.id]
    );
    if (accepted) {
      const low = Math.min(Number(request.sender_id), Number(request.recipient_id));
      const high = Math.max(Number(request.sender_id), Number(request.recipient_id));
      await client.query(
        'INSERT INTO friendships (account_low, account_high) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [low, high]
      );
    }
    await client.query('COMMIT');
    return res.json({ status: accepted ? 'accepted' : 'declined' });
  } catch (error) {
    await client.query('ROLLBACK');
    return next(error);
  } finally {
    client.release();
  }
});

app.delete('/api/friends/:id', authenticate, async (req, res, next) => {
  if (!/^\d{1,18}$/.test(req.params.id)) return fail(res, 400, 'A felhasználóazonosító érvénytelen.');
  try {
    const result = await pool.query(
      `DELETE FROM friendships
       WHERE account_low = LEAST($1::bigint, $2::bigint)
         AND account_high = GREATEST($1::bigint, $2::bigint)
       RETURNING account_low`,
      [req.account.id, req.params.id]
    );
    if (!result.rowCount) return fail(res, 404, 'Ez a felhasználó nincs a barátaid között.');
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  return fail(res, 500, 'Szerverhiba történt. Próbáld újra később.');
});

async function start() {
  const schema = await fs.readFile(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  app.listen(PORT, '0.0.0.0', () => console.log(`MajkClient account API listening on port ${PORT}`));
}

start().catch((error) => {
  console.error('Account service failed to start:', error);
  process.exitCode = 1;
});
