import { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { consumeChallenge, issueChallenge } from './challenges.js';
import { openDatabase } from './database.js';
import { createSession, type CounterUpdate } from './sessions.js';

const port = Number(process.env.PORT ?? 3000);
const origin = new URL(process.env.APP_ORIGIN ?? `http://localhost:${port}`);
const rpID = origin.hostname;
const db = openDatabase();
const deriveKey = promisify(scrypt);
const sessionLifetime = 60 * 60 * 24 * 7;
type User = { id: string; email: string; password_hash: string };
type Passkey = { user_id: string; credential_id: string; public_key: Uint8Array; sign_count: number };

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function json(response: ServerResponse, data: unknown, status = 200) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
}

function cookie(request: IncomingMessage, name: string) {
  return request.headers.cookie?.split(/;\s*/).find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) ?? '';
}

function setCookie(response: ServerResponse, name: string, value: string, maxAge: number) {
  const secure = origin.protocol === 'https:' ? '; Secure' : '';
  response.appendHeader('Set-Cookie', `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`);
}

function digest(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

function signIn(
  request: IncomingMessage, response: ServerResponse, userId: string, counter?: CounterUpdate,
) {
  const token = randomBytes(32).toString('base64url');
  const now = Date.now();
  const created = createSession(
    db, digest(cookie(request, 'session')), digest(token), userId, now, sessionLifetime * 1000, counter,
  );
  if (!created) throw new HttpError(400, 'パスキーを確認できませんでした。');
  setCookie(response, 'session', token, sessionLifetime);
  json(response, {});
}

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > 128 * 1024) throw new HttpError(413, 'リクエストが大きすぎます。');
    chunks.push(chunk);
  }
  try {
    const data: unknown = JSON.parse(Buffer.concat(chunks).toString());
    if (data && typeof data === 'object' && !Array.isArray(data)) return data as Record<string, unknown>;
  } catch {
    // Return the same response for malformed JSON and unsupported JSON shapes.
  }
  throw new HttpError(400, 'リクエストが無効です。');
}

async function passwordAuth(
  request: IncomingMessage, response: ServerResponse, body: Record<string, unknown>, signup: boolean,
) {
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !password ||
      password.length > 1024 || (signup && password.length < 12)) {
    throw new HttpError(400, 'メールアドレスとパスワードを確認してください。');
  }
  if (signup) {
    const id = randomUUID();
    const salt = randomBytes(16).toString('hex');
    const hash = (await deriveKey(password, salt, 64) as Buffer).toString('hex');
    const result = db.prepare('INSERT INTO users VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING')
      .run(id, email, `${salt}:${hash}`);
    if (!result.changes) throw new HttpError(409, 'アカウントを作成できませんでした。');
    return signIn(request, response, id);
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as User | undefined;
  const [salt, hash] = user?.password_hash.split(':') ?? ['0'.repeat(32), '0'.repeat(128)];
  const candidate = await deriveKey(password, salt, 64) as Buffer;
  if (!timingSafeEqual(candidate, Buffer.from(hash, 'hex')) || !user) {
    throw new HttpError(401, 'メールアドレスまたはパスワードが違います。');
  }
  return signIn(request, response, user.id);
}

async function passkey(
  request: IncomingMessage, response: ServerResponse, purpose: 'register' | 'authenticate',
  body: Record<string, unknown>, user: User | undefined, session: string,
) {
  const registration = purpose === 'register';
  if (registration && !user) throw new HttpError(401, 'ログインしてください。');
  const binding = registration ? session : null;
  const name = `passkey_${purpose}`;
  if (body.action === 'options') {
    const options = user && registration
      ? await generateRegistrationOptions({
        rpName: 'パスキー認証', rpID, userName: user.email, userID: new TextEncoder().encode(user.id),
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: (db.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?')
          .all(user.id) as Pick<Passkey, 'credential_id'>[]).map(({ credential_id }) => ({ id: credential_id })),
      })
      : await generateAuthenticationOptions({ rpID, userVerification: 'required' });
    const token = issueChallenge(db, purpose, binding, options.challenge);
    setCookie(response, name, token, 300);
    return json(response, options);
  }

  if (body.action !== 'verify') throw new HttpError(400, '操作が無効です。');
  const expectedChallenge = consumeChallenge(db, cookie(request, name), purpose, binding);
  setCookie(response, name, '', 0);
  if (!expectedChallenge) throw new HttpError(400, 'もう一度操作を開始してください。');
  const expectation = { expectedChallenge, expectedOrigin: origin.origin, expectedRPID: rpID };
  const invalid = new HttpError(400, 'パスキーを確認できませんでした。');
  if (user && registration) {
    const result = await verifyRegistrationResponse({
      ...expectation, response: body.credential as RegistrationResponseJSON, requireUserVerification: true,
    }).catch(() => { throw invalid; });
    if (!result.verified || !result.registrationInfo) throw invalid;
    const active = db.prepare('SELECT 1 FROM sessions WHERE token = ? AND expires_at > ?').get(session, Date.now());
    if (!active) throw new HttpError(401, 'ログインしてください。');
    const { id, publicKey, counter } = result.registrationInfo.credential;
    const inserted = db.prepare('INSERT INTO passkeys VALUES (?, ?, ?, ?) ON CONFLICT(credential_id) DO NOTHING')
      .run(user.id, id, publicKey, counter);
    if (!inserted.changes) throw new HttpError(409, 'このパスキーは登録済みです。');
    return json(response, {});
  }

  const assertion = body.credential as AuthenticationResponseJSON | undefined;
  if (typeof assertion?.id !== 'string') throw invalid;
  const stored = db.prepare('SELECT * FROM passkeys WHERE credential_id = ?').get(assertion.id) as Passkey | undefined;
  if (!stored) throw invalid;
  const result = await verifyAuthenticationResponse({
    ...expectation, response: assertion, requireUserVerification: true,
    credential: { id: stored.credential_id, publicKey: new Uint8Array(stored.public_key), counter: stored.sign_count },
  }).catch(() => { throw invalid; });
  if (!result.verified) throw invalid;
  return signIn(request, response, stored.user_id, {
    credentialId: stored.credential_id,
    previousCount: stored.sign_count,
    newCount: result.authenticationInfo.newCounter,
  });
}

const loginPage = readFileSync(new URL('./login.html', import.meta.url));
const accountPage = readFileSync(new URL('./account.html', import.meta.url));
const script = readFileSync(new URL('./browser.js', import.meta.url));
const style = readFileSync(new URL('./style.css', import.meta.url));

createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  response.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    const session = digest(cookie(request, 'session'));
    const user = db.prepare(`
      SELECT users.* FROM users JOIN sessions ON users.id = sessions.user_id
      WHERE sessions.token = ? AND sessions.expires_at > ?
    `).get(session, Date.now()) as User | undefined;
    if (request.method === 'GET') {
      switch (request.url) {
        case '/':
        case '/account':
          if ((request.url === '/account') !== Boolean(user)) {
            response.writeHead(302, { Location: user ? '/account' : '/' }).end();
            return;
          }
          response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(user ? accountPage : loginPage);
          return;
        case '/browser.js':
          response.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' }).end(script);
          return;
        case '/style.css':
          response.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' }).end(style);
          return;
      }
    }
    if (request.method === 'POST') {
      if (request.headers.origin !== origin.origin) throw new HttpError(403, '許可されていないリクエストです。');
      switch (request.url) {
        case '/api/signup':
        case '/api/login':
          await passwordAuth(request, response, await readBody(request), request.url === '/api/signup');
          return;
        case '/api/logout':
          db.prepare('DELETE FROM sessions WHERE token = ?').run(session);
          setCookie(response, 'session', '', 0);
          return json(response, {});
        case '/api/passkey/register':
        case '/api/passkey/authenticate':
          await passkey(request, response, request.url.endsWith('/register') ? 'register' : 'authenticate',
            await readBody(request), user, session);
          return;
      }
    }
    json(response, { error: 'ページが見つかりません。' }, 404);
  } catch (error) {
    if (error instanceof HttpError) return json(response, { error: error.message }, error.status);
    console.error(error);
    json(response, { error: '処理を完了できませんでした。' }, 500);
  }
}).listen(port, process.env.HOST ?? 'localhost', () => console.log(origin.origin));
