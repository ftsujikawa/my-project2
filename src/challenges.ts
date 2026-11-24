import { randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

type Purpose = 'register' | 'authenticate';
const lifetime = 5 * 60 * 1000;

export function issueChallenge(
  db: DatabaseSync, purpose: Purpose, session: string | null, challenge: string, now = Date.now(),
) {
  const token = randomBytes(32).toString('base64url');
  db.prepare('DELETE FROM passkey_challenges WHERE expires_at <= ?').run(now);
  db.prepare('INSERT INTO passkey_challenges VALUES (?, ?, ?, ?, ?)').run(
    token, purpose, session, challenge, now + lifetime,
  );
  return token;
}

export function consumeChallenge(
  db: DatabaseSync, token: string, purpose: Purpose, session: string | null, now = Date.now(),
) {
  const row = db.prepare(`
    DELETE FROM passkey_challenges
    WHERE token = ? AND purpose = ? AND session IS ? AND expires_at > ?
    RETURNING challenge
  `).get(token, purpose, session, now) as { challenge: string } | undefined;
  return row?.challenge;
}
