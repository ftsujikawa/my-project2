import type { DatabaseSync } from 'node:sqlite';
import { transaction } from './database.js';

export type CounterUpdate = {
  credentialId: string;
  previousCount: number;
  newCount: number;
};

export function createSession(
  db: DatabaseSync, previousToken: string, token: string, userId: string,
  now: number, lifetime: number, counter?: CounterUpdate,
) {
  return transaction(db, () => {
    if (counter) {
      const update = db.prepare('UPDATE passkeys SET sign_count = ? WHERE credential_id = ? AND sign_count = ?')
        .run(counter.newCount, counter.credentialId, counter.previousCount);
      if (!update.changes) return false;
    }
    db.prepare('DELETE FROM sessions WHERE token = ? OR expires_at <= ?').run(previousToken, now);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(token, userId, now + lifetime);
    return true;
  });
}
