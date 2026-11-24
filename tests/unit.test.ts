import type { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { consumeChallenge, issueChallenge } from '../src/challenges.js';
import { openDatabase } from '../src/database.js';
import { createSession } from '../src/sessions.js';

let db: DatabaseSync;
beforeEach(() => { db = openDatabase(':memory:'); });
afterEach(() => { db.close(); });

it('consumes a registration challenge once', () => {
  const token = issueChallenge(db, 'register', 'session', 'challenge', 0);
  expect(consumeChallenge(db, token, 'register', 'session', 1)).toBe('challenge');
  expect(consumeChallenge(db, token, 'register', 'session', 2)).toBeUndefined();
});

it('rejects an expired authentication challenge', () => {
  const token = issueChallenge(db, 'authenticate', null, 'challenge', 0);
  expect(consumeChallenge(db, token, 'authenticate', null, 300_000)).toBeUndefined();
});

it('binds registration to its initiating session', () => {
  const token = issueChallenge(db, 'register', 'first', 'challenge', 0);
  expect(consumeChallenge(db, token, 'register', 'second', 1)).toBeUndefined();
  expect(consumeChallenge(db, token, 'register', 'first', 1)).toBe('challenge');
});

it('keeps registration and authentication challenges separate', () => {
  const token = issueChallenge(db, 'authenticate', null, 'challenge', 0);
  expect(consumeChallenge(db, token, 'register', null, 1)).toBeUndefined();
  expect(consumeChallenge(db, token, 'authenticate', null, 1)).toBe('challenge');
});

it('accepts an authentication challenge just before it expires', () => {
  const token = issueChallenge(db, 'authenticate', null, 'challenge', 0);
  expect(consumeChallenge(db, token, 'authenticate', null, 299_999)).toBe('challenge');
});

it('prunes expired challenges without removing outstanding challenges', () => {
  const expired = issueChallenge(db, 'authenticate', null, 'expired', 0);
  const outstanding = issueChallenge(db, 'authenticate', null, 'outstanding', 1);

  const newest = issueChallenge(db, 'authenticate', null, 'newest', 300_000);

  expect(db.prepare('SELECT 1 FROM passkey_challenges WHERE token = ?').get(expired))
    .toBeUndefined();
  expect(consumeChallenge(db, outstanding, 'authenticate', null, 300_000)).toBe('outstanding');
  expect(consumeChallenge(db, newest, 'authenticate', null, 300_000)).toBe('newest');
});

it.each(['password', 'passkey'] as const)(
  'preserves existing authentication state when %s session creation fails',
  (method) => {
    db.prepare('INSERT INTO users VALUES (?, ?, ?)').run('user', 'user@example.test', 'hash');
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run('previous', 'user', 100);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run('occupied', 'user', 100);
    db.prepare('INSERT INTO passkeys VALUES (?, ?, ?, ?)').run('user', 'credential', Buffer.from([1]), 3);
    const counter = method === 'passkey'
      ? { credentialId: 'credential', previousCount: 3, newCount: 4 }
      : undefined;

    expect(() => createSession(db, 'previous', 'occupied', 'user', 1, 100, counter))
      .toThrow(/UNIQUE constraint failed/);

    expect(db.prepare('SELECT user_id, expires_at FROM sessions WHERE token = ?').get('previous'))
      .toEqual({ user_id: 'user', expires_at: 100 });
    expect(db.prepare('SELECT sign_count FROM passkeys WHERE credential_id = ?').get('credential'))
      .toEqual({ sign_count: 3 });
  },
);
