import { blob, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { users } from './account-schema.js';

export const passkeys = sqliteTable('passkeys', {
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: text('credential_id').primaryKey(),
  publicKey: blob('public_key', { mode: 'buffer' }).notNull(),
  signCount: integer('sign_count').notNull(),
});

export const passkeyChallenges = sqliteTable('passkey_challenges', {
  token: text('token').primaryKey(),
  purpose: text('purpose').notNull(),
  session: text('session'),
  challenge: text('challenge').notNull(),
  expiresAt: integer('expires_at').notNull(),
});
