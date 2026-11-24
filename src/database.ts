import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';

const migrations = ['0000_accounts', '0001_passkeys'];

export function transaction<T>(db: DatabaseSync, run: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = run();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function applySql(db: DatabaseSync, name: string) {
  db.exec(readFileSync(new URL(`../drizzle/${name}.sql`, import.meta.url), 'utf8'));
}

export function openDatabase(path = process.env.DB_PATH ?? 'app.sqlite', down = false) {
  const db = new DatabaseSync(path);
  try {
    db.exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON');
    transaction(db, () => {
      const { user_version: version } = db.prepare('PRAGMA user_version').get() as { user_version: number };
      if (!Number.isInteger(version) || version < 0 || version > migrations.length) {
        throw new Error('Unsupported database version');
      }
      if (down) {
        if (version === 2) {
          applySql(db, 'down/0001_passkeys');
          db.exec('PRAGMA user_version = 1');
        }
        return;
      }
      for (const migration of migrations.slice(version)) applySql(db, migration);
      db.exec(`PRAGMA user_version = ${migrations.length}`);
    });
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  openDatabase(undefined, true).close();
}
