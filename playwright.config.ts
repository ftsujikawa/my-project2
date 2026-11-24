import { defineConfig } from '@playwright/test';

const origin = 'http://localhost:3100';

export default defineConfig({
  testDir: './tests',
  testMatch: '**/passkey.spec.ts',
  use: { browserName: 'chromium', baseURL: origin },
  webServer: {
    command: 'pnpm start',
    url: origin,
    env: { PORT: '3100', APP_ORIGIN: origin, DB_PATH: ':memory:' },
  },
});
