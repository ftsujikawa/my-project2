import { defineConfig } from '@playwright/test';

const origin = 'http://localhost:3100';
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;

export default defineConfig({
  testDir: './tests',
  testMatch: '**/passkey.spec.ts',
  use: { browserName: 'chromium', baseURL: origin, launchOptions: { executablePath } },
  webServer: {
    command: 'pnpm start',
    url: origin,
    env: { PORT: '3100', APP_ORIGIN: origin, DB_PATH: ':memory:' },
  },
});
