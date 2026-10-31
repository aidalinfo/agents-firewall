import { defineConfig, devices } from '@playwright/test'

/**
 * End-to-end tests of the console against the real control plane (lot L3b). Run by e2e/run.sh
 * inside mcr.microsoft.com/playwright (same version as @playwright/test), on the network of
 * e2e/docker-compose.yml. AFW_E2E_CONSOLE: console URL; AFW_E2E_API: afw-api URL; AFW_E2E_TOKEN: admin token.
 */
export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [['list']],
  outputDir: './test-results',
  use: {
    baseURL: process.env.AFW_E2E_CONSOLE ?? 'http://console:3000',
    locale: 'fr-FR',
    colorScheme: 'dark',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 900 },
  },
})
