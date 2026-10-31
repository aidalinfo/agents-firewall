/**
 * Screenshots of console/docs/screenshots/, taken on the real API with the demonstration data
 * (AFW_E2E_SCREENSHOTS=1, after the journey). Not an assertion suite.
 */
import { expect, test, type Page } from '@playwright/test'

const TOKEN = process.env.AFW_E2E_TOKEN ?? 'afw-e2e-admin-token-0123456789'
const OUT = process.env.AFW_E2E_SCREENSHOTS_DIR ?? '../docs/screenshots'

test.skip(!process.env.AFW_E2E_SCREENSHOTS, 'screenshots only on demand')

async function login(page: Page, theme: 'dark' | 'light' = 'dark') {
  await page.addInitScript((t) => {
    localStorage.setItem('afw-color-mode', t)
  }, theme)
  await page.goto('/login')
  await page.getByTestId('login-token').fill(TOKEN)
  await page.getByRole('button', { name: 'Utiliser ce jeton' }).click()
  await expect(page.getByTestId('flow-detail')).toBeVisible()
}

const shot = (page: Page, name: string) => page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false })

test('console screenshots on the real API', async ({ page }) => {
  await page.goto('/login')
  await shot(page, 'connexion')
  await login(page)
  await page.getByTestId('flow-row-00000000-0000-4000-8000-00000000f003').click()
  await page.waitForTimeout(500)
  await shot(page, 'journal-sombre')
  await page.goto('/flows/00000000-0000-4000-8000-00000000f002')
  await page.waitForTimeout(800)
  await shot(page, 'flux-detail')
  await page.goto('/rules?zone=00000000-0000-4000-8000-000000000401')
  await page.waitForTimeout(800)
  await shot(page, 'regles-installee')
  await page.goto('/agents')
  await page.waitForTimeout(800)
  await shot(page, 'agents')
  await page.goto('/agents/00000000-0000-4000-8000-000000000501')
  await page.waitForTimeout(800)
  await shot(page, 'agent-daniel-bot')
  await page.goto('/internal')
  await page.waitForTimeout(800)
  await shot(page, 'flux-internes')
  await page.goto('/alerts?')
  await page.waitForTimeout(500)
  await shot(page, 'alertes')
  await page.goto('/revisions')
  await page.waitForTimeout(800)
  await shot(page, 'revisions')
  await page.goto('/audit')
  await page.waitForTimeout(800)
  await shot(page, 'audit')
  await page.goto('/gateways')
  await page.waitForTimeout(800)
  await shot(page, 'passerelles')
  await page.goto('/inspection')
  await page.waitForTimeout(500)
  await shot(page, 'inspection')
  await page.goto('/settings')
  await page.waitForTimeout(500)
  await shot(page, 'parametres')
  await page.goto('/objects')
  await page.waitForTimeout(800)
  await page.getByTestId('object-create').click()
  await page.getByRole('menuitem').first().click()
  await page.waitForTimeout(400)
  await shot(page, 'formulaire-objet')
  await page.keyboard.press('Escape')

  // Allow from the log, then the rules page with the publish step (dark).
  await page.goto('/?flow=00000000-0000-4000-8000-00000000f001')
  await page.getByTestId(`flow-row-00000000-0000-4000-8000-00000000f001`).click()
  await page.getByTestId('allow-open').click()
  await page.waitForTimeout(400)
  await shot(page, 'autoriser-sombre')
})

test('light theme', async ({ page }) => {
  await login(page, 'light')
  await page.goto('/objects')
  await page.waitForTimeout(800)
  await shot(page, 'objets-clair')
})
