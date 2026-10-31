/**
 * Acceptance screenshots (lot L13): every console screen, on the LIVE demo environment (demo/up.sh), with the
 * data produced by the acceptance scenarios. Run by demo/screenshots.sh (AFW_RECETTE=1), never by the e2e suite.
 * Also times « Autoriser » from the journal: denied flow → form → session → publish → install.
 * Inputs (env): AFW_E2E_TOKEN, AFW_RECETTE_OUT, AFW_RECETTE_DENIED_FLOW (daniel-bot tool call denied),
 * AFW_RECETTE_ALLOW_FLOW (acme-bot denied, allowed by the timed journey), AFW_RECETTE_AGENT (daniel-bot id),
 * AFW_RECETTE_OBJECT (an object id), AFW_RECETTE_REVISION (a revision number with a diff).
 */
import { writeFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'

const env = (k: string) => process.env[k] ?? ''
const TOKEN = env('AFW_E2E_TOKEN')
const OUT = env('AFW_RECETTE_OUT') || '/out'
const DENIED = env('AFW_RECETTE_DENIED_FLOW')
const ALLOW = env('AFW_RECETTE_ALLOW_FLOW')
const AGENT = env('AFW_RECETTE_AGENT')
const OBJECT = env('AFW_RECETTE_OBJECT')
const REVISION = env('AFW_RECETTE_REVISION')

test.skip(!process.env.AFW_RECETTE, 'acceptance screenshots only on demand (demo/screenshots.sh)')
test.describe.configure({ mode: 'serial' })

async function login(page: Page, theme: 'dark' | 'light') {
  await page.addInitScript((t) => {
    localStorage.setItem('afw-color-mode', t)
    localStorage.setItem('afw-locale', 'fr')
  }, theme)
  await page.goto('/login')
  await page.getByTestId('login-token').fill(TOKEN)
  await page.getByRole('button', { name: 'Utiliser ce jeton' }).click()
  await expect(page).toHaveURL(/\/$|\/\?/)
}

const shot = async (page: Page, name: string, settle = 1200) => {
  await page.waitForLoadState('networkidle', { timeout: 2500 }).catch(() => {})
  await page.waitForTimeout(settle)
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false })
}

/** The audit list shows the most recent entries first (ui, api, mcp): the top of the page. */
async function showLatestAudit(page: Page) {
  await expect(page.locator('[data-testid^="audit-"]:not([data-testid="audit-chain"]):not([data-testid="audit-export"])').first()).toBeVisible()
}

test('01 connexion', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('afw-color-mode', 'dark'))
  await page.goto('/login')
  await expect(page.getByTestId('login-token')).toBeVisible()
  await shot(page, '01-connexion')
})

test('Autoriser depuis le journal, chronométré', async ({ page }) => {
  await login(page, 'dark')
  await page.goto(`/?flow=${ALLOW}`)
  const t0 = Date.now()
  await page.getByTestId(`flow-row-${ALLOW}`).click()
  await expect(page.getByTestId('flow-detail')).toContainText('acme-bot')
  await page.getByTestId('allow-open').click()
  await expect(page.getByTestId('allow-form')).toBeVisible()
  await shot(page, '08-autoriser-formulaire', 600)
  await page.getByTestId('allow-dest-exact').click()
  await page.getByTestId('allow-submit').click()
  await expect(page.getByTestId('allow-added')).toContainText('ajoutée à votre session')
  await page.getByTestId('allow-review').click()
  await expect(page.getByTestId('session-bar-title')).toContainText('modif.')
  await shot(page, '09-regles-barre-de-session', 600)
  await page.getByTestId('go-publish').click()
  await expect(page.getByTestId('publish-panel')).toBeVisible()
  await page.locator('#afw-pubcomment').fill('Recette : autoriser api.github.com pour acme-bot (depuis le journal)')
  await shot(page, '10-publication', 400)
  await page.getByTestId('do-publish').click()
  await expect(page.getByTestId('session-bar-title')).toContainText('publiée')
  await page.getByTestId('do-install').click()
  await expect(page.getByTestId('install-result')).toBeVisible()
  await expect(page.getByTestId('install-result')).toContainText('demo-gw')
  const t1 = Date.now()
  await shot(page, '11-installation', 1500)
  writeFileSync(`${OUT}/allow-ui-timing.json`, JSON.stringify({ started_ms: t0, installed_ms: t1, ui_ms: t1 - t0 }))
})

for (const [theme, label, n] of [['dark', 'sombre', 0], ['light', 'clair', 1]] as const) {
  test(`main screens, ${label}`, async ({ page }) => {
    await login(page, theme)
    const no = (base: number) => String(base + n).padStart(2, '0')
    await page.goto(`/?flow=${DENIED}`)
    await expect(page.getByTestId('flow-detail')).toBeVisible()
    await shot(page, `${no(2)}-journal-${label}`)
    await page.goto(`/flows/${DENIED}`)
    await expect(page.getByTestId('flow-detail')).toContainText('daniel-bot')
    await shot(page, `${no(4)}-flux-refuse-${label}`)
    await page.getByRole('tab', { name: 'Agent et conversation' }).click()
    await shot(page, `${no(6)}-flux-refuse-conversation-${label}`)
    await page.goto(`/agents/${AGENT}`)
    await shot(page, `${no(14)}-agent-daniel-bot-${label}`)
    await page.goto('/internal')
    await expect(page.getByTestId('internal-map')).toBeVisible()
    await shot(page, `${no(16)}-flux-internes-${label}`)
    await page.goto('/audit')
    await showLatestAudit(page)
    await shot(page, `${no(21)}-audit-${label}`, 600)
    await page.goto('/gateways')
    await expect(page.getByTestId('gateway-demo-gw')).toBeVisible()
    await shot(page, `${no(23)}-passerelles-${label}`)
    await page.goto('/rules')
    await shot(page, `${no(12)}-regles-${label}`)
  })
}

test('other screens, dark', async ({ page }) => {
  await login(page, 'dark')
  await page.goto('/alerts')
  await expect(page.locator('[data-testid^="alert-port_scan"]').first()).toBeVisible()
  await shot(page, '18-alertes-mouvement-lateral')
  await page.goto(`/objects?object=${OBJECT}`)
  await expect(page.getByTestId('object-detail')).toBeVisible()
  await shot(page, '19-objets-ou-utilise')
  await page.getByTestId('zone-card-internes').scrollIntoViewIfNeeded()
  await shot(page, '20-zones')
  await page.goto('/revisions')
  await page.getByTestId(`rev-${REVISION}`).click()
  await expect(page.getByTestId('revision-detail')).toBeVisible()
  await shot(page, '25-revisions-diff')
  await page.goto('/inspection')
  await shot(page, '26-inspection-tls')
  await page.goto('/settings')
  await shot(page, '27-parametres')
})
