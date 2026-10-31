/**
 * The EF-42 journey on the real API, in a real browser: a denied flow in the journal →
 * « Autoriser ce flux » → rule added to the session → publish → install; then the published
 * revision is checked through the API (it holds the new rule, installation requested).
 */
import { expect, test } from '@playwright/test'
import { createHttpApi } from '../app/api/http'

const API = process.env.AFW_E2E_API ?? 'http://afw-api:8080'
const TOKEN = process.env.AFW_E2E_TOKEN ?? 'afw-e2e-admin-token-0123456789'
const DENIED_FLOW = '00000000-0000-4000-8000-00000000f001'

test('refus → Autoriser → publier → installer, revision published by the API', async ({ page }) => {
  const api = createHttpApi({ baseUrl: API, getToken: () => TOKEN })
  const before = await api.policyStatus()
  const expected = (before.latest_revision ?? 0) + 1

  await page.goto('/login')
  await page.getByTestId('login-token').fill(TOKEN)
  await page.getByRole('button', { name: 'Utiliser ce jeton' }).click()
  await expect(page).toHaveURL(/\/$|\/\?/)

  const row = page.getByTestId(`flow-row-${DENIED_FLOW}`)
  await expect(row).toBeVisible()
  await expect(row).toContainText('daniel-bot')
  await row.click()
  const detail = page.getByTestId('flow-detail')
  await expect(detail).toContainText('blocked by agents-firewall: upload.fichiers-partage.example not allowed for daniel-bot')
  await expect(page.getByTestId('trace-default-deny')).toBeVisible()

  await page.getByTestId('allow-open').click()
  await expect(page.getByTestId('allow-form')).toBeVisible()
  await expect(page.getByTestId('cli-snippet')).toContainText("--zone 'internes'")
  await page.getByTestId('allow-dest-exact').click()
  await page.getByTestId('allow-submit').click()
  await expect(page.getByTestId('allow-added')).toContainText('ajoutée à votre session')
  await expect(page.getByTestId('allow-added')).toContainText(`révision ${expected}`)

  await page.getByTestId('allow-review').click()
  await expect(page).toHaveURL(/\/rules\?zone=/)
  await expect(page.getByTestId('session-bar-title')).toContainText('modif.')
  await expect(page.locator('[data-testid^="rule-tag-"]').filter({ hasText: 'ajoutée' })).toHaveCount(1)

  await page.getByTestId('go-publish').click()
  await expect(page.getByTestId('publish-panel')).toBeVisible()
  await page.locator('#afw-pubcomment').fill('Autoriser le dépôt de rapports (e2e)')
  await expect(page.getByTestId('do-publish')).toContainText(`Publier la révision ${expected}`)
  await page.getByTestId('do-publish').click()
  await expect(page.getByTestId('session-bar-title')).toContainText(`Révision ${expected} publiée`)

  await page.getByTestId('do-install').click()
  await expect(page.getByTestId('install-result')).toBeVisible()
  await expect(page.getByTestId('install-result')).toContainText('gw-demo-01')

  // The API is the reference: revision published, holding the new rule, installation requested.
  const after = await api.policyStatus()
  expect(after.latest_revision).toBe(expected)
  expect(after.installed_revision).toBe(expected)
  const rev = await api.getRevision(expected)
  expect(rev.revision.comment).toBe('Autoriser le dépôt de rapports (e2e)')
  expect(rev.revision.interface).toBe('ui')
  const added = rev.document.rules.find(r => r.name === 'Autoriser upload.fichiers-partage.example')
  expect(added).toMatchObject({ action: 'accept', layer: { type: 'zone', zone_id: '00000000-0000-4000-8000-000000000401' }, position: 1 })
  const installs = await api.listInstalls({ revision: expected })
  expect(installs.items.map(i => i.state)).toContain('pending')
  const audit = await api.listAudit({ action: 'session.*', interface: 'ui' })
  expect(audit.items.map(e => e.action)).toEqual(expect.arrayContaining(['session.open', 'session.publish']))
})
