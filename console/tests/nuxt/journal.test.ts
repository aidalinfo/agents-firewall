import { flushPromises } from '@vue/test-utils'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { describe, expect, it } from 'vitest'
import type { MockApi } from '../../app/api/mock'
import { FLOW_IDS, GW_IDS } from '../../app/api/mock-data'
import JournalPage from '../../app/pages/index.vue'
import RulesPage from '../../app/pages/rules.vue'

async function settle(times = 4) {
  for (let i = 0; i < times; i++) {
    await flushPromises()
    await new Promise(r => setTimeout(r, 0))
  }
}

async function until(check: () => boolean, label: string, tries = 80) {
  for (let i = 0; i < tries; i++) {
    if (check()) return
    await settle(1)
  }
  throw new Error(`timeout: ${label}`)
}

describe('journal (mock API, contract shapes)', () => {
  it('renders the flows, the counters and the evaluation trace given by the API', async () => {
    const page = await mountSuspended(JournalPage)
    await until(() => page.find(`[data-testid="flow-row-${FLOW_IDS.upload}"]`).exists(), 'flow rows')

    expect(page.text()).toContain('Journal')
    expect(Number(page.find('[data-testid="segment-deny"]').text().replace(/\D/g, ''))).toBeGreaterThan(0)
    const first = page.find(`[data-testid="flow-row-${FLOW_IDS.upload}"]`)
    expect(first.attributes('aria-current')).toBe('true')
    expect(first.text()).toContain('refusé')
    expect(first.text()).toContain('daniel-bot')
    expect(first.text()).toContain('default-deny')

    await until(() => page.find('[data-testid="trace-default-deny"]').exists(), 'trace')
    expect(page.find('[data-testid="trace-default-deny"]').text()).toContain('refuser')
    // EF-21: the exact text received by the agent comes from the API.
    expect(page.find('[data-testid="flow-detail"]').text()).toContain('blocked by agents-firewall: upload.fichiers-partage.example not allowed for daniel-bot (rule default-deny)')
  })

  it('filters on the denied segment and never offers to override the baseline', async () => {
    const page = await mountSuspended(JournalPage)
    await until(() => page.find(`[data-testid="flow-row-${FLOW_IDS.upload}"]`).exists(), 'flow rows')
    await page.find('[data-testid="segment-deny"]').trigger('click')
    await until(() => !page.find(`[data-testid="flow-row-${FLOW_IDS.llm}"]`).exists(), 'denied rows only')

    await page.find(`[data-testid="flow-row-${FLOW_IDS.metadata}"]`).trigger('click')
    await until(() => page.find('[data-testid="trace-1"]').exists(), 'baseline trace')
    expect(page.find('[data-testid="allow-open"]').exists()).toBe(false)
    expect(page.find('[data-testid="flow-detail"]').text()).toContain('Socle commun · non contournable')
  })

  it('reloads when the stream reports skipped events (lagged)', async () => {
    const page = await mountSuspended(JournalPage)
    await until(() => page.find(`[data-testid="flow-row-${FLOW_IDS.upload}"]`).exists(), 'flow rows')
    const api = useNuxtApp().$api as MockApi
    const f = (await api.getFlow(FLOW_IDS.upload)).flow
    api.control.emit({ kind: 'event', event: { ...f, id: 'f0000000-0000-4000-8000-0000000000aa', started_at: new Date().toISOString(), type: 'flow' } })
    api.control.emit({ kind: 'lagged', skipped: 5 })
    await until(() => page.find('[data-testid="flow-row-f0000000-0000-4000-8000-0000000000aa"]').exists(), 'new flow shown')
  })
})

describe('« Autoriser » journey (mock API)', () => {
  it('pre-fills a rule, adds it to the session, then publishes and installs it', async () => {
    const journal = await mountSuspended(JournalPage)
    await until(() => journal.find('[data-testid="allow-open"]').exists(), 'allow button')
    await journal.find('[data-testid="allow-open"]').trigger('click')
    await until(() => journal.find('[data-testid="allow-form"]').exists(), 'allow form')

    const cli = journal.find('[data-testid="cli-snippet"]').text()
    expect(cli).toContain("--zone 'bots-internes'")
    expect(cli).toContain("--dest 'upload.fichiers-partage.example' --create-object")
    expect(cli).toContain("--before '5' --expire 30d")

    await journal.find('[data-testid="allow-dest-wildcard"]').trigger('click')
    expect(journal.find('[data-testid="cli-snippet"]').text()).toContain("--dest '*.fichiers-partage.example'")
    await journal.find('[data-testid="allow-dest-exact"]').trigger('click')

    await journal.find('[data-testid="allow-submit"]').trigger('click')
    await until(() => journal.find('[data-testid="allow-added"]').exists(), 'rule added')
    expect(journal.find('[data-testid="allow-added"]').text()).toContain('Règle #5 ajoutée à votre session')
    expect(journal.find('[data-testid="allow-added"]').text()).toContain('révision 43')

    const api = useNuxtApp().$api as MockApi
    const session = await api.currentSession()
    expect(session).toMatchObject({ state: 'open', base_revision: 42, next_revision: 43 })
    expect(session?.locks.map(l => l.kind)).toEqual(expect.arrayContaining(['object', 'rule']))

    const rules = await mountSuspended(RulesPage, { route: '/rules' })
    await until(() => rules.find('[data-testid="zone-tab-bots-internes"]').exists(), 'zone tabs')
    await rules.find('[data-testid="zone-tab-bots-internes"]').trigger('click')
    await until(() => rules.find('[data-testid="rule-tag-5"]').exists(), 'rule 5 in the draft')
    expect(rules.find('[data-testid="rule-5"]').text()).toContain('Autoriser upload.fichiers-partage.example')
    expect(rules.find('[data-testid="rule-tag-5"]').text()).toContain('ajoutée')
    expect(rules.find('[data-testid="rule-tag-6"]').text()).toContain('modifiée')
    expect(rules.find('[data-testid="session-bar-title"]').text()).toMatch(/\d+ modif\./)

    await rules.find('[data-testid="go-publish"]').trigger('click')
    await until(() => rules.find('[data-testid="publish-panel"]').exists(), 'publish panel')
    expect(rules.find('[data-testid="publish-panel"]').text()).toContain('Différences avec la révision 42')
    expect(rules.find('[data-testid="publish-panel"]').text()).toContain('Règle expirée encore en place : 8 · GitHub API')

    expect(rules.find('[data-testid="do-publish"]').text()).toContain('Publier la révision 43')
    await rules.find('[data-testid="do-publish"]').trigger('click')
    await until(() => rules.find('[data-testid="do-install"]').exists(), 'published')
    expect(rules.find('[data-testid="session-bar-title"]').text()).toContain('Révision 43 publiée')
    expect(rules.find('[data-testid="session-bar"]').text()).toContain('appliquent toujours la révision 42')
    expect(rules.find('[data-testid="do-install"]').text()).toContain('Installer la rév. 43 sur toutes les passerelles (3)')
    await until(() => rules.find('[data-testid="do-install"]').attributes('disabled') === undefined, 'install enabled')
    await rules.find('[data-testid="do-install"]').trigger('click')
    await until(() => rules.find('[data-testid="install-result"]').exists(), 'installed')
    expect(rules.find('[data-testid="install-result"]').text()).toContain('gw-hermes-01')

    await new Promise(r => setTimeout(r, 700))
    const gws = await api.listGateways()
    expect(gws.find(g => g.id === GW_IDS.hermes01)?.active_revision).toBe(43)
    expect(gws.find(g => g.id === GW_IDS.ops01)?.active_revision).toBe(41)
    expect((await api.policyStatus()).latest_revision).toBe(43)
  })
})
