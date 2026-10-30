import { flushPromises } from '@vue/test-utils'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { describe, expect, it } from 'vitest'
import type { AfwApi } from '../../app/api/client'
import { FLOW_IDS } from '../../app/api/mock-data'
import JournalPage from '../../app/pages/index.vue'
import RulesPage from '../../app/pages/rules.vue'

async function settle(times = 4) {
  for (let i = 0; i < times; i++) {
    await flushPromises()
    await new Promise(r => setTimeout(r, 0))
  }
}

async function until(check: () => boolean, label: string) {
  for (let i = 0; i < 50; i++) {
    if (check()) return
    await settle(1)
  }
  throw new Error(`timeout: ${label}`)
}

describe('journal (mock API)', () => {
  it('renders the flows, the counters and the evaluation trace of the selected flow', async () => {
    const page = await mountSuspended(JournalPage)
    await until(() => page.findAll('[data-testid^="flow-row-"]').length === 11, 'flow rows')

    expect(page.text()).toContain('Journal')
    expect(page.find('[data-testid="segment-deny"]').text()).toContain('33')
    const first = page.find(`[data-testid="flow-row-${FLOW_IDS.upload1}"]`)
    expect(first.attributes('aria-current')).toBe('true')
    expect(first.text()).toContain('refusé')
    expect(first.text()).toContain('daniel-bot')

    await until(() => page.find('[data-testid="trace-12"]').exists(), 'trace')
    expect(page.find('[data-testid="trace-S1–S5"]').text()).toContain('Socle commun')
    expect(page.find('[data-testid="trace-12"]').text()).toContain('refuser')
    expect(page.find('[data-testid="flow-detail"]').text()).toContain('bloqué par agents-firewall : api.exemple.com non autorisé pour daniel-bot (règle 12)')
  })

  it('filters on the denied segment and never offers to override the baseline', async () => {
    const page = await mountSuspended(JournalPage)
    await until(() => page.findAll('[data-testid^="flow-row-"]').length === 11, 'flow rows')
    await page.find('[data-testid="segment-deny"]').trigger('click')
    await until(() => page.findAll('[data-testid^="flow-row-"]').length === 5, 'denied rows')

    await page.find(`[data-testid="flow-row-${FLOW_IDS.metadata}"]`).trigger('click')
    await until(() => page.find('[data-testid="trace-S1"]').exists(), 'baseline trace')
    expect(page.find('[data-testid="allow-open"]').exists()).toBe(false)
    expect(page.find('[data-testid="flow-detail"]').text()).toContain('Socle commun · non contournable')
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
    expect(cli).toContain("--dest 'dom-api.exemple.com' --create-object")
    expect(cli).toContain("--before '12' --expire 30d")

    await journal.find('[data-testid="allow-dest-group"]').trigger('click')
    expect(journal.find('[data-testid="cli-snippet"]').text()).toContain("--dest 'grp-portails-partenaires' \\")
    await journal.find('[data-testid="allow-dest-exact"]').trigger('click')

    await journal.find('[data-testid="allow-submit"]').trigger('click')
    await until(() => journal.find('[data-testid="allow-added"]').exists(), 'rule added')
    expect(journal.find('[data-testid="allow-added"]').text()).toContain('Règle #12 ajoutée à votre session')
    expect(journal.find('[data-testid="allow-review"]').text()).toContain('Relire, publier et installer')

    const api = useNuxtApp().$api as AfwApi
    const session = await api.currentSession()
    expect(session?.changes.map(c => c.op)).toEqual(['add', 'add', 'renumber'])

    const rules = await mountSuspended(RulesPage)
    await until(() => rules.find('[data-testid="rule-12"]').exists(), 'rule 12 in rulebase')
    expect(rules.find('[data-testid="rule-12"]').text()).toContain('session')
    expect(rules.find('[data-testid="rule-13"]').text()).toContain('Était la règle 12')
    expect(rules.find('[data-testid="session-bar-title"]').text()).toContain('3 modif.')

    await rules.find('[data-testid="go-publish"]').trigger('click')
    await until(() => rules.find('[data-testid="publish-panel"]').exists(), 'publish panel')
    expect(rules.find('[data-testid="publish-panel"]').text()).toContain('Différences avec la révision 42')
    expect(rules.find('[data-testid="publish-panel"]').text()).toContain('Règle expirée encore en place : 25')

    expect(rules.find('[data-testid="do-publish"]').text()).toContain('Publier la révision 43')
    await rules.find('[data-testid="do-publish"]').trigger('click')
    await until(() => rules.find('[data-testid="do-install"]').exists(), 'published')
    expect(rules.find('[data-testid="session-bar-title"]').text()).toContain('Révision 43 publiée')
    expect(rules.find('[data-testid="session-bar"]').text()).toContain('appliquent toujours la révision 42')
    // One click, the summary is in the button.
    expect(rules.find('[data-testid="do-install"]').text()).toContain('Installer la rév. 43 sur 3 passerelles : gw-hermes-01, gw-hermes-02, gw-ops-01')
    await rules.find('[data-testid="do-install"]').trigger('click')
    await until(() => rules.find('[data-testid="install-result"]').exists(), 'installed')
    expect(rules.find('[data-testid="session-bar-title"]').text()).toContain('Révision 43 installée sur 3/3 passerelles')
    expect((await api.listGateways()).every(g => g.revision === 43)).toBe(true)
  })
})
