import { beforeEach, describe, expect, it } from 'vitest'
import type { AfwApi } from '../../app/api/client'
import { createMockApi } from '../../app/api/mock'
import { FLOW_IDS } from '../../app/api/mock-data'

const NOW = new Date(2026, 9, 30, 14, 32, 10)

describe('mock API — journal', () => {
  let api: AfwApi
  beforeEach(() => {
    api = createMockApi({ now: NOW, latencyMs: 0 })
  })

  it('lists the mockup flows, newest first', async () => {
    const page = await api.listFlows({})
    expect(page.items).toHaveLength(11)
    expect(page.items[0]!.agent_name).toBe('daniel-bot')
    expect(page.items[0]!.domain).toBe('api.exemple.com')
    const times = page.items.map(f => f.started_at)
    expect([...times].sort().reverse()).toEqual(times)
  })

  it('filters by verdict, agent, rule, alert, wildcard destination and free text', async () => {
    expect((await api.listFlows({ verdict: 'deny' })).items).toHaveLength(5)
    expect((await api.listFlows({ agent: 'vulcain-bot' })).items).toHaveLength(3)
    expect((await api.listFlows({ rule: 'S1' })).items.map(f => f.domain)).toEqual(['169.254.169.254'])
    expect((await api.listFlows({ alert: true })).items).toHaveLength(2)
    expect((await api.listFlows({ destination: '*.exemple.com' })).items).toHaveLength(2)
    expect((await api.listFlows({ q: 'sendMail' })).items.map(f => f.domain)).toEqual(['graph.microsoft.com'])
  })

  it('returns journal counters and a 60-minute histogram', async () => {
    const stats = await api.flowStats({})
    expect(stats.histogram).toHaveLength(60)
    expect(stats.total).toBe(stats.allowed + stats.denied)
  })

  it('returns the evaluation trace and an allow proposal for a zone denial', async () => {
    const d = await api.getFlow(FLOW_IDS.upload1)
    expect(d.trace.map(t => [t.label, t.result])).toEqual([
      ['S1–S5', 'no_match'],
      ['1–11', 'no_match'],
      ['12', 'deny'],
    ])
    expect(d.agent_message).toBe('blocked by agents-firewall: api.exemple.com not allowed for daniel-bot (rule 12)')
    expect(d.allow_proposal?.zone.name).toBe('bots-internes')
    expect(d.allow_proposal?.destination_options.map(o => o.key)).toEqual(['exact', 'group', 'wildcard'])
    expect(d.allow_proposal?.destination_options[2]?.value).toBe('*.exemple.com')
    expect(d.allow_proposal?.would_allow.flows).toBe(3)
    expect(d.http?.method).toBe('POST')
    expect(d.tool_call?.tool).toBe('terminal · python envoi.py')
  })

  it('never proposes to override the baseline', async () => {
    const d = await api.getFlow(FLOW_IDS.metadata)
    expect(d.allow_proposal).toBeNull()
    expect(d.trace.map(t => [t.label, t.result])).toEqual([['S1', 'deny']])
  })
})

describe('mock API — allow from log → publish → install', () => {
  let api: AfwApi
  beforeEach(() => {
    api = createMockApi({ now: NOW, latencyMs: 0 })
  })

  it('adds a pre-filled rule before the cleanup rule of the zone', async () => {
    expect(await api.currentSession()).toBeNull()
    const session = await api.openSession('Ouverture api.exemple.com')
    const { rule, changes } = await api.allowFromLog(session.id, {
      flow_id: FLOW_IDS.upload1,
      destination: 'exact',
      expires_in_days: 30,
      track: 'detailed',
    })
    expect(rule.number).toBe('12')
    expect(rule.in_session).toBe(true)
    expect(rule.destination_names).toEqual(['dom-api.exemple.com'])
    expect(rule.expires_at).not.toBeNull()
    expect(changes.map(c => c.op)).toEqual(['add', 'add', 'renumber'])

    const zones = await api.listZones()
    const zone = zones.find(z => z.name === 'bots-internes')!
    const rb = await api.getRulebase({ zone_id: zone.id })
    const cleanup = rb.zone.at(-1)!
    expect(cleanup.number).toBe('13')
    expect(cleanup.previous_number).toBe('12')
    expect((await api.currentSession())?.changes).toHaveLength(3)
    expect((await api.listObjects()).find(o => o.name === 'dom-api.exemple.com')?.in_session).toBe(true)
  })

  it('reuses an existing group without creating an object', async () => {
    const session = await api.openSession('s')
    const { rule, changes } = await api.allowFromLog(session.id, {
      flow_id: FLOW_IDS.upload1,
      destination: 'group',
      expires_in_days: null,
      track: 'log',
    })
    expect(rule.destination_names).toEqual(['grp-portails-partenaires'])
    expect(rule.expires_at).toBeNull()
    expect(changes.map(c => c.op)).toEqual(['add', 'renumber'])
  })

  it('refuses to allow a flow denied by the baseline', async () => {
    const session = await api.openSession('s')
    await expect(api.allowFromLog(session.id, {
      flow_id: FLOW_IDS.metadata,
      destination: 'exact',
      expires_in_days: null,
      track: 'detailed',
    })).rejects.toMatchObject({ status: 409 })
  })

  it('publishes revision 43 then installs it on the selected gateways', async () => {
    const session = await api.openSession('Ouverture api.exemple.com')
    await api.allowFromLog(session.id, { flow_id: FLOW_IDS.upload1, destination: 'exact', expires_in_days: 30, track: 'detailed' })

    const report = await api.verify()
    expect(report.ok).toBe(true)
    expect(report.findings.map(f => f.code)).toEqual(['expired_rule', 'unused_object'])

    expect((await api.currentSession())?.base_revision).toBe(42)
    expect((await api.currentSession())?.next_revision).toBe(43)
    const rev = await api.publishSession(session.id, 'portail partenaire')
    expect(rev.number).toBe(43)
    expect(rev.installed).toBe(false)
    expect(await api.currentSession()).toBeNull()
    expect((await api.listRevisions())[0]?.number).toBe(43)

    const gateways = await api.listGateways()
    const install = await api.install(43, gateways.map(g => g.id))
    expect(install.results.every(r => r.ok)).toBe(true)
    expect((await api.listGateways()).every(g => g.revision === 43)).toBe(true)
    expect((await api.getRevision(43)).installed).toBe(true)
    expect((await api.getRevision(42)).installed).toBe(false)
    expect(await api.policyStatus()).toMatchObject({ installed_revision: 43, latest_revision: 43, gateways_on_revision: 3, gateways_total: 3 })

    const audit = await api.listAudit({})
    expect(audit.items.slice(0, 2).map(a => a.action)).toEqual(['install', 'publish'])
  })

  it('discarding the session restores the rulebase', async () => {
    const session = await api.openSession('s')
    await api.allowFromLog(session.id, { flow_id: FLOW_IDS.upload1, destination: 'exact', expires_in_days: 7, track: 'detailed' })
    await api.discardSession(session.id)
    expect(await api.currentSession()).toBeNull()
    const zone = (await api.listZones()).find(z => z.name === 'bots-internes')!
    const rb = await api.getRulebase({ zone_id: zone.id })
    expect(rb.zone.at(-1)?.number).toBe('12')
    expect(rb.zone.some(r => r.in_session)).toBe(false)
  })
})

describe('mock API — other screens', () => {
  const api = createMockApi({ now: NOW, latencyMs: 0 })

  it('serves zones, objects with where-used, agents and overview', async () => {
    const zones = await api.listZones()
    expect(zones.map(z => z.name)).toEqual(['bots-internes', 'bots-clients', 'nouveaux-bots', 'ops'])
    expect(zones.find(z => z.name === 'ops')?.holds_mcp_agent).toBe(true)

    const objects = await api.listObjects()
    const grp = objects.find(o => o.name === 'grp-portails-partenaires')!
    expect(grp.members).toHaveLength(4)
    const used = await api.whereUsed(grp.id)
    expect(used[0]).toMatchObject({ kind: 'rule', ref: '11', hits: 57 })
    const unused = objects.find(o => o.name === 'dom-ancien-crm.exemple.fr')!
    expect(unused.used_in).toBe(0)

    const agents = await api.listAgents()
    expect(agents.map(a => a.agent.name)).toContain('hermes-compta')
    const daniel = agents.find(a => a.agent.name === 'daniel-bot')!
    const ov = await api.agentOverview(daniel.agent.id)
    expect(ov.volume).toHaveLength(24)
    expect(ov.recent_denials[0]?.destination).toBe('api.exemple.com')
  })

  it('reports the installed policy as the API sees it', async () => {
    expect(await api.policyStatus()).toMatchObject({ installed_revision: 42, latest_revision: 42, gateways_on_revision: 3, gateways_total: 3, latency_p95_ms: 6 })
  })

  it('tells the layer of the destination rule on the agent view', async () => {
    const daniel = (await api.listAgents()).find(a => a.agent.name === 'daniel-bot')!
    const ov = await api.agentOverview(daniel.agent.id)
    expect(ov.destinations.find(d => d.rule_label === 'S3')?.rule_layer).toBe('baseline')
    expect(ov.destinations.find(d => d.rule_label === '9')?.rule_layer).toBe('zone')
  })

  it('serves alerts, the internal map, gateways and a valid audit chain', async () => {
    expect((await api.listAlerts()).filter(a => a.severity === 'critical')).toHaveLength(2)
    const map = await api.internalMap('24h')
    expect(map.nodes.filter(n => n.kind === 'agent')).toHaveLength(5)
    expect(map.admin_calls).toHaveLength(5)
    expect((await api.listGateways()).map(g => g.status)).toEqual(['online', 'degraded', 'online'])
    expect((await api.verifyAudit()).ok).toBe(true)
    const rb = await api.getRulebase({})
    expect(rb.baseline.map(r => r.number)).toEqual(['S1', 'S2', 'S3', 'S4', 'S5'])
  })

  it('acknowledges an alert', async () => {
    const alert = (await api.listAlerts())[0]!
    const acked = await api.acknowledgeAlert(alert.id)
    expect(acked.acknowledged_by).toBe('Killian Stein')
  })
})
