import { describe, expect, it } from 'vitest'
import { ApiError } from '../../app/api/client'
import { createMockApi } from '../../app/api/mock'
import { AGENT_IDS, FLOW_IDS, GW_IDS, OBJ, RULE_IDS, ZONE_IDS } from '../../app/api/mock-data'
import type { StreamEvent } from '../../app/api/types'
import { assertSchema, assertSchemaArray } from '../support/contract'

describe('mock API answers in the shapes of the contract', () => {
  it('every read matches the JSON schemas of docs/api/openapi.yaml', async () => {
    const api = createMockApi()
    assertSchema('Me', await api.me())
    const flows = await api.listFlows({})
    assertSchema('Page_for_FlowListItem', flows)
    assertSchema('FlowStats', await api.flowStats({}))
    for (const id of Object.values(FLOW_IDS)) assertSchema('FlowDetail', await api.getFlow(id))
    assertSchemaArray('NetObject', await api.objects.list())
    assertSchemaArray('Service', await api.services.list())
    assertSchemaArray('DataClass', await api.dataClasses.list())
    assertSchemaArray('Zone', await api.zones.list())
    assertSchemaArray('Agent', await api.agents.list())
    assertSchemaArray('RuleView', await api.rules.list())
    assertSchemaArray('InspectionRule', await api.inspectionRules.list())
    assertSchemaArray('RuleView', await api.listRules())
    assertSchema('Rulebase', await api.getRulebase())
    assertSchema('WhereUsed', await api.whereUsed(OBJ.llm))
    assertSchema('PolicySettings', await api.getSettings())
    assertSchema('Page_for_Revision', await api.listRevisions())
    assertSchema('RevisionDetail', await api.getRevision(42))
    assertSchema('RevisionDiff', await api.diffRevision(42))
    assertSchema('VerifyReport', await api.verify(42))
    assertSchema('PolicyStatus', await api.policyStatus())
    assertSchema('Page_for_Install', await api.listInstalls())
    assertSchema('AgentOverview', await api.agentOverview(AGENT_IDS.daniel))
    assertSchema('Page_for_Alert', await api.listAlerts())
    assertSchemaArray('AlertChannel', await api.alertChannels.list())
    assertSchema('InternalMap', await api.internalMap('24h'))
    assertSchema('Page_for_AuditEntry', await api.listAudit())
    assertSchema('AuditVerifyResult', (({ anchor_sources: _a, ...r }) => r)(await api.verifyAudit()))
    assertSchemaArray('Gateway', await api.listGateways())
    assertSchemaArray('ApiToken', await api.listTokens())
    assertSchema('RegistrationToken', await api.createRegistrationToken('gw-new'))
    assertSchema('Page_for_Capture', await api.listCaptures())
  })

  it('journal: filters by verdict and agent id, newest first, with display fields from the API', async () => {
    const api = createMockApi()
    const page = await api.listFlows({ verdict: 'deny', agent: AGENT_IDS.daniel })
    expect(page.items.length).toBeGreaterThan(0)
    expect(page.items.every(f => f.verdict === 'deny' && f.agent_id === AGENT_IDS.daniel)).toBe(true)
    expect(page.items[0]).toMatchObject({ id: FLOW_IDS.upload, agent_name: 'daniel-bot', zone_name: 'bots-internes', rule_label: 'default-deny', tool: 'upload_file' })
    const times = page.items.map(f => f.started_at)
    expect([...times].sort().reverse()).toEqual(times)
  })

  it('flow detail: trace ends on the deciding rule, allow proposal and EF-21 message', async () => {
    const api = createMockApi()
    const d = await api.getFlow(FLOW_IDS.upload)
    expect(d.trace.at(-1)).toMatchObject({ layer: 'implicit', outcome: 'matched', rule_label: 'default-deny' })
    expect(d.trace.slice(0, -1).every(s => s.outcome === 'not_matched')).toBe(true)
    expect(d.agent_message).toBe('blocked by agents-firewall: upload.fichiers-partage.example not allowed for daniel-bot (rule default-deny)')
    expect(d.allow_proposal?.zone_id).toBe(ZONE_IDS.internes)
    expect(d.allow_proposal?.destinations.map(x => x.kind)).toEqual(['exact', 'wildcard'])
    expect(d.allow_proposal?.service).toMatchObject({ label: 'https', port: 443 })
    const allowed = await api.getFlow(FLOW_IDS.llm)
    expect(allowed.allow_proposal).toBeNull()
    expect(allowed.trace.at(-1)).toMatchObject({ rule_id: RULE_IDS.llm, outcome: 'matched' })
  })

  it('allow → publish → install: rule at the top of the zone layer, revision 43, gateways acknowledge', async () => {
    const api = createMockApi({ installAckMs: 5 })
    const session = await api.openSession('Autoriser upload')
    assertSchema('Session', session)
    expect(session).toMatchObject({ state: 'open', base_revision: 42, next_revision: 43 })
    const res = await api.allowFromLog(session.id, { flow_id: FLOW_IDS.upload, destination: 'wildcard', expires_in_days: 30, track: 'detailed' })
    assertSchema('AllowFromLogResponse', res)
    expect(res.rule).toMatchObject({ name: 'Autoriser upload.fichiers-partage.example', position: 1, pending_change: 'create', action: 'accept' })
    expect(res.created_object?.spec).toEqual({ type: 'domain', pattern: '*.fichiers-partage.example' })
    expect(res.changes.map(c => c.resource.kind)).toEqual(expect.arrayContaining(['object', 'rule']))

    // Read with the session: the draft is visible, the former first rule of the zone moved down.
    api.setSession(session.id)
    const rb = await api.getRulebase()
    const zone = rb.zones.find(z => z.zone.id === ZONE_IDS.internes)!
    const first = zone.sections[0]!.rules[0]!
    expect(first.id).toBe(res.rule.id)
    expect(zone.sections.flatMap(s => s.rules).find(r => r.id === RULE_IDS.m365)?.pending_change).toBe('update')
    api.setSession(null)
    expect((await api.getRulebase()).zones.find(z => z.zone.id === ZONE_IDS.internes)!.sections[0]!.rules[0]!.id).toBe(RULE_IDS.m365)

    const outcome = await api.publishSession(session.id, 'Autoriser le dépôt de fichiers')
    expect(outcome.status).toBe('published')
    if (outcome.status !== 'published') return
    assertSchema('Revision', outcome.revision)
    expect(outcome.revision.number).toBe(43)
    expect((await api.currentSession())?.pending_install).toBe(43)

    const inst = await api.install(43, [])
    assertSchema('InstallResult', inst)
    expect(inst.installs.map(i => i.gateway_id).sort()).toEqual(Object.values(GW_IDS).sort())
    expect(inst.installs.every(i => i.state === 'pending')).toBe(true)
    await new Promise(r => setTimeout(r, 20))
    const status = await api.policyStatus()
    expect(status).toMatchObject({ latest_revision: 43, installed_revision: 43, gateways_total: 3, gateways_on_revision: 2, pending_installs: 2 })
    expect(await api.currentSession()).toBeNull()
    const audit = await api.listAudit({ action: 'session.*' })
    expect(audit.items.map(e => e.action)).toEqual(expect.arrayContaining(['session.open', 'session.publish']))
  })

  it('locks: a resource changed in another session answers 423 with its owner', async () => {
    const api = createMockApi()
    api.control.lockByOther('object', OBJ.s3)
    const s = await api.openSession(null)
    const obj = (await api.objects.get(OBJ.s3))
    const err = await api.objects.update(s.id, { ...obj, comment: 'x' }).catch(e => e) as ApiError
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(423)
    expect(err.lockedBy).toBe('Marie Durand')
    const views = await api.listRules()
    expect(views.every(v => v.locked_by == null)).toBe(true)
  })

  it('approvals: publish answers 202 then 409 while pending', async () => {
    const api = createMockApi()
    api.control.requireApproval(true)
    const s = await api.openSession(null)
    await api.zones.create(s.id, { id: '', name: 'nouvelle-zone', comment: '', mode: 'observe', delegated_to_mcp: false })
    const out = await api.publishSession(s.id, 'c')
    expect(out.status).toBe('approval')
    if (out.status === 'approval') assertSchema('Approval', out.approval)
    expect((await api.getSession(s.id)).approval_id).toBeTruthy()
    await expect(api.publishSession(s.id, 'c')).rejects.toMatchObject({ status: 409, detail: 'approval pending' })
  })

  it('CRUD in a session: validation errors come from the API, deletes refuse referenced objects', async () => {
    const api = createMockApi()
    const s = await api.openSession(null)
    await expect(api.objects.create(s.id, { id: '', name: '', comment: '', category: null, spec: { type: 'any' } })).rejects.toMatchObject({ status: 400 })
    await expect(api.objects.remove(s.id, OBJ.s3)).rejects.toMatchObject({ status: 409 })
    const created = await api.objects.create(s.id, { id: '', name: 'dom-test', comment: '', category: null, spec: { type: 'domain', pattern: 'test.example' } })
    assertSchema('NetObject', created)
    api.setSession(s.id)
    expect((await api.objects.list()).some(o => o.name === 'dom-test')).toBe(true)
    api.setSession(null)
    expect((await api.objects.list()).some(o => o.name === 'dom-test')).toBe(false)
    // Moving an agent to another zone is an agent update.
    const agent = await api.agents.get(AGENT_IDS.compta)
    const moved = await api.agents.update(s.id, { ...agent, zone_id: ZONE_IDS.clients })
    expect(moved.zone_id).toBe(ZONE_IDS.clients)
    expect((await api.getSession(s.id)).changes).toBe(2)
    // Rule move.
    const r = await api.moveRule(s.id, RULE_IDS.github, { position: 1 })
    expect(r.position).toBe(1)
  })

  it('stream: pushes flow events and the lagged notice to subscribers', async () => {
    const api = createMockApi()
    const got: StreamEvent[] = []
    const stop = api.streamLogs(e => got.push(e))
    const f = (await api.getFlow(FLOW_IDS.llm)).flow
    api.control.emit({ kind: 'event', event: { ...f, id: 'f-new', type: 'flow' } })
    api.control.emit({ kind: 'lagged', skipped: 3 })
    stop()
    api.control.emit({ kind: 'lagged', skipped: 1 })
    expect(got.map(e => e.kind)).toEqual(['event', 'lagged'])
    expect((await api.listFlows({})).items[0]!.id).toBe('f-new')
  })

  it('expired token: every call answers 401', async () => {
    const api = createMockApi()
    api.control.expireToken()
    await expect(api.me()).rejects.toMatchObject({ status: 401 })
  })
})
