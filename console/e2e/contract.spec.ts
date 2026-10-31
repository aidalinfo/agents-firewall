/**
 * Contract checked end to end: every method of `createHttpApi` (the console's real client) is
 * called against the running afw-api, and every answer is validated against the JSON schemas of
 * docs/api/openapi.yaml (strict: no undeclared field).
 */
import { expect, test } from '@playwright/test'
import { ApiError } from '../app/api/client'
import { createHttpApi } from '../app/api/http'
import type { StreamEvent } from '../app/api/types'
import { assertSchema, assertSchemaArray } from '../tests/support/contract'

const API = process.env.AFW_E2E_API ?? 'http://afw-api:8080'
const TOKEN = process.env.AFW_E2E_TOKEN ?? 'afw-e2e-admin-token-0123456789'
const DANIEL = '00000000-0000-4000-8000-000000000501'
const INTERNES = '00000000-0000-4000-8000-000000000401'
const DENIED_FLOW = '00000000-0000-4000-8000-00000000f001'

test('every method of the HTTP client matches the contract against the real API', async () => {
  let unauthorized = 0
  const api = createHttpApi({ baseUrl: API, getToken: () => TOKEN, onUnauthorized: () => unauthorized++ })

  assertSchema('Me', await api.me())
  const oidc = await api.oidcConfig()
  expect(typeof oidc.enabled).toBe('boolean')
  assertSchemaArray('ApiToken', await api.listTokens())
  const created = await api.createToken({ name: 'e2e-contract', role: 'viewer' })
  assertSchema('CreatedApiToken', created)
  await api.revokeToken(created.token.id)

  const flows = await api.listFlows({ limit: 50 })
  assertSchema('Page_for_FlowListItem', flows)
  expect(flows.items.length).toBeGreaterThan(0)
  assertSchema('FlowStats', await api.flowStats({ bucket: '1m' }))
  assertSchema('FlowDetail', await api.getFlow(DENIED_FLOW))
  assertSchema('Page_for_Capture', await api.listCaptures())

  assertSchemaArray('NetObject', await api.objects.list())
  assertSchemaArray('Service', await api.services.list())
  assertSchemaArray('DataClass', await api.dataClasses.list())
  assertSchemaArray('Zone', await api.zones.list())
  assertSchemaArray('Agent', await api.agents.list())
  assertSchemaArray('Rule', await api.rules.list())
  assertSchemaArray('InspectionRule', await api.inspectionRules.list())
  assertSchemaArray('RuleView', await api.listRules())
  assertSchema('Rulebase', await api.getRulebase())
  assertSchema('PolicySettings', await api.getSettings())
  const objects = await api.objects.list()
  assertSchema('WhereUsed', await api.whereUsed(objects[0]!.id))
  assertSchema('NetObject', await api.objects.get(objects[0]!.id))

  assertSchema('Page_for_Revision', await api.listRevisions())
  assertSchema('RevisionDetail', await api.getRevision(1))
  assertSchema('RevisionDiff', await api.diffRevision(1))
  assertSchema('VerifyReport', await api.verify(1))
  assertSchema('PolicyStatus', await api.policyStatus())
  assertSchema('Page_for_Install', await api.listInstalls())
  assertSchemaArray('Approval', await api.listApprovals())
  assertSchema('AgentOverview', await api.agentOverview(DANIEL))
  assertSchema('Page_for_Alert', await api.listAlerts())
  assertSchema('InternalMap', await api.internalMap('24h'))
  assertSchema('Page_for_AuditEntry', await api.listAudit({ limit: 5 }))
  const chain = await api.verifyAudit()
  expect(chain.ok).toBe(true)
  expect((await (await api.exportAudit()).text()).split('\n')[0]).toContain('"seq"')
  const gateways = await api.listGateways()
  assertSchemaArray('Gateway', gateways)
  assertSchema('RegistrationToken', await api.createRegistrationToken('gw-e2e'))
  await api.sendGatewayCommand(gateways[0]!.id, { type: 'self_test' })

  // Alert channels and acknowledgement (outside policy sessions).
  const channel = await api.alertChannels.create({ id: '7a1c0000-0000-4000-8000-0000000000c1', name: 'e2e-webhook', kind: 'webhook', url: 'https://hooks.example.org/afw', min_severity: 'critical', enabled: false })
  assertSchema('AlertChannel', channel)
  assertSchema('AlertChannel', await api.alertChannels.update({ ...channel, enabled: false, url: 'https://hooks.example.org/afw2' }))
  assertSchemaArray('AlertChannel', await api.alertChannels.list())
  await api.alertChannels.remove(channel.id)
  const alerts = await api.listAlerts({ acknowledged: false })
  if (alerts.items[0]) assertSchema('Alert', await api.acknowledgeAlert(alerts.items[0].event.id))

  // Policy writes in a session: create, update, move, delete, settings, discard.
  const session = await api.openSession('e2e contrat')
  assertSchema('Session', session)
  api.setSession(session.id)
  const zone = await api.zones.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a1', name: 'e2e-zone', comment: '', mode: 'observe', delegated_to_mcp: false })
  assertSchema('Zone', zone)
  const obj = await api.objects.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a2', name: 'e2e.example', comment: '', category: null, spec: { type: 'domain', pattern: 'e2e.example' } })
  const svc = await api.services.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a3', name: 'e2e-8443', comment: '', protocol: 'tcp', ports: [{ start: 8443, end: 8443 }], app: null })
  const dc = await api.dataClasses.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a4', name: 'e2e-classe', comment: '', category: 'custom', detectors: [{ type: 'regex', name: 'ref', pattern: 'E2E-\\d{4}' }] })
  assertSchema('DataClass', dc)
  const rule = await api.rules.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a5', name: 'e2e règle', layer: { type: 'zone', zone_id: zone.id }, section: 'E2E', position: 1, sources: [zone.id], destinations: [obj.id], services: [svc.id], data_classes: [], action: 'accept', track: 'log', expires_at: null, comment: '', enabled: true })
  assertSchema('Rule', rule)
  assertSchema('Rule', await api.rules.update(session.id, { ...rule, comment: 'modifiée' }))
  assertSchema('Rule', await api.moveRule(session.id, rule.id, { position: 1, section: 'E2E bis' }))
  const insp = await api.inspectionRules.create(session.id, { id: '7a1c0000-0000-4000-8000-0000000000a6', name: 'e2e inspection', position: 1, zones: [zone.id], destinations: [obj.id], action: 'bypass' })
  assertSchema('InspectionRule', insp)
  const agent = await api.agents.get(DANIEL)
  assertSchema('Agent', await api.agents.update(session.id, { ...agent, zone_id: INTERNES }))
  assertSchema('PolicySettings', await api.updateSettings(session.id, await api.getSettings()))
  expect((await api.listRules({ zone_id: zone.id })).map(r => r.pending_change)).toEqual(['create'])
  assertSchema('VerifyReport', await api.verify())
  await api.inspectionRules.remove(session.id, insp.id)
  const current = await api.currentSession()
  assertSchema('Session', current)
  expect(current?.changes).toBeGreaterThan(0)
  assertSchema('Session', await api.getSession(session.id))
  assertSchema('Session', await api.discardSession(session.id))
  api.setSession(null)

  // Problem details: 404 and 409 come back as ApiError with the API's detail.
  const missing = await api.getFlow('00000000-0000-4000-8000-0000000000ff').catch(e => e)
  expect(missing).toBeInstanceOf(ApiError)
  expect((missing as ApiError).status).toBe(404)
  const s2 = await api.openSession('e2e conflit')
  const conflict = await api.openSession('e2e conflit 2').catch(e => e)
  expect(conflict).toBeInstanceOf(ApiError)
  expect((conflict as ApiError).status).toBe(409)
  await api.discardSession(s2.id)

  // Revert opens a session whose content is the revision.
  const revert = await api.revertToRevision(1)
  assertSchema('Session', revert)
  await api.discardSession(revert.id)

  // A bad token: 401 and the callback.
  const anonymous = createHttpApi({ baseUrl: API, getToken: () => 'not-a-token', onUnauthorized: () => unauthorized++ })
  const e401 = await anonymous.me().catch(e => e)
  expect((e401 as ApiError).status).toBe(401)
  expect(unauthorized).toBe(1)

  // Live stream: subscribed, then closed (the server sends keep-alives; events need a gateway).
  const events: StreamEvent[] = []
  const stop = api.streamLogs(e => events.push(e))
  await new Promise(r => setTimeout(r, 500))
  stop()
})
