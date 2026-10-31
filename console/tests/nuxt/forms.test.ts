import { flushPromises } from '@vue/test-utils'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { describe, expect, it } from 'vitest'
import type { MockApi } from '../../app/api/mock'
import { OBJ, ZONE_IDS } from '../../app/api/mock-data'
import ObjectForm from '../../app/components/forms/ObjectForm.vue'
import ZoneForm from '../../app/components/forms/ZoneForm.vue'
import SessionBanner from '../../app/components/shell/SessionBanner.vue'

async function until(check: () => boolean, label: string) {
  for (let i = 0; i < 80; i++) {
    if (check()) return
    await flushPromises()
    await new Promise(r => setTimeout(r, 0))
  }
  throw new Error(`timeout: ${label}`)
}

/** The forms render in a modal (teleported to body). */
const body = () => document.body
const q = (sel: string) => body().querySelector<HTMLElement>(sel)

/** Submits the form holding `field` (several modals may be open in the shared document). */
function submit(field: string) {
  q(field)!.closest('form')!.querySelector<HTMLButtonElement>('[data-testid="form-submit"]')!.click()
}

async function type(sel: string, value: string) {
  const el = q(sel) as HTMLInputElement
  el.value = value
  el.dispatchEvent(new Event('input'))
  await flushPromises()
}

describe('forms (EF-44): every change goes through the API, in the session', () => {
  it('creates an object in the session (draft visible, published policy unchanged)', async () => {
    const api = useNuxtApp().$api as MockApi
    await mountSuspended(ObjectForm, { props: { open: true } })
    await until(() => !!q('#obj-name'), 'form')
    await type('#obj-name', 'dom-nouveau')
    await type('#obj-value', 'nouveau.exemple.fr')
    submit('#obj-name')
    await until(() => !q('#obj-name'), 'form closed')
    const s = await api.currentSession()
    expect(s?.state).toBe('open')
    expect(s?.locks.map(l => l.name)).toContain('dom-nouveau')
    api.setSession(null)
    expect((await api.objects.list()).some(o => o.name === 'dom-nouveau')).toBe(false)
    api.setSession(s!.id)
    expect((await api.objects.list()).find(o => o.name === 'dom-nouveau')?.spec).toEqual({ type: 'domain', pattern: 'nouveau.exemple.fr' })
  })

  it('shows the API validation message as is', async () => {
    await mountSuspended(ObjectForm, { props: { open: true } })
    await until(() => !!q('#obj-name'), 'form')
    await type('#obj-name', '')
    submit('#obj-name')
    await until(() => !!q('[data-testid="form-error"]'), 'error')
    expect(q('[data-testid="form-error"]')!.textContent).toContain('name must not be empty')
  })

  it('names the owner of a lock (423)', async () => {
    const api = useNuxtApp().$api as MockApi
    api.control.lockByOther('zone', ZONE_IDS.ops)
    const zone = await api.zones.get(ZONE_IDS.ops)
    await mountSuspended(ZoneForm, { props: { open: true, zone } })
    await until(() => !!q('#zone-name'), 'form')
    submit('#zone-name')
    await until(() => [...body().querySelectorAll('[data-testid="form-error"]')].some(e => e.textContent?.includes('Marie Durand')), 'lock error')
    expect([...body().querySelectorAll('[data-testid="form-error"]')].map(e => e.textContent).join()).toContain('Modifié par Marie Durand dans une autre session')
  })

  it('shows the pending approval banner after a 202 publish', async () => {
    const api = useNuxtApp().$api as MockApi
    api.control.requireApproval(true)
    const banner = await mountSuspended(SessionBanner)
    const { publish, ensureOpen } = usePolicySession()
    const s = await ensureOpen('approbation')
    await api.objects.update(s.id, { ...(await api.objects.get(OBJ.github)), comment: 'élargi' })
    const out = await publish('élargissement')
    expect(out.status).toBe('approval')
    await until(() => banner.find('[data-testid="approval-banner"]').exists(), 'banner')
    expect(banner.text()).toContain('Publication en attente d’approbation humaine (EF-52)')
    expect(banner.text()).toContain('Killian Stein')
  })
})
