export interface NavItem {
  key: string
  to: string
  icon: string
  /** Two-key shortcut ("g j"). */
  keys?: string
  /** Other routes that highlight this item. */
  also?: string[]
}

export interface NavGroup {
  key: 'watch' | 'policy' | 'infra'
  items: NavItem[]
}

export const NAV: NavGroup[] = [
  {
    key: 'watch',
    items: [
      { key: 'journal', to: '/', icon: 'i-lucide-align-left', keys: 'g j', also: ['/flows'] },
      { key: 'agents', to: '/agents', icon: 'i-lucide-bot', keys: 'g a' },
      { key: 'internal', to: '/internal', icon: 'i-lucide-share-2', keys: 'g i' },
      { key: 'alerts', to: '/alerts', icon: 'i-lucide-bell', keys: 'g l' },
    ],
  },
  {
    key: 'policy',
    items: [
      { key: 'rules', to: '/rules', icon: 'i-lucide-shield', keys: 'g r' },
      { key: 'objects', to: '/objects', icon: 'i-lucide-layout-grid', keys: 'g o' },
      { key: 'inspection', to: '/inspection', icon: 'i-lucide-eye' },
      { key: 'revisions', to: '/revisions', icon: 'i-lucide-history', keys: 'g v', also: ['/audit'] },
    ],
  },
  {
    key: 'infra',
    items: [
      { key: 'gateways', to: '/gateways', icon: 'i-lucide-server', keys: 'g p' },
      { key: 'settings', to: '/settings', icon: 'i-lucide-settings' },
    ],
  },
]

export function isActive(item: NavItem, path: string): boolean {
  if (item.to === '/') return path === '/' || (item.also ?? []).some(p => path.startsWith(p))
  return path === item.to || path.startsWith(`${item.to}/`) || (item.also ?? []).some(p => path.startsWith(p))
}
