/** Shell-quotes a value with single quotes. */
function sq(v: string): string {
  return `'${v.replace(/'/g, `'\\''`)}'`
}

export interface AllowCliInput {
  zone: string
  dest: string
  createObject: boolean
  service: string
  before: string
  expiresInDays: number | null
  flowId: string
}

/**
 * "Équivalent CLI" of the pre-filled rule — same operation through the `afw` CLI, the API or the MCP.
 * Every value comes from the API (and ultimately from agent traffic): all of them are single-quoted
 * so that pasting the command in a shell can never run anything else.
 */
export function allowRuleCli(i: AllowCliInput): string {
  const days = i.expiresInDays == null ? '' : ` --expire ${Math.trunc(Number(i.expiresInDays))}d`
  return [
    '$ afw rule add \\',
    `    --zone ${sq(i.zone)} \\`,
    `    --dest ${sq(i.dest)}${i.createObject ? ' --create-object' : ''} \\`,
    `    --service ${sq(i.service)} --action accept \\`,
    `    --before ${sq(i.before)}${days} \\`,
    `    --comment ${sq(`flux ${i.flowId}`)}`,
  ].join('\n')
}

export function curlFor(req: { method: string, url: string, headers: [string, string][] }): string {
  const lines = [`curl -X ${sq(req.method)} ${sq(req.url)}`, ...req.headers.map(([k, v]) => `  -H ${sq(`${k}: ${v}`)}`)]
  return lines.join(' \\\n')
}

const REASONS: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 409: 'Conflict', 429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
}

export function httpReason(status: number): string {
  return REASONS[status] ? `${status} ${REASONS[status]}` : String(status)
}
