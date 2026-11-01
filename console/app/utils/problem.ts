import { ApiError } from '~/api/client'

export interface ProblemText {
  /** Translation key of the headline. */
  key: string
  params: Record<string, string>
  /** Server detail, shown as is (the API's validation message is the reference). */
  detail: string | null
}

/** How the console words an API error: 423 names the lock owner, the API's detail is kept verbatim. */
export function describeProblem(e: unknown): ProblemText {
  if (!(e instanceof ApiError)) return { key: 'errors.unexpected', params: {}, detail: e instanceof Error ? e.message : String(e) }
  switch (e.status) {
    case 0: return { key: 'errors.network', params: {}, detail: e.detail ?? null }
    case 400: return { key: 'errors.invalid', params: {}, detail: e.detail ?? null }
    case 401: return { key: 'errors.unauthorized', params: {}, detail: null }
    case 403: return { key: 'errors.forbidden', params: {}, detail: e.detail ?? null }
    case 404: return { key: 'errors.notFound', params: {}, detail: null }
    case 409: return { key: 'errors.conflict', params: {}, detail: e.detail ?? null }
    case 423: return { key: 'errors.locked', params: { by: e.lockedBy ?? '?' }, detail: null }
    default: return { key: 'errors.server', params: { status: String(e.status) }, detail: e.detail ?? null }
  }
}
