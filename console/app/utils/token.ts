export const TOKEN_KEY = 'afw-token'

/** Bearer token (OIDC access token or API token), kept for the browser session only. */
export function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  }
  catch {
    return null
  }
}

export function writeToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token)
    else sessionStorage.removeItem(TOKEN_KEY)
  }
  catch {
    // storage unavailable (private mode): the token lives until reload
  }
}
