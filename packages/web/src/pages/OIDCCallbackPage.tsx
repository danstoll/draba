/**
 * OIDCCallbackPage — lands the browser after a successful SSO login.
 *
 * The API's /auth/oidc/callback redirects here with the freshly issued tokens
 * in the URL fragment (#access_token=…&refresh_token=…). The fragment is used
 * rather than the query string so the tokens are never sent to a server or
 * written to an access log. We persist the refresh token and hand off to "/",
 * where AuthProvider's mount effect exchanges it for a session — reusing the
 * exact same restore path as a normal page load.
 */

import { useEffect } from 'react'
import { storeRefreshToken } from '@/lib/api'

export default function OIDCCallbackPage() {
  useEffect(() => {
    // location.hash looks like "#access_token=...&refresh_token=..."
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const refresh = params.get('refresh_token')

    if (!refresh) {
      window.location.replace('/login?sso_error=missing_tokens')
      return
    }

    storeRefreshToken(refresh)
    // Strip the tokens from the address bar, then let AuthProvider restore the
    // session from the stored refresh token on the next load.
    window.location.replace('/')
  }, [])

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--background)',
        color: 'var(--muted-foreground)',
        fontSize: 14,
      }}
    >
      Signing you in…
    </div>
  )
}
