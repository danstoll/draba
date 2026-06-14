/**
 * OIDCCallbackPage — lands the browser after a successful SSO login.
 *
 * The API's /auth/oidc/callback redirects here with the freshly issued tokens
 * in the URL fragment (#access_token=…&refresh_token=…). The fragment is used
 * rather than the query string so the tokens are never sent to a server or
 * written to an access log.
 *
 * We hand the tokens straight to the auth context and navigate via the router.
 * We deliberately do NOT do a full-page reload: a hard navigation aborts the
 * in-flight session-restore request (surfacing as "TypeError: Failed to fetch")
 * and races the AuthProvider mount, which previously bounced the user back to
 * the login page even though SSO had succeeded.
 */

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'

export default function OIDCCallbackPage() {
  const { loginWithTokens } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)
  // Guard against React StrictMode double-invocation consuming the hash twice.
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current) return
    ran.current = true

    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')

    if (!accessToken || !refreshToken) {
      navigate('/login?sso_error=missing_tokens', { replace: true })
      return
    }

    // Clear the tokens from the address bar immediately.
    window.history.replaceState(null, '', '/auth/callback')

    loginWithTokens(accessToken, refreshToken)
      .then(() => navigate('/', { replace: true }))
      .catch((e) => setError((e as Error).message || 'Sign-in failed'))
  }, [loginWithTokens, navigate])

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
      {error ? `Sign-in failed: ${error}` : 'Signing you in…'}
    </div>
  )
}
