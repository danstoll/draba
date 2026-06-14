/**
 * Auth context: current user + access token in memory, refresh token in localStorage.
 *
 * Provides login, logout, and register actions so any component can
 * authenticate without knowing about token storage details.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import type { components } from '@draba/shared'
import {
  API_BASE,
  ApiError,
  clearStoredRefreshToken,
  configureSilentRefresh,
  getStoredRefreshToken,
  storeRefreshToken,
} from '@/lib/api'

type User = components['schemas']['User']
type AuthResponse = components['schemas']['AuthResponse']
type RefreshResponse = components['schemas']['RefreshResponse']

interface AuthState {
  user: User | null
  accessToken: string | null
  /** True while checking the stored refresh token on initial mount. */
  initializing: boolean
}

interface AuthContextValue extends AuthState {
  getAccessToken: () => string | null
  login: (email: string, password: string) => Promise<void>
  /** Registers a new account and returns the fresh access token directly,
   *  avoiding a race against the async setState that follows. */
  register: (email: string, password: string, displayName: string, inviteToken?: string) => Promise<string>
  /** Establishes a session directly from tokens obtained out-of-band (e.g. the
   *  OIDC callback's URL fragment), persisting the refresh token and loading
   *  the user. Avoids a full-page reload that would race the mount restore. */
  loginWithTokens: (accessToken: string, refreshToken: string) => Promise<void>
  logout: () => void
  /** Merges fields into the current user object — used after profile updates. */
  patchUser: (patch: Partial<User>) => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) {
    const err = data as { error: { code: string; message: string } }
    throw new ApiError(res.status, err.error?.code ?? 'UNKNOWN', err.error?.message ?? res.statusText)
  }
  return data as T
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    initializing: true,
  })

  // Stable ref so callbacks never capture a stale token.
  const tokenRef = useRef<string | null>(null)
  tokenRef.current = state.accessToken

  const getAccessToken = useCallback(() => tokenRef.current, [])

  // On mount, attempt to restore session via the stored refresh token.
  // After exchanging the refresh token we also fetch /auth/me so that `user`
  // is populated — without it, admin checks (canEditTeam etc.) always fail
  // because userId is '' and no member's userId matches an empty string.
  useEffect(() => {
    const refresh = getStoredRefreshToken()
    if (!refresh) {
      setState(s => ({ ...s, initializing: false }))
      return
    }
    postJson<RefreshResponse>('/auth/refresh', { refreshToken: refresh })
      .then(async ({ accessToken }) => {
        try {
          const res = await fetch(`${API_BASE}/auth/me`, {
            headers: { Authorization: `Bearer ${accessToken}` },
          })
          const user: User | null = res.ok ? (await res.json() as User) : null
          setState({ user, accessToken, initializing: false })
        } catch {
          // /auth/me failed but the token is still valid — set what we have.
          setState(s => ({ ...s, accessToken, initializing: false }))
        }
      })
      .catch(() => {
        clearStoredRefreshToken()
        setState(s => ({ ...s, initializing: false }))
      })
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const { user, accessToken, refreshToken } = await postJson<AuthResponse>('/auth/login', {
      email,
      password,
    })
    storeRefreshToken(refreshToken)
    setState({ user, accessToken, initializing: false })
  }, [])

  const register = useCallback(
    async (
      email: string,
      password: string,
      displayName: string,
      inviteToken?: string,
    ): Promise<string> => {
      const { user, accessToken, refreshToken } = await postJson<AuthResponse>(
        '/auth/register',
        { email, password, displayName, inviteToken },
      )
      storeRefreshToken(refreshToken)
      setState({ user, accessToken, initializing: false })
      // Return the token directly so callers don't race against the async
      // setState — tokenRef won't update until the next render cycle.
      return accessToken
    },
    [],
  )

  const loginWithTokens = useCallback(async (accessToken: string, refreshToken: string) => {
    storeRefreshToken(refreshToken)
    // Load the user with the access token we already hold; tolerate failure
    // (the token is still valid) the same way the mount restore does.
    let user: User | null = null
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      if (res.ok) user = (await res.json()) as User
    } catch {
      // keep user null; session still works via the access token
    }
    setState({ user, accessToken, initializing: false })
  }, [])

  const logout = useCallback(() => {
    clearStoredRefreshToken()
    setState({ user: null, accessToken: null, initializing: false })
  }, [])

  // Register a silent-refresh callback with the API layer so that any 401
  // anywhere in the app triggers a token refresh rather than a hard failure.
  // On refresh failure, clear the session and redirect to /login.
  useEffect(() => {
    const silentRefresh = async (): Promise<string | null> => {
      const refresh = getStoredRefreshToken()
      if (!refresh) {
        logout()
        window.location.replace('/login')
        return null
      }
      try {
        const { accessToken: newToken } = await postJson<RefreshResponse>('/auth/refresh', { refreshToken: refresh })
        setState(s => ({ ...s, accessToken: newToken }))
        return newToken
      } catch {
        clearStoredRefreshToken()
        setState({ user: null, accessToken: null, initializing: false })
        window.location.replace('/login')
        return null
      }
    }
    configureSilentRefresh(silentRefresh)
    return () => configureSilentRefresh(null)
  }, [logout])

  const patchUser = useCallback((patch: Partial<User>) => {
    setState(s => s.user ? { ...s, user: { ...s.user, ...patch } } : s)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, getAccessToken, login, register, loginWithTokens, logout, patchUser }),
    [state, getAccessToken, login, register, loginWithTokens, logout, patchUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** Returns the auth context. Throws if used outside of AuthProvider. */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
