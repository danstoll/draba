import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { Eye, EyeOff, Check, Loader2 } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { ApiError, API_BASE } from '@/lib/api'
import DarkModeToggle from '@/components/DarkModeToggle'
import { usePublicSettings } from '@/hooks/usePublicSettings'

// ── Floating-label input ─────────────────────────────────────────────────────

interface FloatInputProps {
  id: string
  label: string
  type: string
  value: string
  autoComplete: string
  error?: string | null
  onChange: (v: string) => void
  onKeyDown?: (e: React.KeyboardEvent) => void
  rightSlot?: React.ReactNode
}

function FloatInput({ id, label, type, value, autoComplete, error, onChange, onKeyDown, rightSlot }: FloatInputProps) {
  const [focused, setFocused] = useState(false)
  const floated = focused || value.length > 0

  const borderColor = error
    ? '#e74c3c'
    : focused
    ? '#288C9B'
    : 'hsl(210 15% 24%)'

  const boxShadow = error
    ? '0 0 0 3px rgba(231,76,60,0.15)'
    : focused
    ? '0 0 0 3px rgba(40,140,155,0.18)'
    : 'none'

  const labelColor = error
    ? '#e74c3c'
    : focused
    ? '#5BC0DE'
    : 'hsl(210 15% 65%)'

  return (
    <div>
      <div style={{
        position: 'relative',
        borderRadius: 8,
        border: `1px solid ${borderColor}`,
        background: 'hsl(210 15% 17%)',
        transition: 'border-color 180ms ease, box-shadow 180ms ease',
        boxShadow,
      }}>
        {/* Floating label */}
        <label
          htmlFor={id}
          style={{
            position: 'absolute',
            left: 14,
            top: floated ? 8 : '50%',
            transform: floated ? 'none' : 'translateY(-50%)',
            fontSize: floated ? 11 : 14,
            letterSpacing: floated ? '0.06em' : 0,
            textTransform: floated ? 'uppercase' : 'none',
            fontWeight: 600,
            color: labelColor,
            transition: 'all 160ms cubic-bezier(0.4, 0, 0.2, 1)',
            pointerEvents: 'none',
            userSelect: 'none',
          }}
        >
          {label}
        </label>

        <input
          id={id}
          type={type}
          autoComplete={autoComplete}
          value={value}
          onChange={e => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={onKeyDown}
          style={{
            width: '100%',
            padding: '22px 42px 8px 14px',
            background: 'transparent',
            border: 'none',
            outline: 'none',
            fontSize: 15,
            color: 'hsl(210 17% 93%)',
            fontFamily: 'inherit',
            lineHeight: 1.4,
            boxSizing: 'border-box',
          }}
        />

        {rightSlot && (
          <div style={{
            position: 'absolute',
            right: 12,
            top: '50%',
            transform: 'translateY(-50%)',
          }}>
            {rightSlot}
          </div>
        )}
      </div>

      {error && (
        <p style={{ fontSize: 12, color: '#e74c3c', margin: '5px 0 0 2px' }}>{error}</p>
      )}
    </div>
  )
}

// ── Spinner ──────────────────────────────────────────────────────────────────

function Spinner() {
  return (
    <Loader2
      size={16}
      strokeWidth={2.5}
      color="rgba(255,255,255,0.8)"
      style={{ animation: 'spin 0.8s linear infinite' }}
    />
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? '/'
  // A success message routed here from another page (e.g. password reset).
  // Derived from navigation state, so it clears naturally on a full reload.
  const notice = (location.state as { message?: string } | null)?.message ?? null
  const { data: branding } = usePublicSettings()
  const instanceName = branding?.instanceName || 'draba'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [emailError, setEmailError] = useState<string | null>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [serverError, setServerError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  function validateAndSubmit() {
    let valid = true
    setServerError(null)

    if (!email.trim()) {
      setEmailError('Email is required')
      valid = false
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      setEmailError('Enter a valid email')
      valid = false
    } else {
      setEmailError(null)
    }

    if (!password) {
      setPasswordError('Password is required')
      valid = false
    } else if (password.length < 6) {
      setPasswordError('Password must be at least 6 characters')
      valid = false
    } else {
      setPasswordError(null)
    }

    if (!valid) return
    doLogin()
  }

  async function doLogin() {
    setLoading(true)
    try {
      await login(email, password)
      setSuccess(true)
      // Brief success flash then navigate
      setTimeout(() => navigate(from, { replace: true }), 600)
    } catch (err) {
      if (err instanceof ApiError) {
        setServerError(err.message)
      } else {
        setServerError('Something went wrong. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    validateAndSubmit()
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--background)',
      padding: '24px',
      position: 'relative',
    }}>
      {/* Teal radial glow behind card */}
      <div style={{
        position: 'fixed',
        inset: 0,
        background: 'radial-gradient(ellipse 60% 50% at 20% 50%, rgba(40,140,155,0.12) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      {/* Dark mode toggle */}
      <div style={{ position: 'fixed', top: 16, right: 16, zIndex: 10 }}>
        <DarkModeToggle />
      </div>

      {/* Card */}
      <div style={{
        width: '100%',
        maxWidth: 860,
        minHeight: 520,
        borderRadius: 16,
        overflow: 'hidden',
        display: 'flex',
        boxShadow: '0 32px 80px -12px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.06)',
        position: 'relative',
        zIndex: 1,
      }}>

        {/* ── Left panel — brand ─────────────────────────────────────── */}
        <div style={{
          width: '38%',
          flexShrink: 0,
          background: 'linear-gradient(155deg, #2aa5b8 0%, #1c7585 60%, #145f6e 100%)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
          padding: '48px 32px',
          position: 'relative',
          overflow: 'hidden',
        }}>
          {/* Decorative circles */}
          <div style={{ width: 220, height: 220, borderRadius: '50%', background: 'rgba(255,255,255,0.07)', position: 'absolute', top: -60, left: -60, pointerEvents: 'none' }} />
          <div style={{ width: 160, height: 160, borderRadius: '50%', background: 'rgba(255,255,255,0.05)', position: 'absolute', bottom: -40, right: -40, pointerEvents: 'none' }} />

          {/* Logo — 2× the handoff's 88px */}
          <img
            src="/logo-color.svg"
            alt="draba"
            style={{ width: 270, height: 270, filter: 'drop-shadow(0 4px 16px rgba(0,0,0,0.25))', position: 'relative', marginTop: '-15px', marginBottom: '-47px' }}
          />

          <div style={{ position: 'relative', textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#fff', letterSpacing: '-0.01em', textShadow: '0 2px 8px rgba(0,0,0,0.2)' }}>
              {instanceName}
            </div>
            <div style={{ fontSize: 13, fontWeight: 400, color: 'rgba(255,255,255,0.72)', lineHeight: 1.5, marginTop: 8 }}>
              Team coordination,<br />simplified.
            </div>
          </div>
        </div>

        {/* ── Right panel — form ─────────────────────────────────────── */}
        <div style={{
          flex: 1,
          background: 'var(--card)',
          padding: '52px 48px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}>
          {success ? (
            /* Success state */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 0 }}>
              <div style={{
                width: 56, height: 56, borderRadius: '50%',
                background: 'rgba(40,140,155,0.15)', border: '2px solid #288C9B',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 20px',
              }}>
                <Check size={24} color="#288C9B" strokeWidth={2.5} />
              </div>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--foreground)', marginBottom: 8 }}>
                You're signed in
              </div>
              <div style={{ fontSize: 14, color: 'var(--muted-foreground)' }}>
                Redirecting to your timeline…
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate>
              {/* Heading */}
              <div style={{ marginBottom: 28 }}>
                <h1 style={{ fontSize: 28, fontWeight: 700, color: 'hsl(210 17% 93%)', letterSpacing: '-0.02em', margin: '0 0 6px' }}>
                  Sign in
                </h1>
                <p style={{ fontSize: 14, color: 'hsl(210 15% 52%)', margin: 0 }}>
                  Welcome back — sign in to your account.
                </p>
              </div>

              {/* Success notice routed from another page (e.g. password reset).
                  Suppressed once a server error is shown so it can't go stale. */}
              {notice && !serverError && (
                <div className="mb-5 rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3 py-2.5 text-[13px] text-emerald-400">
                  {notice}
                </div>
              )}

              {/* Fields */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginBottom: 24 }}>
                <FloatInput
                  id="email"
                  label="Email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  error={emailError}
                  onChange={v => { setEmail(v); if (emailError) setEmailError(null) }}
                />

                <FloatInput
                  id="password"
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  error={passwordError}
                  onChange={v => { setPassword(v); if (passwordError) setPasswordError(null) }}
                  rightSlot={
                    <button
                      type="button"
                      onClick={() => setShowPassword(s => !s)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'hsl(210 15% 52%)', display: 'flex', padding: 0 }}
                    >
                      {showPassword ? <EyeOff size={18} strokeWidth={1.5} /> : <Eye size={18} strokeWidth={1.5} />}
                    </button>
                  }
                />
              </div>

              {/* Forgot password */}
              <div style={{ textAlign: 'right', marginBottom: 22, marginTop: -6 }}>
                <Link
                  to="/forgot-password"
                  style={{ fontSize: 13, fontWeight: 600, color: '#5BC0DE', textDecoration: 'none' }}
                  onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                  onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}
                >
                  Forgot password?
                </Link>
              </div>

              {/* Server error */}
              {serverError && (
                <p style={{ fontSize: 13, color: '#e74c3c', margin: '0 0 16px' }}>{serverError}</p>
              )}

              {/* Sign in button */}
              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '14px',
                  borderRadius: 8,
                  border: 'none',
                  background: loading
                    ? 'hsl(188 40% 35%)'
                    : 'linear-gradient(135deg, #2aa5b8 0%, #1e8a9c 100%)',
                  color: '#fff',
                  fontSize: 15,
                  fontWeight: 700,
                  letterSpacing: '0.01em',
                  boxShadow: loading ? 'none' : '0 4px 20px rgba(40,140,155,0.35)',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  fontFamily: 'inherit',
                  transition: 'opacity 160ms ease, transform 160ms ease, box-shadow 160ms ease',
                }}
                onMouseEnter={e => { if (!loading) { e.currentTarget.style.opacity = '0.92'; e.currentTarget.style.transform = 'translateY(-1px)' } }}
                onMouseLeave={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.transform = 'translateY(0)' }}
                onMouseDown={e => { if (!loading) e.currentTarget.style.transform = 'scale(0.98)' }}
                onMouseUp={e => { if (!loading) e.currentTarget.style.transform = 'translateY(-1px)' }}
              >
                {loading && <Spinner />}
                {loading ? 'Signing in…' : 'Sign in'}
              </button>

              {/* SSO — shown only when the instance has OIDC configured. A
                  full-page navigation to the API begins the OIDC redirect flow;
                  the browser returns to /auth/callback with tokens. */}
              {branding?.ssoEnabled && (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '20px 0' }}>
                    <div style={{ flex: 1, height: 1, background: 'hsl(210 15% 24%)' }} />
                    <span style={{ fontSize: 12, color: 'hsl(210 15% 52%)', fontWeight: 600 }}>OR</span>
                    <div style={{ flex: 1, height: 1, background: 'hsl(210 15% 24%)' }} />
                  </div>
                  <button
                    type="button"
                    onClick={() => { window.location.href = `${API_BASE}/auth/oidc/login` }}
                    style={{
                      width: '100%',
                      padding: '13px',
                      borderRadius: 8,
                      border: '1px solid hsl(210 15% 24%)',
                      background: 'hsl(210 15% 17%)',
                      color: 'hsl(210 17% 93%)',
                      fontSize: 14,
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                      transition: 'border-color 160ms ease, background 160ms ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#288C9B'; e.currentTarget.style.background = 'hsl(210 15% 19%)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'hsl(210 15% 24%)'; e.currentTarget.style.background = 'hsl(210 15% 17%)' }}
                  >
                    Sign in with SSO
                  </button>
                </>
              )}

              {/* Register link */}
              <p style={{ marginTop: 24, fontSize: 13, textAlign: 'center', color: 'hsl(210 15% 52%)' }}>
                Have an invite?{' '}
                <Link
                  to="/register"
                  style={{ color: '#5BC0DE', fontWeight: 600, textDecoration: 'none' }}
                  onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                  onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}
                >
                  Create an account
                </Link>
              </p>
            </form>
          )}
        </div>
      </div>

      {/* Keyframe for spinner */}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
