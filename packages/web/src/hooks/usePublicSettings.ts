/**
 * usePublicSettings — fetches /settings/branding without authentication.
 *
 * Used by LoginPage and App.tsx to display instance name and apply
 * the admin-configured accent color before the user has signed in.
 */

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

interface PublicBranding {
  instanceName: string
  accentColor: string
  /** True when the instance has SSO (OIDC) configured. Drives the login-page
   *  "Sign in with SSO" button. */
  ssoEnabled: boolean
}

export function usePublicSettings() {
  return useQuery({
    queryKey: ['settings', 'branding'],
    queryFn: () => apiFetch<PublicBranding>('/settings/branding'),
    staleTime: 5 * 60 * 1000,
  })
}
