import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/contexts/AuthContext'
import ProtectedRoute from '@/components/ProtectedRoute'
import ThemeSync from '@/components/ThemeSync'
import BrandingSync from '@/components/BrandingSync'
import LoginPage from '@/pages/LoginPage'
import RegisterPage from '@/pages/RegisterPage'
import DashboardPage from '@/pages/DashboardPage'
import SetupPage from '@/pages/SetupPage'
import SettingsPage from '@/pages/SettingsPage'
import ForgotPasswordPage from '@/pages/ForgotPasswordPage'
import ResetPasswordPage from '@/pages/ResetPasswordPage'
import ShareViewPage from '@/pages/ShareViewPage'
import OIDCCallbackPage from '@/pages/OIDCCallbackPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          {/* Side-effect components — render nothing but apply global state. */}
          <ThemeSync />
          <BrandingSync />
          <Routes>
            {/* First-run setup — public, shown before any users exist */}
            <Route path="/setup" element={<SetupPage />} />

            {/* Public routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            {/* SSO landing — receives tokens in the URL fragment after OIDC login */}
            <Route path="/auth/callback" element={<OIDCCallbackPage />} />
            {/* Public share viewer — no auth required */}
            <Route path="/s/:token" element={<ShareViewPage />} />

            {/* Protected routes */}
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/settings/*" element={<SettingsPage />} />
            </Route>

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
