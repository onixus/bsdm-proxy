import type { ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
import { FrozenRouteShell } from './components/layout/FrozenRouteShell'
import { AiSemanticCachePage } from './pages/AiSemanticCache'
import { AnalyticsPage } from './pages/Analytics'
import { ClusterMeshPage } from './pages/ClusterMesh'
import { DashboardPage } from './pages/Dashboard'
import { LogsPage } from './pages/Logs'
import { PoliciesPage } from './pages/Policies'
import { RpzManagementPage } from './pages/RpzManagement'
import { SettingsPage } from './pages/Settings'
import { ThreatScoresPage } from './pages/ThreatScores'
import { WasmPluginsPage } from './pages/WasmPlugins'
import { DataSecurityPage } from './pages/DataSecurity'
import { AmneziaWgPage } from './pages/AmneziaWg'
import { Users } from './pages/Users'

function frozen(page: ReactNode) {
  return <FrozenRouteShell>{page}</FrozenRouteShell>
}

export function App() {
  return (
    <BrowserRouter basename={import.meta.env.BASE_URL}>
      <AppLayout>
        <Routes>
          {/* Supported Hybrid pilot surfaces (primary nav) */}
          <Route path="/" element={<DashboardPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/threat-scores" element={<ThreatScoresPage />} />
          <Route path="/security" element={<DataSecurityPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/rpz" element={<RpzManagementPage />} />
          <Route path="/users" element={<Users />} />
          <Route path="/settings" element={<SettingsPage />} />
          {/* Frozen experimental deep-links — not in primary nav */}
          <Route path="/wasm" element={frozen(<WasmPluginsPage />)} />
          <Route path="/cluster" element={frozen(<ClusterMeshPage />)} />
          <Route path="/ai-cache" element={frozen(<AiSemanticCachePage />)} />
          <Route path="/amneziawg" element={frozen(<AmneziaWgPage />)} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  )
}
