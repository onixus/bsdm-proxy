import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
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

export function App() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/threat-scores" element={<ThreatScoresPage />} />
          <Route path="/security" element={<DataSecurityPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/rpz" element={<RpzManagementPage />} />
          <Route path="/wasm" element={<WasmPluginsPage />} />
          <Route path="/cluster" element={<ClusterMeshPage />} />
          <Route path="/ai-cache" element={<AiSemanticCachePage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  )
}
