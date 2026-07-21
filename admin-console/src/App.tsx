import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
import { DashboardPage } from './pages/Dashboard'
import { LogsPage } from './pages/Logs'
import { PoliciesPage } from './pages/Policies'
import { RpzManagementPage } from './pages/RpzManagement'
import { SettingsPage } from './pages/Settings'
import { ThreatScoresPage } from './pages/ThreatScores'
import { WasmPluginsPage } from './pages/WasmPlugins'

export function App() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/threat-scores" element={<ThreatScoresPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/rpz" element={<RpzManagementPage />} />
          <Route path="/wasm" element={<WasmPluginsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  )
}
