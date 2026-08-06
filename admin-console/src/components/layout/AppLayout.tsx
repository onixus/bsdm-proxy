import { useEffect, useState, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { CredentialBanner } from './CredentialBanner'
import { AppShell } from './AppShell'
import { CommandPalette } from '../ui/CommandPalette'
import { API_CREDENTIALS_CHANGED_EVENT, hasApiCredentials } from '../../api/settings'

interface AppLayoutProps {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [credentialsAttached, setCredentialsAttached] = useState(hasApiCredentials)
  const location = useLocation()

  useEffect(() => {
    const handleToggle = () => setCmdOpen((value) => !value)
    window.addEventListener('toggle-command-palette', handleToggle)
    return () => window.removeEventListener('toggle-command-palette', handleToggle)
  }, [])

  useEffect(() => {
    const refreshCredentials = () => setCredentialsAttached(hasApiCredentials())
    window.addEventListener(API_CREDENTIALS_CHANGED_EVENT, refreshCredentials)
    return () => window.removeEventListener(API_CREDENTIALS_CHANGED_EVENT, refreshCredentials)
  }, [])

  return (
    <AppShell
      sidebar={<Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />}
      topBar={
        <TopBar
          onMenuOpen={() => setSidebarOpen(true)}
          onCommandOpen={() => setCmdOpen(true)}
          credentialsAttached={credentialsAttached}
          pathname={location.pathname}
        />
      }
      statusBar={<CredentialBanner visible={!credentialsAttached} />}
      overlays={<CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />}
    >
      {children}
    </AppShell>
  )
}
