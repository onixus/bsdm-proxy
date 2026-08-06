import type { ReactNode } from 'react'

interface AppShellProps {
  sidebar: ReactNode
  topBar: ReactNode
  statusBar?: ReactNode
  children: ReactNode
  overlays?: ReactNode
}

export function AppShell({ sidebar, topBar, statusBar, children, overlays }: AppShellProps) {
  return (
    <div className="flex min-h-screen bg-surface-0 font-sans">
      <a
        href="#main-content"
        className="sr-only fixed left-4 top-4 z-[60] rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white focus:not-sr-only"
      >
        Skip to content
      </a>

      {sidebar}

      <div className="flex min-w-0 flex-1 flex-col">
        {topBar}
        {statusBar}
        <main
          id="main-content"
          tabIndex={-1}
          className="scrollbar-stable flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8"
        >
          {children}
        </main>
      </div>

      {overlays}
    </div>
  )
}
