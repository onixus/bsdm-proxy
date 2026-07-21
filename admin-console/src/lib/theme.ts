export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'bsdm-admin-theme'

export function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    /* localStorage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme)
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    /* localStorage unavailable */
  }
}

export function initTheme(): Theme {
  const theme = loadTheme()
  document.documentElement.setAttribute('data-theme', theme)
  return theme
}
