import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { readFileSync } from 'node:fs'

const proxyManifest = readFileSync(new URL('../proxy/Cargo.toml', import.meta.url), 'utf8')
const appVersion = proxyManifest.match(/^version\s*=\s*"([^"]+)"/m)?.[1]

if (!appVersion) {
  throw new Error('Unable to read BSDM product version from proxy/Cargo.toml')
}

const bearerHeaders = (token: string | undefined) =>
  token ? { Authorization: `Bearer ${token}` } : undefined

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/admin/',
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  server: {
    port: 5173,
    proxy: {
      '/api/search': { target: 'http://127.0.0.1:8080', changeOrigin: true, headers: bearerHeaders(process.env.SEARCH_API_TOKEN) },
      '/api/events': { target: 'http://127.0.0.1:8080', changeOrigin: true, headers: bearerHeaders(process.env.SEARCH_API_TOKEN) },
      '/api/acl': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.ACL_API_TOKEN) },
      '/api/stats': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/cache': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/hierarchy': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/upstream': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/security': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/auth': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/amneziawg': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/cluster': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/threats': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/wasm': { target: 'http://127.0.0.1:9090', changeOrigin: true, headers: bearerHeaders(process.env.CONTROL_API_TOKEN) },
      '/api/threat-scores': { target: 'http://127.0.0.1:8091', changeOrigin: true },
      '/metrics': { target: 'http://127.0.0.1:9090', changeOrigin: true },
    },
  },
  build: {
    target: 'es2020',
    cssMinify: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/react') || id.includes('node_modules/react-dom') || id.includes('react-router')) {
            return 'vendor'
          }
        },
      },
    },
  },
})
