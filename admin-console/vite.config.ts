import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/',
  server: {
    port: 5173,
    proxy: {
      '/api/search': { target: 'http://127.0.0.1:8080', changeOrigin: true },
      '/api/events': { target: 'http://127.0.0.1:8080', changeOrigin: true },
      '/api/acl': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/stats': { target: 'http://127.0.0.1:9090', changeOrigin: true },
      '/api/cache': { target: 'http://127.0.0.1:9090', changeOrigin: true },
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
