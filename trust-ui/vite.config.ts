import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3001,
    proxy: {
      '/api/search': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/api/stats': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/api/v1': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/metrics': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
    },
  },
});
